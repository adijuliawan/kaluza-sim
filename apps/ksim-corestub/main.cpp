// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// ksim-corestub: the scripted core stub on loopback (P1 N8; ADR 0009 point 8).
// The AMF's NGAP and NAS sides and the home functions of tests/corestub over a
// real SCTP listener, for component runs of `ksim` in real time; from P1 N10
// its SMF, and its UPF with the DN reflector on a real UDP socket (N3).
//
//   ksim-corestub --listen 127.0.0.1:38412 --master <file> --block 001010000300000/100
//                 --ctl <socket> [--profile <yaml>] [--plmn 00101] [--n3 127.0.0.1:2152]
//
// It binds 127.0.0.0/8 only. The subscribers' K and OPc derive from the range
// master (sim-uicc.md §8) and are never printed. GET /v1/stub on the control
// socket reports what it saw and its verdicts (every check it made, with the
// clause); POST /v1/stub/release (ue, psi, cause) releases a session from the
// network side and POST /v1/stub/ping-ue (ue, psi, seq) pings a UE from the DN,
// for the gate rows a UE cannot trigger; from N12 POST /v1/stub/deregister
// (ue, rereg) de-registers a UE from the network side, /v1/stub/t3512 (seconds)
// changes T3512 for the next accepts, and /v1/stub/restart plays an AMF
// restart: AMF STATUS INDICATION, then the association aborted, the UE
// contexts kept for the gNB's next association; POST /v1/stop ends it.

#include <CLI/CLI.hpp>

#include <cstdio>
#include <exception>

#include <algorithm>
#include <atomic>
#include <csignal>
#include <future>
#include <iostream>
#include <map>
#include <memory>
#include <thread>

#include "api/http.hpp"
#include "net/netd.hpp"
#include "net/sctp.hpp"
#include "net/tun.hpp"
#include "net/udp.hpp"
#include "ngap_amf.hpp"
#include "platform/clock.hpp"
#include "platform/shard.hpp"
#include "platform/yaml.hpp"
#include "uicc/secrets/secrets.hpp"

namespace {

using ksim::api::Exit;
using ksim::api::Reply;

volatile std::sig_atomic_t g_signal = 0;

extern "C" void on_signal(int sig) { g_signal = sig; }

struct Stub {
    ksim::MonotonicClock clock;
    ksim::Shard shard{0, 1U << 14, clock};
    ksim::corestub::Home home{ksim::Rng(0x5157, {1})};
    ksim::nas::ie::Plmn plmn;
    ksim::corestub::Profile profile;
    // On the shard.
    std::unique_ptr<ksim::net::SctpListener> listener;
    std::unique_ptr<ksim::net::UdpSocket> n3;
    std::array<std::uint8_t, 4> n3_addr{127, 0, 0, 1};
    ksim::AssocPool ng;                          // P3 R2: every gNB's association at once
    std::unique_ptr<ksim::corestub::NgapAmf> amf;
    std::unique_ptr<ksim::net::TunPort> dn;      // P2 Q12: the DN namespace's TUN, when --dn-netd
    std::vector<ksim::corestub::Verdict> past;   // the verdicts of associations that ended
    std::map<std::string, bool> sms_sub;         // N13: per-UE SMS subscription, before the AMF exists
    std::uint64_t associations = 0;
    ksim::Millis release_delay_ms = 0;           // P2 Q14 prep: --release-delay-ms

    template <class T>
    std::optional<T> call(std::function<T()> fn) {
        auto p = std::make_shared<std::promise<T>>();
        auto fut = p->get_future();
        if (!shard.post([p, fn = std::move(fn)]() mutable { p->set_value(fn()); })) {
            return std::nullopt;
        }
        if (fut.wait_for(std::chrono::seconds(5)) != std::future_status::ready) {
            return std::nullopt;
        }
        return fut.get();
    }
};

bool add_block(Stub& s, const std::string& master_file, const std::string& block, std::string& why) {
    const auto slash = block.find('/');
    const std::string first = block.substr(0, slash);
    const unsigned count = slash == std::string::npos ? 1U : static_cast<unsigned>(std::stoul(block.substr(slash + 1)));
    if (first.size() != 15 || first.find_first_not_of("0123456789") != std::string::npos || count == 0 || count > 1000 ||
        (first.rfind("001010000300", 0) != 0 && first.rfind("999700000300", 0) != 0)) {
        why = "--block is <first IMSI of a sim range>/<count 1..1000>";
        return false;
    }
    auto master = ksim::uicc::secrets::load_kek(master_file);   // the same 32-octet, owner-only file rule
    if (!master) {
        why = std::string("the range master: ") + master.error().what;
        return false;
    }
    for (unsigned i = 0; i < count; ++i) {
        std::array<char, 24> buf{};
        std::snprintf(buf.data(), buf.size(), "%015llu", std::stoull(first) + i);
        const std::string imsi(buf.data());
        s.home.add(imsi, ksim::uicc::secrets::derive(*master, "K", imsi), ksim::uicc::secrets::derive(*master, "OPc", imsi));
    }
    return true;
}

Reply report(Stub& s) {
    auto r = s.call<Reply>([&s] {
        Reply out;
        std::vector<ksim::corestub::Verdict> all = s.past;
        out.set("ASSOCIATIONS", static_cast<std::int64_t>(s.associations));
        out.set("NG_SETUP", s.amf && s.amf->ng_setup_done() ? "1" : "0");
        out.set("UES", static_cast<std::int64_t>(s.amf ? s.amf->ues() : 0));
        if (s.amf) {
            const auto f = s.amf->failures();
            all.insert(all.end(), f.begin(), f.end());
            std::map<std::string, std::int64_t> counts;
            for (const auto& m : s.amf->received()) {
                ++counts[m];
            }
            for (const auto& [m, n] : counts) {
                out.set("RECEIVED." + m, n);
            }
            std::int64_t registered = 0;
            std::int64_t identified = 0;
            for (std::size_t i = 0; i < s.amf->ues(); ++i) {
                if (auto* nas = s.amf->nas(i); nas != nullptr) {
                    registered += nas->registered() ? 1 : 0;
                    identified += static_cast<std::int64_t>(nas->identity_requests());
                }
            }
            out.set("REGISTERED", registered);
            out.set("IDENTITY_REQUESTS", identified);   // P2 Q14 prep: a 5G-GUTI the AMF could not resolve
            out.set("ERROR_INDICATIONS", static_cast<std::int64_t>(s.amf->error_indications()));
            out.set("LAST_RELEASE_CAUSE", s.amf->last_release_cause().empty() ? std::string("-") : s.amf->last_release_cause());
            // P2 Q14 prep (KS-PLAT-D20): how NG ended, and release requests asked again.
            out.set("NG_END", s.amf->ng_end());
            out.set("RELEASE_REQUESTS_REPEATED", static_cast<std::int64_t>(s.amf->repeated_release_requests()));
            out.set("RELEASE_DELAY_MS", static_cast<std::int64_t>(s.amf->release_delay()));
            out.set("SESSIONS", static_cast<std::int64_t>(s.amf->smf().sessions()));
            out.set("NOTIFIES", static_cast<std::int64_t>(s.amf->notifies()));   // P2 Q10
            out.set("NOTIFY_FULFILLED", static_cast<std::int64_t>(s.amf->notify_fulfilled()));   // P2 Q11
            out.set("NOTIFY_NOT_FULFILLED", static_cast<std::int64_t>(s.amf->notify_not_fulfilled()));
            out.set("SETUPS_WITH_REFUSED_FLOWS", static_cast<std::int64_t>(s.amf->refused_flows()));
            out.set("SM_RQOS", static_cast<std::int64_t>(s.amf->smf().rqos_sessions()));
            out.set("SM_REQUESTS", static_cast<std::int64_t>(s.amf->smf().requests()));
            if (const auto* upf = s.amf->upf()) {
                out.set("UPF_UL", static_cast<std::int64_t>(upf->stats().ul_packets));
                out.set("UPF_DL", static_cast<std::int64_t>(upf->stats().dl_packets));
                out.set("UPF_ECHO_REPLIES", static_cast<std::int64_t>(upf->stats().echo_replies));
                out.set("UPF_ECHO_FROM_UE", static_cast<std::int64_t>(upf->stats().echo_from_ue));
                out.set("UPF_ERROR_INDICATIONS", static_cast<std::int64_t>(upf->error_indications()));
                out.set("UPF_UDP_TO_UE", static_cast<std::int64_t>(upf->stats().udp_to_ue));   // P2 Q11
                out.set("UPF_UDP_FROM_UE", static_cast<std::int64_t>(upf->stats().udp_from_ue));
                out.set("UPF_RQI_MARKED", static_cast<std::int64_t>(upf->stats().rqi_marked));
                out.set("UPF_DN_TX", static_cast<std::int64_t>(upf->stats().dn_tx));   // P2 Q12
                out.set("UPF_DL_BYTES", static_cast<std::int64_t>(upf->stats().dl_bytes));
                out.set("UPF_DN_RX", static_cast<std::int64_t>(upf->stats().dn_rx));
                out.set("UPF_DN_NO_UE", static_cast<std::int64_t>(upf->stats().dn_no_ue));
                // P2 Q10: the UPF's packets per QFI, as its classification of them found them.
                for (const auto& [q, n] : upf->stats().ul_per_qfi) {
                    out.set("UPF_UL_QFI." + std::to_string(q), static_cast<std::int64_t>(n));
                }
                for (const auto& [q, n] : upf->stats().dl_per_qfi) {
                    out.set("UPF_DL_QFI." + std::to_string(q), static_cast<std::int64_t>(n));
                }
            }
        }
        out.set("FAILURES", static_cast<std::int64_t>(all.size()));
        int n = 0;
        for (const auto& v : all) {
            out.set("FAILURE." + std::to_string(++n), "[" + v.clause + "] " + v.what + (v.detail.empty() ? "" : " (" + v.detail + ")"));
        }
        return out;
    });
    return r ? *r : Reply::fail(Exit::abort, "the stub did not answer in time");
}

} // namespace

static int run_main(int argc, char** argv) {
    CLI::App app{"ksim-corestub: the scripted core stub on loopback"};
    std::string listen = "127.0.0.1:38412";
    std::string master;
    std::string block;
    std::string ctl;
    std::string profile_file;
    ksim::Millis release_delay_ms = 0;
    std::string plmn = "00101";
    std::string n3 = "127.0.0.1:2152";
    std::string dn_netd;
    std::string dn_ns = "ksim-dn-stub";
    app.add_option("--listen", listen, "the NG-C address, 127.0.0.0/8 only");
    app.add_option("--dn-netd", dn_netd, "P2 Q12: ksim-netd's socket; the UPF forwards to a DN namespace's TUN (10.60.0.1)");
    app.add_option("--dn-ns", dn_ns, "the DN namespace's name (ksim-dn-...)");
    app.add_option("--n3", n3, "the UPF's GTP-U address, 127.0.0.0/8 only");
    app.add_option("--master", master, "the range master file (0600)")->required();
    app.add_option("--block", block, "the subscribers: <first IMSI>/<count>")->required();
    app.add_option("--ctl", ctl, "the control socket")->required();
    app.add_option("--profile", profile_file, "a behaviour profile (tests/corestub/profiles)");
    app.add_option("--release-delay-ms", release_delay_ms,
                   "P2 Q14 prep: the UE CONTEXT RELEASE COMMAND this late, as a loaded core's (0: at once)");
    app.add_option("--plmn", plmn, "the AMF's PLMN");
    CLI11_PARSE(app, argc, argv);
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    std::signal(SIGPIPE, SIG_IGN);

    auto ep = ksim::Endpoint::parse(listen);
    if (!ep || ep->family != ksim::Endpoint::Family::v4 || !ep->in(ksim::Endpoint::v4(127, 0, 0, 0, 0), 8)) {
        std::cerr << "ksim-corestub: refused: --listen must be 127.0.0.0/8:port (ADR 0009 point 11)\n";
        return 7;
    }
    auto n3_ep = ksim::Endpoint::parse(n3);
    if (!n3_ep || n3_ep->family != ksim::Endpoint::Family::v4 || !n3_ep->in(ksim::Endpoint::v4(127, 0, 0, 0, 0), 8)) {
        std::cerr << "ksim-corestub: refused: --n3 must be 127.0.0.0/8:port (ADR 0009 point 11)\n";
        return 7;
    }
    Stub s;
    s.release_delay_ms = release_delay_ms;
    s.n3_addr = {n3_ep->addr[0], n3_ep->addr[1], n3_ep->addr[2], n3_ep->addr[3]};
    if (plmn.size() < 5 || plmn.size() > 6 || plmn.find_first_not_of("0123456789") != std::string::npos) {
        std::cerr << "ksim-corestub: --plmn is MCC and MNC digits\n";
        return 2;
    }
    s.plmn = {plmn.substr(0, 3), plmn.substr(3)};
    if (!profile_file.empty()) {
        try {
            s.profile = ksim::corestub::Profile::from_yaml(ksim::Yaml::load_file(profile_file));
        } catch (const ksim::YamlError& e) {
            std::cerr << "ksim-corestub: " << e.what() << "\n";
            return 2;
        }
    }
    s.profile.tacs = s.profile.tacs.empty() ? std::vector<std::uint32_t>{1} : s.profile.tacs;
    std::string why;
    if (!add_block(s, master, block, why)) {
        std::cerr << "ksim-corestub: " << why << "\n";
        return 2;
    }
    // P2 Q12: a DN namespace with its TUN dn0 (10.60.0.1, a route to the UE pool 10.60.0.0/24),
    // made by ksim-netd; the UPF forwards to it, and a traffic server runs in it.
    std::optional<ksim::net::netd::Client> netd;
    ksim::Fd dn_fd;
    if (!dn_netd.empty()) {
        auto c = ksim::net::netd::Client::connect(dn_netd);
        if (!c) {
            std::cerr << "ksim-corestub: ksim-netd at " << dn_netd << ": " << c.error().what << "\n";
            return 1;
        }
        netd = std::move(*c);
        (void)netd->teardown(dn_ns);   // one left by a run that did not end cleanly
        if (auto r = netd->setup_dn(dn_ns); !r) {
            std::cerr << "ksim-corestub: setup_dn " << dn_ns << ": " << netd->last_error() << "\n";
            return 1;
        }
        auto t = netd->dn_tun(dn_ns, ksim::net::netd::DnTunSpec{{10, 60, 0, 1}, 1500, {10, 60, 0, 0}, 24});
        if (!t) {
            std::cerr << "ksim-corestub: dn_tun " << dn_ns << ": " << netd->last_error() << "\n";
            (void)netd->teardown(dn_ns);
            return 1;
        }
        dn_fd = std::move(*t);
    }
    s.shard.start();
    auto started = s.call<std::string>([&s, &ep, &n3_ep, &dn_fd] {
        if (dn_fd) {
            auto p = ksim::net::TunPort::adopt(s.shard.reactor(), std::move(dn_fd));
            if (!p) {
                return "the DN TUN: " + std::string(p.error().what);
            }
            s.dn = std::move(*p);
        }
        auto u = ksim::net::UdpSocket::bind(s.shard.reactor(), *n3_ep);
        if (!u) {
            return "N3 " + n3_ep->to_string() + ": " + std::string(u.error().what);
        }
        s.n3 = std::move(*u);
        ksim::net::SctpOptions opt;
        opt.out_streams = 10;   // P3 R2: as our CU-CP's (KS-NGAP-D6) and kaluza-core's AMF
        opt.max_in_streams = 10;
        auto l = ksim::net::SctpListener::listen(s.shard.reactor(), {*ep}, opt, [&s](std::unique_ptr<ksim::IAssoc> a) {
            // P3 R2: several gNBs at once, each its own link in the pool. The AMF keeps its UE
            // contexts across a gNB's new association (N12: a gNB or AMF restart); the N2
            // connections of a gNB whose association went are dropped.
            if (!s.amf) {
                s.amf = std::make_unique<ksim::corestub::NgapAmf>(s.shard, s.home, s.plmn, s.profile, s.ng, s.n3.get(),
                                                                  s.n3_addr);
                s.amf->set_release_delay(s.release_delay_ms);
                if (s.dn && s.amf->upf() != nullptr) {
                    s.amf->upf()->attach_dn(s.dn.get());   // P2 Q12
                }
                for (const auto& [supi, on] : s.sms_sub) {
                    s.amf->set_sms_subscribed(supi, on);
                }
            }
            (void)s.ng.take(std::move(a));
            ++s.associations;
        });
        if (!l) {
            return std::string(l.error().what);
        }
        s.listener = std::move(*l);
        return std::string();
    });
    if (!started || !started->empty()) {
        std::cerr << "ksim-corestub: " << (started ? *started : "the shard did not start") << "\n";
        return 1;
    }
    std::atomic<bool> stop{false};
    ksim::api::Server server;
    server.get("/v1/stub", [&s](const ksim::api::Request&) { return report(s); });
    // The UE is the n-th that came (0 first), as `ue`; the session by `psi`.
    auto num = [](const ksim::api::Request& req, const char* key, unsigned long fallback, unsigned long max) {
        const std::string v = req.arg(key);
        if (v.empty() || v.size() > 6 || v.find_first_not_of("0123456789") != std::string::npos) {
            return fallback;
        }
        return std::min(std::stoul(v), max);
    };
    // `ue`: the SUPI's 15 digits (its latest registration), or the n-th UE that came (0 first).
    auto find_ue = [num](Stub& st, const ksim::api::Request& req) -> ksim::corestub::Amf* {
        if (!st.amf) {
            return nullptr;
        }
        std::string u = req.arg("ue");
        if (u.rfind("imsi-", 0) == 0) {
            u = u.substr(5);
        }
        if (u.size() == 15) {
            return st.amf->nas_by_supi(u);
        }
        return st.amf->nas(static_cast<std::size_t>(num(req, "ue", 0, 1000)));
    };
    server.post("/v1/stub/release", [&s, find_ue, num](const ksim::api::Request& req) {
        const auto psi = static_cast<std::uint8_t>(num(req, "psi", 1, 15));
        const auto cause = static_cast<std::uint8_t>(num(req, "cause", 36, 255));
        auto r = s.call<bool>([&s, &req, find_ue, psi, cause] {
            auto* nas = find_ue(s, req);
            return nas != nullptr && nas->release_session(psi, cause);
        });
        if (!r) {
            return Reply::fail(Exit::abort, "the stub did not answer in time");
        }
        if (!*r) {
            return Reply::fail(Exit::wrong_state, "no such registered UE or session");
        }
        Reply out;
        out.set("RELEASE", "sent");
        return out;
    });
    server.post("/v1/stub/ping-ue", [&s, find_ue, num](const ksim::api::Request& req) {
        const auto psi = static_cast<std::uint8_t>(num(req, "psi", 1, 15));
        const auto seq = static_cast<std::uint16_t>(num(req, "seq", 1, 65535));
        auto r = s.call<bool>([&s, &req, find_ue, psi, seq] {
            auto* nas = find_ue(s, req);
            return nas != nullptr && s.amf->smf().ping_ue(nas->supi(), psi, seq).has_value();
        });
        if (!r) {
            return Reply::fail(Exit::abort, "the stub did not answer in time");
        }
        if (!*r) {
            return Reply::fail(Exit::wrong_state, "no such UE session with a downlink tunnel");
        }
        Reply out;
        out.set("PING", "sent");
        return out;
    });
    server.post("/v1/stub/deregister", [&s, find_ue](const ksim::api::Request& req) {
        const bool rereg = req.arg("rereg") == "1";
        auto r = s.call<bool>([&s, &req, find_ue, rereg] {
            auto* nas = find_ue(s, req);
            return nas != nullptr && nas->network_deregister(rereg);
        });
        if (!r) {
            return Reply::fail(Exit::abort, "the stub did not answer in time");
        }
        if (!*r) {
            return Reply::fail(Exit::wrong_state, "no such registered, connected UE");
        }
        Reply out;
        out.set("DEREGISTER", "sent");
        return out;
    });
    server.post("/v1/stub/sms-sub", [&s](const ksim::api::Request& req) {
        // N13: SMS in a UE's subscription or not; the next REGISTRATION ACCEPT says so.
        std::string supi = req.arg("ue");
        if (supi.rfind("imsi-", 0) == 0) {
            supi = supi.substr(5);
        }
        const bool on = req.arg("on", "1") == "1";
        if (supi.size() != 15) {
            return Reply::fail(Exit::usage, "sms-sub --ue <SUPI> [--off]");
        }
        auto r = s.call<bool>([&s, supi, on] {
            if (s.amf) {
                s.amf->set_sms_subscribed(supi, on);
            }
            s.sms_sub[supi] = on;   // kept for the AMF of the next association
            return true;
        });
        if (!r) {
            return Reply::fail(Exit::abort, "the stub did not answer in time");
        }
        Reply out;
        out.set("SMS_SUBSCRIBED", on ? "1" : "0");
        return out;
    });
    server.post("/v1/stub/t3512", [&s, num](const ksim::api::Request& req) {
        const auto secs = static_cast<int>(num(req, "seconds", 3600, 100000));
        auto r = s.call<bool>([&s, secs] {
            s.profile.t3512_s = secs;
            if (s.amf) {
                s.amf->set_t3512(secs);
            }
            return true;
        });
        if (!r) {
            return Reply::fail(Exit::abort, "the stub did not answer in time");
        }
        Reply out;
        out.set("T3512_S", static_cast<std::int64_t>(secs));
        return out;
    });
    server.post("/v1/stub/up-policy", [&s](const ksim::api::Request& req) {
        // P2 Q9: the UP Security Indication the SMF sends with the next sessions (TS 38.413
        // 9.3.1.27): required, preferred, not-needed, or absent (no IE).
        const auto ok = [](const std::string& v) {
            return v == "required" || v == "preferred" || v == "not-needed" || v == "absent";
        };
        const auto rate_ok = [](const std::string& v) { return v.empty() || v == "bitrate64kbs" || v == "maximum-UE-rate"; };
        const std::string in = req.arg("integrity", "not-needed");
        const std::string cp = req.arg("confidentiality", "required");
        const std::string ul = req.arg("rate-ul");
        const std::string dl = req.arg("rate-dl");
        if (!ok(in) || !ok(cp) || !rate_ok(ul) || !rate_ok(dl)) {
            return Reply::fail(Exit::usage, "up-policy --integrity|--confidentiality required|preferred|not-needed|absent "
                                            "[--rate-ul|--rate-dl bitrate64kbs|maximum-UE-rate]");
        }
        auto r = s.call<bool>([&s, in, cp, ul, dl] {
            for (auto* p : {&s.profile.session, s.amf ? &s.amf->smf().profile() : nullptr}) {
                if (p == nullptr) {
                    continue;
                }
                p->up_integrity = in;
                p->up_confidentiality = cp;
                p->up_rate_ul = ul.empty() ? std::nullopt : std::optional<std::string>(ul);
                p->up_rate_dl = dl.empty() ? std::nullopt : std::optional<std::string>(dl);
            }
            return true;
        });
        if (!r) {
            return Reply::fail(Exit::abort, "the stub did not answer in time");
        }
        Reply out;
        out.set("UP_INTEGRITY", in);
        out.set("UP_CONFIDENTIALITY", cp);
        return out;
    });
    // P2 Q10: QoS flows. flows-add / flows-clear set the flows new sessions get beside the
    // default one; add / del change a session of a UE by a network-requested modification.
    server.post("/v1/stub/qos", [&s, find_ue, num](const ksim::api::Request& req) {
        const std::string action = req.arg("action");
        ksim::corestub::FlowSpec f;
        if (action == "rq-timer") {
            const int secs = static_cast<int>(num(req, "seconds", 60, 1860));   // P2 Q11: 0 sends none
            auto r = s.call<bool>([&s, secs] {
                for (auto* p : {&s.profile.session, s.amf ? &s.amf->smf().profile() : nullptr}) {
                    if (p != nullptr) {
                        p->rq_timer_s = secs;
                    }
                }
                return true;
            });
            if (!r) {
                return Reply::fail(Exit::abort, "the stub did not answer in time");
            }
            Reply out;
            out.set("RQ_TIMER_S", static_cast<std::int64_t>(secs));
            return out;
        }
        if (req.has("gfbr") != req.has("mfbr")) {
            return Reply::fail(Exit::usage, "qos: a GBR flow takes --gfbr and --mfbr (kbit/s)");
        }
        if (req.has("gfbr")) {   // P2 Q11: a GBR flow
            f.gfbr_kbps = num(req, "gfbr", 0, 10'000'000);
            f.mfbr_kbps = num(req, "mfbr", 0, 10'000'000);
            if (*f.gfbr_kbps > *f.mfbr_kbps) {
                return Reply::fail(Exit::usage, "qos: the GFBR is at most the MFBR");
            }
            f.notification_control = req.has("notify") && req.arg("notify") != "0";
        }
        if (action == "mod") {
            f.qfi = static_cast<std::uint8_t>(num(req, "qfi", 2, 63));
            f.five_qi = static_cast<std::uint16_t>(num(req, "5qi", 9, 255));
        } else if (action == "flows-add" || action == "add") {
            f.qfi = static_cast<std::uint8_t>(num(req, "qfi", 2, 63));
            f.five_qi = static_cast<std::uint16_t>(num(req, "5qi", 9, 255));
            f.precedence = static_cast<std::uint8_t>(num(req, "precedence", 10, 255));
            auto d = ksim::corestub::parse_direction(req.arg("direction", "bidirectional"));
            f.filter = req.arg("filter", "all");
            auto c = ksim::corestub::parse_filter(f.filter);
            if (!d || !c || f.precedence == 80) {   // 80 is reserved (TS 24.501 9.11.4.13)
                return Reply::fail(Exit::usage, "qos: --direction uplink|downlink|bidirectional, --filter COMPONENTS "
                                                "(all, remote=A/N, local=A/N, proto=N, lport=N, lports=N-M, rport=N, "
                                                "rports=N-M, spi=N, tos=V/M), --precedence not 80");
            }
            f.direction = *d;
            f.components = std::move(*c);
        } else if (action == "del") {
            f.qfi = static_cast<std::uint8_t>(num(req, "qfi", 2, 63));
        } else if (action != "flows-clear") {
            return Reply::fail(Exit::usage, "qos flows-add|flows-clear|add|del|mod|rq-timer");
        }
        const auto psi = static_cast<std::uint8_t>(num(req, "psi", 1, 15));
        auto r = s.call<std::string>([&s, &req, find_ue, action, f, psi] {
            if (action == "flows-add" || action == "flows-clear") {
                for (auto* p : {&s.profile.session, s.amf ? &s.amf->smf().profile() : nullptr}) {
                    if (p == nullptr) {
                        continue;
                    }
                    if (action == "flows-clear") {
                        p->flows.clear();
                    } else {
                        p->flows.erase(std::remove_if(p->flows.begin(), p->flows.end(), [&f](const auto& x) { return x.qfi == f.qfi; }),
                                       p->flows.end());
                        p->flows.push_back(f);
                    }
                }
                return std::string();
            }
            auto* nas = find_ue(s, req);
            if (nas == nullptr) {
                return std::string("no such registered UE");
            }
            const auto done = action == "add"   ? nas->qos_add(psi, f)
                              : action == "mod" ? nas->qos_mod(psi, f.qfi, f.five_qi, f.gfbr_kbps, f.mfbr_kbps)
                                                : nas->qos_del(psi, f.qfi);
            return done ? std::string() : std::string(done.error().what);
        });
        if (!r) {
            return Reply::fail(Exit::abort, "the stub did not answer in time");
        }
        if (!r->empty()) {
            return Reply::fail(Exit::wrong_state, *r);
        }
        Reply out;
        out.set("QOS", action);
        out.set("QFI", static_cast<std::int64_t>(f.qfi));
        return out;
    });
    // P2 Q11: a UDP datagram from the DN to a UE's echo port (7), on a QFI of the test's and with
    // the RQI when asked: the reflective QoS and unknown-QFI rows.
    server.post("/v1/stub/udp-ue", [&s, find_ue, num](const ksim::api::Request& req) {
        const auto psi = static_cast<std::uint8_t>(num(req, "psi", 1, 15));
        const auto sport = static_cast<std::uint16_t>(num(req, "sport", 40000, 65535));
        const auto seq = static_cast<std::uint16_t>(num(req, "seq", 1, 65535));
        std::optional<std::uint8_t> qfi;
        if (req.has("qfi")) {
            qfi = static_cast<std::uint8_t>(num(req, "qfi", 1, 63));
        }
        const bool rqi = req.has("rqi") && req.arg("rqi") != "0";
        auto from = ksim::Endpoint::parse(req.arg("src", "10.60.0.1"), 0);
        if (!from || from->family != ksim::Endpoint::Family::v4) {
            return Reply::fail(Exit::usage, "udp-ue --src takes an IPv4 address");
        }
        const ksim::ip::Addr src{from->addr[0], from->addr[1], from->addr[2], from->addr[3]};
        auto r = s.call<bool>([&s, &req, find_ue, psi, src, sport, qfi, rqi, seq] {
            auto* nas = find_ue(s, req);
            return nas != nullptr && s.amf->smf().udp_ue(nas->supi(), psi, src, sport, qfi, rqi, seq).has_value();
        });
        if (!r) {
            return Reply::fail(Exit::abort, "the stub did not answer in time");
        }
        if (!*r) {
            return Reply::fail(Exit::wrong_state, "no such UE session with a downlink tunnel");
        }
        Reply out;
        out.set("UDP", "sent");
        return out;
    });
    server.post("/v1/stub/nas-alg", [&s, num](const ksim::api::Request& req) {
        // P2 Q8: the NAS algorithms the next SECURITY MODE COMMAND selects (TS 33.501 6.7.2);
        // 1 and 2 only: 0 is the bisect switch's, 3 (ZUC) the declared gap KS-SEC-G1.
        const auto ea = static_cast<std::uint8_t>(num(req, "ea", 2, 2));
        const auto ia = static_cast<std::uint8_t>(num(req, "ia", 2, 2));
        if (ea < 1 || ia < 1) {
            return Reply::fail(Exit::usage, "nas-alg --ea 1|2 --ia 1|2");
        }
        auto r = s.call<bool>([&s, ea, ia] {
            s.profile.ea = ea;
            s.profile.ia = ia;
            if (s.amf) {
                s.amf->set_nas_algorithms(ea, ia);
            }
            return true;
        });
        if (!r) {
            return Reply::fail(Exit::abort, "the stub did not answer in time");
        }
        Reply out;
        out.set("EA", static_cast<std::int64_t>(ea));
        out.set("IA", static_cast<std::int64_t>(ia));
        return out;
    });
    server.post("/v1/stub/restart", [&s](const ksim::api::Request&) {
        // An AMF going away and back (rows amf-ueransim.063-066): AMF STATUS
        // INDICATION, then the association aborted after a moment; the UE
        // contexts stay for the gNB's next association (L11).
        auto r = s.call<bool>([&s] {
            if (!s.amf || s.ng.links().empty()) {
                return false;
            }
            s.amf->status_indication();
            s.shard.start_timer(300, [&s] { s.ng.abort_all(); });
            return true;
        });
        if (!r) {
            return Reply::fail(Exit::abort, "the stub did not answer in time");
        }
        if (!*r) {
            return Reply::fail(Exit::wrong_state, "no gNB associated");
        }
        Reply out;
        out.set("RESTART", "started");
        return out;
    });
    server.post("/v1/stop", [&stop](const ksim::api::Request&) {
        stop.store(true);
        Reply r;
        r.set("STOPPING", "1");
        return r;
    });
    if (auto r = server.listen_unix(ctl); !r) {
        std::cerr << "ksim-corestub: " << ctl << ": " << r.error().what << "\n";
        return 1;
    }
    if (netd) {
        std::cout << "DN_NS=" << dn_ns << "\n";
    }
    std::cout << "STUB_LISTEN=" << ep->to_string() << "\nCTL=" << ctl << "\n" << std::flush;
    while (g_signal == 0 && !stop.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    server.stop();
    (void)s.call<bool>([&s] {
        s.ng.set_handlers({}, {});
        s.amf.reset();
        s.ng.clear();
        s.listener.reset();
        s.n3.reset();
        s.dn.reset();
        return true;
    });
    s.shard.stop();
    s.shard.join();
    if (netd) {
        (void)netd->teardown(dn_ns);   // P2 Q12: the DN namespace and its TUN go
    }
    return 0;
}

int main(int argc, char** argv) {
    // An exception that reaches here is a bug: exit 10 (cli.md's internal error).
    try {
        return run_main(argc, argv);
    } catch (const std::exception& e) {
        std::fputs("ksim-corestub: internal error: ", stderr);
        std::fputs(e.what(), stderr);
        std::fputs("\n", stderr);
    } catch (...) {
        std::fputs("ksim-corestub: internal error\n", stderr);
    }
    return 10;
}
