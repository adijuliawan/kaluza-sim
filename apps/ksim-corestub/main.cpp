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
#include "net/sctp.hpp"
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
    std::unique_ptr<ksim::IAssoc> assoc;
    std::unique_ptr<ksim::corestub::NgapAmf> amf;
    std::vector<ksim::corestub::Verdict> past;   // the verdicts of associations that ended
    std::uint64_t associations = 0;

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
            for (std::size_t i = 0; i < s.amf->ues(); ++i) {
                if (auto* nas = s.amf->nas(i); nas != nullptr && nas->registered()) {
                    ++registered;
                }
            }
            out.set("REGISTERED", registered);
            out.set("ERROR_INDICATIONS", static_cast<std::int64_t>(s.amf->error_indications()));
            out.set("SESSIONS", static_cast<std::int64_t>(s.amf->smf().sessions()));
            out.set("SM_REQUESTS", static_cast<std::int64_t>(s.amf->smf().requests()));
            if (const auto* upf = s.amf->upf()) {
                out.set("UPF_UL", static_cast<std::int64_t>(upf->stats().ul_packets));
                out.set("UPF_DL", static_cast<std::int64_t>(upf->stats().dl_packets));
                out.set("UPF_ECHO_REPLIES", static_cast<std::int64_t>(upf->stats().echo_replies));
                out.set("UPF_ECHO_FROM_UE", static_cast<std::int64_t>(upf->stats().echo_from_ue));
                out.set("UPF_ERROR_INDICATIONS", static_cast<std::int64_t>(upf->error_indications()));
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
    std::string plmn = "00101";
    std::string n3 = "127.0.0.1:2152";
    app.add_option("--listen", listen, "the NG-C address, 127.0.0.0/8 only");
    app.add_option("--n3", n3, "the UPF's GTP-U address, 127.0.0.0/8 only");
    app.add_option("--master", master, "the range master file (0600)")->required();
    app.add_option("--block", block, "the subscribers: <first IMSI>/<count>")->required();
    app.add_option("--ctl", ctl, "the control socket")->required();
    app.add_option("--profile", profile_file, "a behaviour profile (tests/corestub/profiles)");
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
    s.shard.start();
    auto started = s.call<std::string>([&s, &ep, &n3_ep] {
        auto u = ksim::net::UdpSocket::bind(s.shard.reactor(), *n3_ep);
        if (!u) {
            return "N3 " + n3_ep->to_string() + ": " + std::string(u.error().what);
        }
        s.n3 = std::move(*u);
        ksim::net::SctpOptions opt;
        opt.out_streams = 3;
        opt.max_in_streams = 3;
        auto l = ksim::net::SctpListener::listen(s.shard.reactor(), {*ep}, opt, [&s](std::unique_ptr<ksim::IAssoc> a) {
            // One gNB at a time: a new association replaces the last. The AMF keeps
            // its UE contexts across it (N12: a gNB or AMF restart), its N2 connections go.
            s.assoc = std::move(a);
            if (s.amf) {
                s.amf->rebind(*s.assoc);
            } else {
                s.amf = std::make_unique<ksim::corestub::NgapAmf>(s.shard, s.home, s.plmn, s.profile, *s.assoc, s.n3.get(),
                                                                  s.n3_addr);
            }
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
    server.post("/v1/stub/restart", [&s](const ksim::api::Request&) {
        // An AMF going away and back (rows amf-ueransim.063-066): AMF STATUS
        // INDICATION, then the association aborted after a moment; the UE
        // contexts stay for the gNB's next association (L11).
        auto r = s.call<bool>([&s] {
            if (!s.amf || !s.assoc) {
                return false;
            }
            s.amf->status_indication();
            s.shard.start_timer(300, [&s] {
                if (s.assoc) {
                    s.assoc->abort();
                }
            });
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
    std::cout << "STUB_LISTEN=" << ep->to_string() << "\nCTL=" << ctl << "\n" << std::flush;
    while (g_signal == 0 && !stop.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    server.stop();
    (void)s.call<bool>([&s] {
        s.amf.reset();
        s.assoc.reset();
        s.listener.reset();
        s.n3.reset();
        return true;
    });
    s.shard.stop();
    s.shard.join();
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
