// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "node/aio/control.hpp"

#include <ksim/build_info.hpp>

#include <fmt/format.h>

#include <algorithm>
#include <cctype>
#include <exception>
#include <optional>
#include <thread>

#include "api/wait.hpp"
#include "proc/ran/cucp.hpp"
#include "proc/ran/du.hpp"

namespace ksim::node {

namespace {

using api::Exit;
using api::Reply;
using api::Request;

constexpr std::chrono::milliseconds kMaxWait{600'000};

Reply unsound() { return Reply::fail(Exit::abort, "the node did not answer in time"); }

std::chrono::milliseconds wait_ms(const Request& r, std::chrono::milliseconds fallback) {
    const std::string v = r.arg("wait_ms");
    if (v.empty() || v.find_first_not_of("0123456789") != std::string::npos || v.size() > 9) {
        return fallback;
    }
    return std::min(std::chrono::milliseconds(std::stoll(v)), kMaxWait);
}

std::uint64_t number(const std::string& v, std::uint64_t fallback) {
    if (v.empty() || v.find_first_not_of("0123456789") != std::string::npos || v.size() > 18) {
        return fallback;
    }
    return std::stoull(v);
}

/// "10.60.0.1" -> its four octets.
std::optional<ip::Addr> ipv4_arg(const std::string& s) {
    auto e = Endpoint::parse(s, 0);
    if (!e || e->family != Endpoint::Family::v4) {
        return std::nullopt;
    }
    return ip::Addr{e->addr[0], e->addr[1], e->addr[2], e->addr[3]};
}

std::string ipv4_text(const ip::Addr& a) { return fmt::format("{}.{}.{}.{}", a[0], a[1], a[2], a[3]); }

/// "1", "0x01", "1-000001" style S-NSSAI parts from the request; nullopt for none, an error text for a bad one.
std::optional<nas::ie::Snssai> snssai_arg(const Request& req, std::string& bad) {
    const std::string sst = req.arg("sst");
    const std::string sd = req.arg("sd");
    if (sst.empty()) {
        if (!sd.empty()) {
            bad = "--sd needs --sst";
        }
        return std::nullopt;
    }
    nas::ie::Snssai s;
    try {
        const unsigned long v = std::stoul(sst, nullptr, 0);
        if (v > 255) {
            bad = "--sst is 0..255";
            return std::nullopt;
        }
        s.sst = static_cast<std::uint8_t>(v);
        if (!sd.empty()) {
            const unsigned long d = std::stoul(sd, nullptr, 16);
            if (d > 0xFFFFFF) {
                bad = "--sd is six hex digits";
                return std::nullopt;
            }
            s.sd = static_cast<std::uint32_t>(d);
        }
    } catch (const std::exception&) {
        bad = "--sst takes a number, --sd hex digits";
        return std::nullopt;
    }
    return s;
}

void add_pairs(Reply& r, const std::vector<std::pair<std::string, std::string>>& kv) {
    for (const auto& [k, v] : kv) {
        r.set(k, v);
    }
}

/// A command on one UE, then, with wait_ms, the event that ends its procedure.
struct UeCommand {
    std::function<Result<void>(UeDevice&)> run;
    std::vector<std::string> until;
    std::vector<std::string> fail;
    std::vector<std::pair<std::string, std::string>> where;
    const char* proc = "";
};

Reply run_ue_command(AllInOne& aio, const Request& req, const UeCommand& cmd) {
    const std::string sel = req.params.count("sel") != 0 ? req.params.at("sel") : "";
    const std::uint64_t since = aio.events().last_seq();   // before the command: its event cannot be missed
    struct Out {
        Exit exit = Exit::ok;
        std::string cause;
        std::string subject;
    };
    auto out = aio.call<Out>([&aio, sel, run = cmd.run]() -> Out {
        UeDevice* ue = aio.ue(sel);
        if (ue == nullptr) {
            return {Exit::unknown, "no such UE", ""};
        }
        auto r = run(*ue);
        if (!r) {
            return {Exit::wrong_state, r.error().what, ue->subject()};
        }
        return {Exit::ok, "", ue->subject()};
    });
    if (!out) {
        return unsound();
    }
    if (out->exit != Exit::ok) {
        Reply r = Reply::fail(out->exit, out->cause);
        if (!out->subject.empty()) {
            r.set("UE", out->subject.substr(3));
        }
        return r;
    }
    const auto w = wait_ms(req, std::chrono::milliseconds(0));
    if (w.count() == 0 || cmd.until.empty()) {
        Reply r;
        r.set("UE", out->subject.substr(3));
        r.set("PROC", cmd.proc);
        r.set("RESULT", "STARTED");
        r.set("EVENT_SEQ", static_cast<std::int64_t>(since));
        return r;
    }
    api::WaitQuery q;
    q.until = cmd.until;
    q.fail = cmd.fail;
    q.subject = out->subject;
    q.where = cmd.where;
    q.since = since;
    q.timeout = w;
    const auto t0 = std::chrono::steady_clock::now();
    Reply waited = api::wait(aio.events(), q);
    Reply r = waited;
    r.kv = api::json::object();
    r.set("UE", out->subject.substr(3));
    r.set("PROC", cmd.proc);
    r.set("RESULT", waited.exit == Exit::ok ? "ACCEPT" : waited.exit == Exit::timeout ? "TIMEOUT" : "FAILED");
    for (const auto& [k, v] : waited.kv.items()) {
        if (k != "UE") {
            r.kv[k] = v;
        }
    }
    r.set("ELAPSED_MS", std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count());
    return r;
}

} // namespace

void bind_control(api::Server& server, AllInOne& aio, std::atomic<bool>& stop) {
    const Topology& t = aio.topology();

    server.get("/v1/version", [](const Request&) {
        Reply r;
        r.set("VERSION", build::kVersion);
        r.set("COMMIT", build::kGitDescribe);
        r.set("BUILD", std::string(build::kBuildType) + (std::string(build::kSanitize).empty() ? "" : "+" + std::string(build::kSanitize)));
        r.set("SPEC_PINS", std::string("INDEX.tsv sha256:") + build::kSpecIndexSha256);
        r.set("ASN1C", build::kAsn1cPin);
        return r;
    });
    server.get("/v1/capabilities", [](const Request&) {
        // What P1 N8 serves; the rest of cli.md says 0 until its milestone.
        Reply r;
        r.set("CAP.NAS_MM", "1");
        r.set("CAP.AS_SECURITY", "nia2/nea2");
        r.set("CAP.PDU_SESSION", "ipv4");
        r.set("CAP.PING", "inject");
        r.set("CAP.SMS_NAS", "0");
        r.set("CAP.SUCI", "null");
        r.set("CAP.NETNS", "0");
        r.set("CAP.FAULTS", "0");
        return r;
    });
    server.get("/v1/faults", [](const Request&) {
        Reply r;
        r.set("FAULTS", "0");   // fault injection is P3
        return r;
    });
    server.get("/v1/info", [&aio, &t](const Request&) {
        auto s = aio.call<Reply>([&aio] {
            Reply r;
            r.set("ROLE", "aio");
            r.set("NG_UP", aio.ng_up() ? "1" : "0");
            r.set("NG_SETUP", aio.cucp().ng_ready() ? "1" : "0");
            r.set("F1_SETUP", aio.cucp().f1_ready() ? "1" : "0");
            r.set("CELL_ACTIVE", aio.du().cell_active() ? "1" : "0");
            r.set("UES", static_cast<std::int64_t>(aio.ues().size()));
            r.set("RAN_UES", static_cast<std::int64_t>(aio.cucp().ues()));
            r.set("KAIR_FRAMES", static_cast<std::int64_t>(aio.stats().kair_frames));
            r.set("KAIR_ERRORS", static_cast<std::int64_t>(aio.stats().kair_errors));
            return r;
        });
        if (!s) {
            return unsound();
        }
        Reply r = *s;
        r.set("GNB", t.gnb_name);
        r.set("PLMN", t.mcc + t.mnc);
        r.set("AMF", t.amf.to_string());
        r.set("RUN_DIR", aio.run_dir());
        r.set("EVENT_SEQ", static_cast<std::int64_t>(aio.events().last_seq()));
        r.set("LOOP_LAG_MAX_MS", static_cast<std::int64_t>(aio.max_lag_ms()));
        return r;
    });
    server.get("/v1/nodes", [&t](const Request&) {
        Reply r;
        r.set("NODES", "2");
        r.set("NODE.1.NAME", t.gnb_name);
        r.set("NODE.1.ROLE", "cucp");
        r.set("NODE.2.NAME", t.gnb_name + "-du");
        r.set("NODE.2.ROLE", "du");
        return r;
    });
    server.get("/v1/ues", [&aio](const Request&) {
        auto s = aio.call<Reply>([&aio] {
            Reply r;
            const auto ues = aio.ues();
            r.set("UES", static_cast<std::int64_t>(ues.size()));
            for (auto* u : ues) {
                const std::string k = "UE." + std::to_string(u->config().index);
                r.set(k, "imsi-" + u->config().supi);
                r.set(k + ".GROUP", aio.groups()[u->config().index - 1]);
            }
            return r;
        });
        return s ? *s : unsound();
    });
    server.get("/v1/ue/:sel/status", [&aio](const Request& req) {
        const std::string sel = req.params.at("sel");
        auto s = aio.call<Reply>([&aio, sel] {
            UeDevice* ue = aio.ue(sel);
            if (ue == nullptr) {
                return Reply::fail(Exit::unknown, "no such UE");
            }
            Reply r;
            add_pairs(r, ue->status());
            return r;
        });
        return s ? *s : unsound();
    });
    server.post("/v1/ue/:sel/power", [&aio](const Request& req) {
        const std::string state = req.arg("state");
        if (state == "on") {
            return run_ue_command(aio, req,
                                  UeCommand{[](UeDevice& u) { return u.power_on(); },
                                            {"nas.reg.accept"},
                                            {"nas.reg.reject", "nas.reg.abort"},
                                            {},
                                            "registration"});
        }
        if (state == "off") {
            const std::string mode = req.arg("mode", "switch-off");
            if (mode != "switch-off") {
                return Reply::fail(Exit::capability, "power off --" + mode + " comes with N12");
            }
            return run_ue_command(aio, req,
                                  UeCommand{[](UeDevice& u) { return u.deregister(true); },
                                            {"nas.dereg.sent"},
                                            {},
                                            {{"switch_off", "1"}},
                                            "deregistration"});
        }
        return Reply::fail(Exit::usage, "power on|off");
    });
    server.post("/v1/ue/:sel/register", [&aio](const Request& req) {
        if (const std::string type = req.arg("type", "initial"); type != "initial") {
            return Reply::fail(Exit::capability, "register --type " + type + " comes with N12");
        }
        return run_ue_command(aio, req,
                              UeCommand{[](UeDevice& u) { return u.register_initial(); },
                                        {"nas.reg.accept"},
                                        {"nas.reg.reject", "nas.reg.abort"},
                                        {},
                                        "registration"});
    });
    server.post("/v1/ue/:sel/deregister", [&aio](const Request& req) {
        const std::string type = req.arg("type", "normal");
        if (type == "normal") {
            return run_ue_command(aio, req,
                                  UeCommand{[](UeDevice& u) { return u.deregister(false); },
                                            {"nas.dereg.accept"},
                                            {"nas.dereg.abort"},
                                            {},
                                            "deregistration"});
        }
        if (type == "switch-off") {
            return run_ue_command(aio, req,
                                  UeCommand{[](UeDevice& u) { return u.deregister(true); },
                                            {"nas.dereg.sent"},
                                            {},
                                            {{"switch_off", "1"}},
                                            "deregistration"});
        }
        return Reply::fail(Exit::capability, "deregister " + type + " comes with N12");
    });
    // ---- 5GSM and the inject-mode ping (P1 N10) ----
    server.get("/v1/ue/:sel/ps", [&aio](const Request& req) {
        const std::string sel = req.params.at("sel");
        auto s = aio.call<Reply>([&aio, sel] {
            UeDevice* ue = aio.ue(sel);
            if (ue == nullptr) {
                return Reply::fail(Exit::unknown, "no such UE");
            }
            Reply r;
            r.set("UE", ue->subject().substr(3));
            const auto list = ue->sessions();
            r.set("PDU_SESSIONS", static_cast<std::int64_t>(list.size()));
            for (const auto& p : list) {
                const std::string k = "PS." + std::to_string(p.psi);
                r.set(k + ".STATE", proc::ue::sm_state_name(p.state));
                r.set(k + ".DNN", p.dnn);
                r.set(k + ".SNSSAI", p.snssai ? proc::ue::snssai_text(*p.snssai) : "-");
                r.set(k + ".TYPE", "ipv4");
                r.set(k + ".IP", p.ipv4 ? ipv4_text(*p.ipv4) : "");
                r.set(k + ".DNS", p.dns ? ipv4_text(*p.dns) : "");
                r.set(k + ".MTU", p.mtu ? std::to_string(*p.mtu) : "");
                r.set(k + ".QFI", static_cast<std::int64_t>(p.default_qfi));
                r.set(k + ".AMBR_DL", p.ambr_dl_bps ? std::to_string(*p.ambr_dl_bps) : "");
                r.set(k + ".AMBR_UL", p.ambr_ul_bps ? std::to_string(*p.ambr_ul_bps) : "");
            }
            return r;
        });
        return s ? *s : unsound();
    });
    server.post("/v1/ue/:sel/ps-establish", [&aio](const Request& req) {
        std::string type = req.arg("type", "ipv4");
        std::transform(type.begin(), type.end(), type.begin(), [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        if (type != "ipv4") {
            return Reply::fail(Exit::capability, "ps-establish " + type + " comes in v1.x (P1 is IPv4)");
        }
        std::string bad;
        const auto snssai = snssai_arg(req, bad);
        if (!bad.empty()) {
            return Reply::fail(Exit::usage, bad);
        }
        const std::uint64_t psi = number(req.arg("psi"), 0);
        if (psi > 15) {
            return Reply::fail(Exit::usage, "--psi is 1..15");
        }
        proc::ue::SessionRequest r{static_cast<std::uint8_t>(psi), req.arg("dnn"), snssai};
        return run_ue_command(aio, req,
                              UeCommand{[r](UeDevice& u) { return u.ps_establish(r); },
                                        {"nas.sm.est.accept"},
                                        {"nas.sm.est.reject", "nas.sm.est.abort", "nas.sm.not_forwarded"},
                                        {},
                                        "pdu-session-establishment"});
    });
    server.post("/v1/ue/:sel/ps-release", [&aio](const Request& req) {
        const std::uint64_t psi = number(req.arg("psi"), 0);
        if (psi < 1 || psi > 15) {
            return Reply::fail(Exit::usage, "ps-release <psi 1..15>");
        }
        return run_ue_command(aio, req,
                              UeCommand{[psi](UeDevice& u) { return u.ps_release(static_cast<std::uint8_t>(psi)); },
                                        {"nas.sm.release"},
                                        {"nas.sm.rel.reject"},
                                        {{"psi", std::to_string(psi)}},
                                        "pdu-session-release"});
    });
    server.post("/v1/ue/:sel/ping", [&aio](const Request& req) {
        const auto dst = ipv4_arg(req.arg("dst"));
        if (!dst) {
            return Reply::fail(Exit::usage, "ping <IPv4 address>");
        }
        PingRequest p;
        p.dst = *dst;
        p.psi = static_cast<std::uint8_t>(std::min<std::uint64_t>(number(req.arg("psi"), 0), 15));
        p.count = static_cast<int>(std::clamp<std::uint64_t>(number(req.arg("count"), 3), 1, 1000));
        p.interval = static_cast<Millis>(std::clamp<std::uint64_t>(number(req.arg("interval_ms"), 1000), 10, 60'000));
        p.size = static_cast<std::size_t>(std::min<std::uint64_t>(number(req.arg("size"), 56), 8952));
        Reply r = run_ue_command(aio, req,
                                 UeCommand{[p](UeDevice& u) { return u.ping(p); }, {"ue.ping.done"}, {}, {}, "ping"});
        if (r.exit == Exit::ok && r.kv.value("RECEIVED", std::string("0")) == "0" && r.kv.contains("SENT")) {
            r.exit = Exit::failed;   // cli.md §2: no reply at all is a failed ping
            r.set("CAUSE", "no echo reply");
        }
        return r;
    });

    server.get("/v1/wait", [&aio](const Request& req) {
        api::WaitQuery q;
        q.until = api::split_names(req.arg("event"));
        q.fail = api::split_names(req.arg("fail"));
        if (q.until.empty()) {
            return Reply::fail(Exit::usage, "wait needs an event name");
        }
        if (const std::string ue = req.arg("ue"); !ue.empty()) {
            auto subject = aio.call<std::string>([&aio, ue] {
                UeDevice* u = aio.ue(ue);
                return u != nullptr ? u->subject() : std::string();
            });
            if (!subject) {
                return unsound();
            }
            if (subject->empty()) {
                return Reply::fail(Exit::unknown, "no such UE");
            }
            q.subject = *subject;
        } else {
            q.subject = req.arg("subject");
        }
        for (auto [it, end] = req.query.equal_range("where"); it != end; ++it) {
            const auto eq = it->second.find('=');
            if (eq == std::string::npos) {
                return Reply::fail(Exit::usage, "where is key=value");
            }
            q.where.emplace_back(it->second.substr(0, eq), it->second.substr(eq + 1));
        }
        q.since = req.arg("new") == "1" ? aio.events().last_seq() : number(req.arg("since"), 0);
        q.timeout = std::min(std::chrono::milliseconds(number(req.arg("timeout_ms"), 30'000)), kMaxWait);
        return api::wait(aio.events(), q);
    });
    server.stream("/v1/events", [&aio, &stop](const Request& req, const api::Server::Write& write) {
        std::uint64_t since = number(req.arg("since"), 0);
        const std::string subject = req.arg("subject");
        const std::string prefix = req.arg("filter");
        const bool follow = req.arg("follow") == "1";
        auto keep = [&](const Event& e) {
            return (subject.empty() || e.subject == subject) && (prefix.empty() || e.name.rfind(prefix, 0) == 0);
        };
        for (;;) {
            for (const auto& e : aio.events().since(since, 1024)) {
                since = e.seq;
                if (keep(e) && !write(to_ndjson(e) + "\n")) {
                    return;
                }
            }
            if (!follow || stop.load()) {
                return;
            }
            (void)aio.events().wait(since, [](const Event&) { return true; }, std::chrono::milliseconds(1000));
        }
    });
    server.get("/v1/gnb/:name/ue-list", [&aio, &t](const Request& req) {
        if (req.params.at("name") != t.gnb_name) {
            return Reply::fail(Exit::unknown, "no such gNB");
        }
        auto s = aio.call<Reply>([&aio] {
            Reply r;
            const auto list = aio.cucp().ue_list();
            r.set("UES", static_cast<std::int64_t>(list.size()));
            int n = 0;
            for (const auto& u : list) {
                const std::string k = "UE." + std::to_string(++n);
                r.set(k + ".RAN_UE_NGAP_ID", static_cast<std::int64_t>(u.ran_ue));
                r.set(k + ".AMF_UE_NGAP_ID", u.amf_ue ? std::to_string(*u.amf_ue) : "-");
                r.set(k + ".C_RNTI", fmt::format("0x{:04x}", u.c_rnti));
                r.set(k + ".PHASE", u.phase);
            }
            return r;
        });
        return s ? *s : unsound();
    });
    server.get("/v1/gnb/:name/amf-list", [&aio, &t](const Request& req) {
        if (req.params.at("name") != t.gnb_name) {
            return Reply::fail(Exit::unknown, "no such gNB");
        }
        auto s = aio.call<Reply>([&aio, &t] {
            Reply r;
            r.set("AMFS", "1");
            r.set("AMF.1.ADDR", t.amf.to_string());
            r.set("AMF.1.SCTP", aio.ng_up() ? "up" : "down");
            r.set("AMF.1.NG_SETUP", aio.cucp().ng_ready() ? "1" : "0");
            r.set("AMF.1.NAME", aio.cucp().amf_name());
            return r;
        });
        return s ? *s : unsound();
    });
    server.post("/v1/stop", [&stop](const Request&) {
        stop.store(true);
        Reply r;
        r.set("STOPPING", "1");
        return r;
    });
}

} // namespace ksim::node
