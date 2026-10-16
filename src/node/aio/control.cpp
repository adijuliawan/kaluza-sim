// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "node/aio/control.hpp"

#include <ksim/build_info.hpp>

#include <fmt/format.h>

#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <csignal>
#include <regex>
#include <sstream>
#include <cctype>
#include <exception>
#include <optional>
#include <thread>

#include "api/events_stream.hpp"
#include "api/wait.hpp"
#include "proc/ran/cucp.hpp"
#include "proc/ran/cuup.hpp"
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

/// A command run inside a UE's namespace (P1 N11): its exit, output and errors.
struct ExecOut {
    Exit exit = Exit::ok;   // of the run itself: unknown UE, inject mode, netd refused, …
    std::string cause;
    std::string subject;
    int status = -1;        // the command's wait status
    bool timed_out = false;
    std::string out;
    std::string err;
    int code() const noexcept { return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + (WIFSIGNALED(status) ? WTERMSIG(status) : 0); }
};

constexpr std::size_t kExecOutputCap = std::size_t{256} * 1024;

ExecOut run_exec(AllInOne& aio, const std::string& sel, const std::vector<std::string>& argv, std::chrono::milliseconds timeout) {
    ExecOut r;
    int in[2] = {-1, -1};
    int out[2] = {-1, -1};
    int err[2] = {-1, -1};
    int st[2] = {-1, -1};
    if (::pipe2(in, O_CLOEXEC) != 0 || ::pipe2(out, O_CLOEXEC) != 0 || ::pipe2(err, O_CLOEXEC) != 0 ||
        ::pipe2(st, O_CLOEXEC) != 0) {
        for (int f : {in[0], in[1], out[0], out[1], err[0], err[1], st[0], st[1]}) {
            if (f >= 0) {
                ::close(f);
            }
        }
        r.exit = Exit::internal;
        r.cause = "pipes";
        return r;
    }
    ::close(in[1]);   // the command reads end-of-file at once
    struct Started {
        Exit exit = Exit::ok;
        std::string cause;
        std::string subject;
        std::uint32_t pid = 0;
    };
    const std::vector<int> pass{in[0], out[1], err[1], st[1]};
    auto started = aio.call_ue<Started>(sel, [&aio, sel, argv, pass]() -> Started {
        UeDevice* ue = aio.ue(sel);
        if (ue == nullptr) {
            return {Exit::unknown, "no such UE", "", 0};
        }
        if (!ue->netns_mode()) {
            return {Exit::capability, "the UE runs in inject mode: exec needs ksim-netd (topology netd: ues)", ue->subject(), 0};
        }
        auto pid = ue->exec(argv, pass);
        if (!pid) {
            return {Exit::wrong_state, pid.error().what, ue->subject(), 0};
        }
        return {Exit::ok, "", ue->subject(), *pid};
    });
    for (int f : pass) {
        ::close(f);   // netd holds its own copies
    }
    if (!started || started->exit != Exit::ok) {
        for (int f : {out[0], err[0], st[0]}) {
            ::close(f);
        }
        r.exit = started ? started->exit : Exit::abort;
        r.cause = started ? started->cause : "the node did not answer in time";
        r.subject = started ? started->subject : "";
        return r;
    }
    r.subject = started->subject;
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    pollfd fds[2] = {{out[0], POLLIN, 0}, {err[0], POLLIN, 0}};
    int open_fds = 2;
    std::array<char, 4096> buf{};
    while (open_fds > 0) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
        if (left.count() <= 0) {
            r.timed_out = true;
            ::kill(-static_cast<pid_t>(started->pid), SIGKILL);   // the helper leads the command's process group
            break;
        }
        if (::poll(fds, 2, static_cast<int>(std::min<long long>(left.count(), 1000))) < 0 && errno != EINTR) {
            break;
        }
        for (int i = 0; i < 2; ++i) {
            if (fds[i].fd < 0 || (fds[i].revents & (POLLIN | POLLHUP | POLLERR)) == 0) {
                continue;
            }
            const ssize_t n = ::read(fds[i].fd, buf.data(), buf.size());
            if (n <= 0) {
                fds[i].fd = -1;
                --open_fds;
                continue;
            }
            std::string& to = i == 0 ? r.out : r.err;
            if (to.size() < kExecOutputCap) {
                to.append(buf.data(), static_cast<std::size_t>(n));
            }
        }
    }
    pollfd sp{st[0], POLLIN, 0};
    if (::poll(&sp, 1, r.timed_out ? 1000 : 5000) > 0) {
        int status = -1;
        if (::read(st[0], &status, sizeof(status)) == static_cast<ssize_t>(sizeof(status))) {
            r.status = status;
        }
    }
    for (int f : {out[0], err[0], st[0]}) {
        ::close(f);
    }
    return r;
}

/// iputils ping's summary: "3 packets transmitted, 3 received, …" and "rtt min/avg/max/mdev = a/b/c/d ms".
/// A reply's value as text ("" when absent): a reply keeps every value as a
/// string. Out of line, since gcc's -Wnull-dereference misreads json's
/// value() and get() once they are inlined into the route lambdas.
[[gnu::noinline]] std::string kv_text(const Reply& r, const char* key) {
    const auto it = r.kv.find(key);
    if (it == r.kv.end()) {
        return {};
    }
    const std::string* s = it->get_ptr<const std::string*>();
    return s != nullptr ? *s : std::string();
}

void add_ping_summary(Reply& r, const std::string& out) {
    std::smatch m;
    static const std::regex counts(R"((\d+) packets transmitted, (\d+) (?:packets )?received)");
    static const std::regex rtt(R"(= ([0-9.]+)/([0-9.]+)/([0-9.]+)/[0-9.]+ ms)");
    if (std::regex_search(out, m, counts)) {
        const long sent = std::stol(m[1]);
        const long got = std::stol(m[2]);
        r.set("SENT", static_cast<std::int64_t>(sent));
        r.set("RECEIVED", static_cast<std::int64_t>(got));
        r.set("LOSS_PCT", static_cast<std::int64_t>(sent == 0 ? 100 : (sent - got) * 100 / sent));
    }
    if (std::regex_search(out, m, rtt)) {
        r.set("RTT_MIN_MS", m[1].str());
        r.set("RTT_AVG_MS", m[2].str());
        r.set("RTT_MAX_MS", m[3].str());
    }
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
    auto out = aio.call_ue<Out>(sel, [&aio, sel, run = cmd.run]() -> Out {
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
    server.get("/v1/capabilities", [&t](const Request&) {
        // What P1 N8 serves; the rest of cli.md says 0 until its milestone.
        Reply r;
        r.set("CAP.NAS_MM", "1");
        r.set("CAP.AS_SECURITY", "nia2/nea2");
        r.set("CAP.PDU_SESSION", "ipv4");
        r.set("CAP.PING", "inject");
        r.set("CAP.SMS_NAS", "0");
        r.set("CAP.SUCI", "null");
        r.set("CAP.NETNS", t.netd.enabled && t.netd.ues ? "1" : "0");   // the TUN data plane (P1 N11)
        r.set("CAP.FAULTS", "0");
        return r;
    });
    server.get("/v1/faults", [](const Request&) {
        Reply r;
        r.set("FAULTS", "0");   // fault injection is P3
        return r;
    });
    server.get("/v1/info", [&aio, &t](const Request&) {
        auto s = aio.call<Reply>([&aio, &t] {
            // P2 Q3: a role process answers for what it hosts.
            Reply r;
            r.set("ROLE", t.role == Role::all ? "aio" : role_name(t.role));
            if (aio.hosts_cucp()) {
                r.set("NG_UP", aio.ng_up() ? "1" : "0");
                r.set("NG_SETUP", aio.cucp().ng_ready() ? "1" : "0");
                r.set("F1_SETUP", aio.cucp().f1_ready() ? "1" : "0");
                r.set("RAN_UES", static_cast<std::int64_t>(aio.cucp().ues()));
            }
            if (aio.hosts_du()) {
                r.set("CELL_ACTIVE", aio.du().cell_active() ? "1" : "0");
            }
            if (aio.hosts_ues()) {
                r.set("UES", static_cast<std::int64_t>(aio.ues().size()));
            }
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
        if (t.role != Role::all) {
            r.set("NODES", "1");
            r.set("NODE.1.NAME", t.role == Role::ue ? std::string("ue-farm") : t.gnb_name + (t.role == Role::cucp ? "" : std::string("-") + role_name(t.role)));
            r.set("NODE.1.ROLE", role_name(t.role));
            return r;
        }
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
        auto s = aio.call_ue<Reply>(sel, [&aio, sel] {
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
            if (mode == "abrupt") {
                // N12: the battery pulled: no signalling (the gNB finds out by radio supervision).
                return run_ue_command(aio, req,
                                      UeCommand{[](UeDevice& u) { return u.power_off_abrupt(); },
                                                {"ue.power"},
                                                {},
                                                {{"mode", "abrupt"}},
                                                "power-off"});
            }
            if (mode != "switch-off" && mode != "graceful") {
                return Reply::fail(Exit::usage, "power off --switch-off|--graceful|--abrupt");
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
    server.post("/v1/ue/:sel/sim", [&aio](const Request& req) {
        const std::string action = req.arg("action");
        if (action != "remove" && action != "insert") {
            return Reply::fail(Exit::usage, "sim remove|insert");
        }
        const bool present = action == "insert";
        return run_ue_command(aio, req,
                              UeCommand{[present](UeDevice& u) { return u.sim(present); }, {}, {}, {}, "sim"});
    });
    // ---- the card (N14): info, read, trace ----
    server.get("/v1/ue/:sel/sim", [&aio](const Request& req) {
        const std::string sel = req.params.at("sel");
        auto s = aio.call_ue<Reply>(sel, [&aio, sel] {
            UeDevice* ue = aio.ue(sel);
            if (ue == nullptr) {
                return Reply::fail(Exit::unknown, "no such UE");
            }
            const SimInfo i = ue->sim_info();
            Reply r;
            r.set("UE", ue->subject().substr(3));
            r.set("PRESENT", i.present ? "1" : "0");
            r.set("READER", i.reader);
            r.set("ICCID", i.iccid);
            r.set("IMSI", i.imsi);
            r.set("MSISDN", i.msisdn);
            std::string ust;
            for (unsigned n : i.ust) {
                ust += (ust.empty() ? "" : ",") + std::to_string(n);
            }
            r.set("UST", ust);
            r.set("SUCI_SCHEMES", i.suci_schemes);
            r.set("ROUTING_INDICATOR", i.routing_indicator);
            r.set("ATR", i.atr);
            r.set("TRACE", ue->sim_tracing() ? "on" : "off");
            return r;
        });
        return s ? *s : unsound();
    });
    server.get("/v1/ue/:sel/sim-read", [&aio](const Request& req) {
        const std::string sel = req.params.at("sel");
        const std::string ef = req.arg("ef");
        if (ef.empty()) {
            return Reply::fail(Exit::usage, "sim read <EF name, FID or FID path>");
        }
        auto s = aio.call_ue<Reply>(sel, [&aio, sel, ef] {
            UeDevice* ue = aio.ue(sel);
            if (ue == nullptr) {
                return Reply::fail(Exit::unknown, "no such UE");
            }
            auto f = ue->sim_read(ef);
            if (!f) {
                return Reply::fail(Exit::wrong_state, f.error().what);
            }
            Reply r;
            r.set("EF", f->name);
            r.set("PATH", f->path);
            if (f->records) {
                r.set("RECORDS", static_cast<std::int64_t>(f->contents.size()));
                for (std::size_t i = 0; i < f->contents.size(); ++i) {
                    r.set("RECORD." + std::to_string(i + 1), to_hex(f->contents[i]));
                }
            } else {
                r.set("DATA", to_hex(f->contents.front()));
            }
            return r;
        });
        return s ? *s : unsound();
    });
    server.post("/v1/ue/:sel/sim-trace", [&aio](const Request& req) {
        const std::string state = req.arg("state");
        if (state != "on" && state != "off") {
            return Reply::fail(Exit::usage, "sim trace on|off");
        }
        const bool on = state == "on";
        return run_ue_command(aio, req,
                              UeCommand{[on](UeDevice& u) { return u.sim_trace(on); }, {}, {}, {}, "sim trace"});
    });
    server.post("/v1/ue/:sel/airplane", [&aio](const Request& req) {
        const std::string state = req.arg("state");
        if (state != "on" && state != "off") {
            return Reply::fail(Exit::usage, "airplane on|off");
        }
        const bool on = state == "on";
        return run_ue_command(aio, req,
                              UeCommand{[on](UeDevice& u) { return u.airplane(on); }, {}, {}, {}, "airplane"});
    });
    // ---- SMS over NAS (N13) ----
    server.post("/v1/ue/:sel/sms-send", [&aio](const Request& req) {
        proc::ue::SmsSubmit m;
        m.to = req.arg("to");
        m.text = req.arg("text");
        m.ucs2 = req.arg("ucs2") == "1";
        m.status_report = req.arg("srr") == "1";
        if (const std::string vp = req.arg("vp"); !vp.empty()) {
            m.vp = static_cast<std::uint8_t>(std::min<std::uint64_t>(number(vp, 167), 255));
        }
        if (m.to.empty() || m.text.empty()) {
            return Reply::fail(Exit::usage, "sms-send <digits> <text> [--ucs2] [--srr]");
        }
        return run_ue_command(aio, req,
                              UeCommand{[m](UeDevice& u) -> Result<void> {
                                            auto r = u.sms_send(m);
                                            if (!r) {
                                                return r.error();
                                            }
                                            return {};
                                        },
                                        {"sms.mo.done"},
                                        {},
                                        {},
                                        "sms-send"});
    });
    server.get("/v1/ue/:sel/sms", [&aio](const Request& req) {
        const std::string sel = req.params.at("sel");
        auto s = aio.call_ue<Reply>(sel, [&aio, sel] {
            UeDevice* ue = aio.ue(sel);
            if (ue == nullptr) {
                return Reply::fail(Exit::unknown, "no such UE");
            }
            Reply r;
            r.set("UE", ue->subject().substr(3));
            r.set("SMS_ALLOWED", ue->sms_allowed() ? "1" : "0");
            const auto& list = ue->sms_list();
            r.set("MESSAGES", static_cast<std::int64_t>(list.size()));
            for (std::size_t i = 0; i < list.size(); ++i) {
                const std::string k = "SMS." + std::to_string(i + 1);
                const auto& m = list[i];
                r.set(k + ".FROM", m.from);
                r.set(k + ".TEXT", m.text);
                r.set(k + ".DCS", static_cast<std::int64_t>(m.dcs));
                r.set(k + ".UD", to_hex(m.ud));
                r.set(k + ".RECORD", static_cast<std::int64_t>(m.record));
                if (m.concat) {
                    r.set(k + ".CONCAT", fmt::format("{}/{}/{}", (*m.concat)[0], (*m.concat)[2], (*m.concat)[1]));
                }
            }
            return r;
        });
        return s ? *s : unsound();
    });
    server.post("/v1/ue/:sel/sms-memory", [&aio](const Request& req) {
        const std::string state = req.arg("state");
        if (state != "full" && state != "available") {
            return Reply::fail(Exit::usage, "sms-memory full|available");
        }
        const bool full = state == "full";
        return run_ue_command(aio, req,
                              UeCommand{[full](UeDevice& u) -> Result<void> {
                                            u.sms_memory(full);
                                            return {};
                                        },
                                        {},
                                        {},
                                        {},
                                        "sms-memory"});
    });
    server.post("/v1/ue/:sel/service-request", [&aio](const Request& req) {
        return run_ue_command(aio, req,
                              UeCommand{[](UeDevice& u) { return u.service_request(); },
                                        {"nas.sr.accept"},
                                        {"nas.sr.reject", "nas.sr.abort"},
                                        {},
                                        "service-request"});
    });
    server.post("/v1/ue/:sel/register", [&aio](const Request& req) {
        const std::string type = req.arg("type", "initial");
        if (type == "update") {
            // N13: a mobility registration update (e.g. SMS requested again).
            return run_ue_command(aio, req,
                                  UeCommand{[](UeDevice& u) { return u.register_update(); },
                                            {"nas.reg.accept"},
                                            {"nas.reg.reject", "nas.reg.abort"},
                                            {{"type", "mobility"}},
                                            "registration update"});
        }
        if (type != "initial") {
            return Reply::fail(Exit::usage, "register --type initial|update");
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
        auto s = aio.call_ue<Reply>(sel, [&aio, sel] {
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
        // With the TUN data plane the namespace's own ping goes (iputils, as the user).
        const std::string sel = req.params.at("sel");
        auto mode = aio.call_ue<std::pair<bool, std::string>>(sel, [&aio, sel, psi = p.psi]() -> std::pair<bool, std::string> {
            UeDevice* ue = aio.ue(sel);
            if (ue == nullptr || !ue->netns_mode()) {
                return {false, ""};
            }
            for (const auto& i : ue->ifaces()) {
                if (psi == 0 || i.psi == psi) {
                    return {true, i.ifname};
                }
            }
            return {true, ""};
        });
        if (mode && mode->first) {
            if (mode->second.empty()) {
                return Reply::fail(Exit::wrong_state, "no PDU session interface to ping from");
            }
            std::vector<std::string> argv{"ping", "-c", std::to_string(p.count), "-i",
                                          fmt::format("{:.3f}", static_cast<double>(p.interval) / 1000.0), "-s",
                                          std::to_string(p.size), "-W", "2", "-I", mode->second};
            if (req.arg("df") == "1") {
                argv.insert(argv.end(), {"-M", "do"});   // the MTU probe: no fragmentation
            }
            argv.push_back(ipv4_text(*dst));
            const auto budget = std::chrono::milliseconds(static_cast<long long>(p.count) * p.interval + 5'000);
            ExecOut x = run_exec(aio, sel, argv, budget);
            if (x.exit != Exit::ok) {
                return Reply::fail(x.exit, x.cause);
            }
            Reply r;
            r.set("UE", x.subject.substr(3));
            r.set("MODE", "netns");
            r.set("IFACE", mode->second);
            add_ping_summary(r, x.out);
            r.set("EXIT_CODE", static_cast<std::int64_t>(x.code()));
            if (x.code() == 126 || x.code() == 127) {
                // The command never ran (exit 126/127): say why, not "no echo reply".
                r.exit = Exit::failed;
                const std::string first = x.err.substr(0, x.err.find('\n'));
                r.set("CAUSE", "ping could not be run" + (first.empty() ? std::string() : ": " + first));
            } else if (const std::string got = kv_text(r, "RECEIVED"); got.empty() || got == "0") {
                r.exit = Exit::failed;
                r.set("CAUSE", x.timed_out ? "timeout" : "no echo reply");
            }
            return r;
        }
        Reply r = run_ue_command(aio, req,
                                 UeCommand{[p](UeDevice& u) { return u.ping(p); }, {"ue.ping.done"}, {}, {}, "ping"});
        r.set("MODE", "inject");
        if (const std::string got = kv_text(r, "RECEIVED"); r.exit == Exit::ok && (got.empty() || got == "0") && r.kv.contains("SENT")) {
            r.exit = Exit::failed;   // cli.md §2: no reply at all is a failed ping
            r.set("CAUSE", "no echo reply");
        }
        return r;
    });

    // ---- the TUN data plane (P1 N11) ----
    server.post("/v1/ue/:sel/exec", [&aio](const Request& req) {
        std::vector<std::string> argv;
        if (req.body.is_object() && req.body.contains("argv") && req.body["argv"].is_array()) {
            for (const auto& a : req.body["argv"]) {
                if (!a.is_string()) {
                    return Reply::fail(Exit::usage, "exec takes words");
                }
                argv.push_back(a.get<std::string>());
            }
        }
        if (argv.empty() || argv.size() > 16) {
            return Reply::fail(Exit::usage, "exec <command> [args…] (16 words at most)");
        }
        const auto timeout = std::min(std::chrono::milliseconds(number(req.arg("timeout_ms"), 30'000)), kMaxWait);
        ExecOut x = run_exec(aio, req.params.at("sel"), argv, timeout);
        if (x.exit != Exit::ok) {
            Reply r = Reply::fail(x.exit, x.cause);
            if (!x.subject.empty()) {
                r.set("UE", x.subject.substr(3));
            }
            return r;
        }
        Reply r;
        r.set("UE", x.subject.substr(3));
        r.set("EXIT_CODE", static_cast<std::int64_t>(x.code()));
        r.set("TIMED_OUT", x.timed_out ? "1" : "0");
        r.set("STDOUT", x.out);
        r.set("STDERR", x.err);
        if (x.timed_out) {
            r.exit = Exit::timeout;
        } else if (x.code() != 0) {
            r.exit = Exit::failed;
        }
        return r;
    });
    server.get("/v1/ue/:sel/ifaces", [&aio](const Request& req) {
        const std::string sel = req.params.at("sel");
        auto s = aio.call_ue<Reply>(sel, [&aio, sel] {
            UeDevice* ue = aio.ue(sel);
            if (ue == nullptr) {
                return Reply::fail(Exit::unknown, "no such UE");
            }
            Reply r;
            r.set("UE", ue->subject().substr(3));
            r.set("MODE", ue->netns_mode() ? "netns" : "inject");
            if (ue->netns_mode()) {
                r.set("NETNS", ue->netns_up() ? ue->config().netns : "");
            }
            const auto list = ue->ifaces();
            r.set("IFACES", static_cast<std::int64_t>(list.size()));
            for (const auto& i : list) {
                const std::string k = "IF." + i.ifname;
                r.set(k + ".PSI", static_cast<std::int64_t>(i.psi));
                r.set(k + ".IP", ipv4_text(i.addr));
                r.set(k + ".MTU", static_cast<std::int64_t>(i.mtu));
                r.set(k + ".DNS", i.dns ? ipv4_text(*i.dns) : "");
                r.set(k + ".UL_PACKETS", static_cast<std::int64_t>(i.ul));
                r.set(k + ".DL_PACKETS", static_cast<std::int64_t>(i.dl));
            }
            r.set("NOISE", static_cast<std::int64_t>(ue->noise()));
            return r;
        });
        if (!s) {
            return unsound();
        }
        Reply r = *s;
        if (r.exit != Exit::ok || kv_text(r, "MODE") != "netns" || kv_text(r, "NETNS").empty()) {
            return r;
        }
        // The kernel's own view of the namespace: every address on every link.
        ExecOut x = run_exec(aio, sel, {"ip", "-o", "addr", "show"}, std::chrono::seconds(10));
        if (x.exit != Exit::ok || x.code() != 0) {
            r.set("KERNEL", "unavailable");
            return r;
        }
        std::int64_t v4 = 0;
        std::int64_t v6 = 0;
        std::istringstream lines(x.out);
        std::string line;
        static const std::regex addr(R"(^\d+:\s+(\S+)\s+(inet6?)\s+(\S+))");
        while (std::getline(lines, line)) {
            std::smatch m;
            if (!std::regex_search(line, m, addr) || m[1] == "lo") {
                continue;
            }
            if (m[2] == "inet") {
                ++v4;
                r.set("KERNEL." + m[1].str() + ".IPV4", m[3].str());
            } else {
                ++v6;
            }
        }
        r.set("KERNEL_IPV4", v4);
        r.set("KERNEL_IPV6", v6);   // the UE's tunnels must hold none (L13)
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
        api::stream_events(aio.events(), since, keep, follow, stop, write);   // a blank line each quiet second
    });
    server.get("/v1/gnb/:name/ue-list", [&aio, &t](const Request& req) {
        if (req.params.at("name") != t.gnb_name || !aio.hosts_cucp()) {
            return Reply::fail(Exit::unknown, "no such gNB");
        }
        auto s = aio.call<Reply>([&aio] {
            Reply r;
            const auto list = aio.cucp().ue_list();
            r.set("UES", static_cast<std::int64_t>(list.size()));
            // P2 Q2: the streams the DU's UE-associated F1AP came on (TS 38.472 §7).
            std::string streams;
            for (std::uint16_t st : aio.cucp().f1_ue_streams()) {
                streams += (streams.empty() ? "" : ",") + std::to_string(st);
            }
            r.set("F1_UE_STREAMS", streams.empty() ? "-" : streams);
            r.set("F1_UE_ON_STREAM0", static_cast<std::int64_t>(aio.cucp().stats().f1_ue_on_stream0));
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
        if (req.params.at("name") != t.gnb_name || !aio.hosts_cucp()) {
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
    server.post("/v1/gnb/:name/ue-release", [&aio, &t](const Request& req) {
        if (req.params.at("name") != t.gnb_name || !aio.hosts_cucp()) {
            return Reply::fail(Exit::unknown, "no such gNB");
        }
        const std::string sel = req.arg("ue");
        const std::string cause = req.arg("cause", "user-inactivity");
        if (!aio.hosts_ues()) {
            // P2 Q3: in a split run the supervisor found the UE's C-RNTI at the farm.
            const std::string crnti = req.arg("c_rnti");
            const std::string label = req.arg("ue_label");
            auto s = aio.call<Reply>([&aio, crnti, cause, label] {
                for (const auto& u : aio.cucp().ue_list()) {
                    if (!crnti.empty() && fmt::format("0x{:04x}", u.c_rnti) == crnti) {
                        if (auto r = aio.cucp().request_release(u.ran_ue, cause); !r) {
                            return Reply::fail(Exit::wrong_state, r.error().what);
                        }
                        Reply out;
                        out.set("UE", label);
                        out.set("RAN_UE_NGAP_ID", static_cast<std::int64_t>(u.ran_ue));
                        out.set("CAUSE", cause);
                        out.set("RESULT", "STARTED");
                        return out;
                    }
                }
                return Reply::fail(Exit::wrong_state, "the UE has no RRC connection at this gNB");
            });
            return s ? *s : unsound();
        }
        auto s = aio.call_ue<Reply>(sel, [&aio, sel, cause] {
            // The UE by its farm selector, found at the CU-CP by its C-RNTI.
            UeDevice* ue = aio.ue(sel);
            if (ue == nullptr) {
                return Reply::fail(Exit::unknown, "no such UE");
            }
            std::string crnti;
            for (const auto& [k, v] : ue->status()) {
                if (k == "C_RNTI") {
                    crnti = v;
                }
            }
            for (const auto& u : aio.cucp().ue_list()) {
                if (!crnti.empty() && fmt::format("0x{:04x}", u.c_rnti) == crnti) {
                    if (auto r = aio.cucp().request_release(u.ran_ue, cause); !r) {
                        return Reply::fail(Exit::wrong_state, r.error().what);
                    }
                    Reply out;
                    out.set("UE", ue->subject().substr(3));
                    out.set("RAN_UE_NGAP_ID", static_cast<std::int64_t>(u.ran_ue));
                    out.set("CAUSE", cause);
                    out.set("RESULT", "STARTED");
                    return out;
                }
            }
            return Reply::fail(Exit::wrong_state, "the UE has no RRC connection at this gNB");
        });
        return s ? *s : unsound();
    });
    server.post("/v1/gnb/:name/restart", [&aio, &t](const Request& req) {
        if (req.params.at("name") != t.gnb_name || !aio.hosts_cucp()) {
            return Reply::fail(Exit::unknown, "no such gNB");
        }
        if (t.role != Role::all) {
            return Reply::fail(Exit::wrong_state, "a split run's gNB is restarted by its supervisor");
        }
        const std::uint64_t since = aio.events().last_seq();
        auto s = aio.call<Reply>([&aio] {
            if (auto r = aio.restart_gnb(); !r) {
                return Reply::fail(Exit::internal, r.error().what);
            }
            Reply out;
            out.set("RESULT", "STARTED");
            return out;
        });
        if (!s) {
            return unsound();
        }
        Reply r = *s;
        r.set("EVENT_SEQ", static_cast<std::int64_t>(since));
        return r;
    });
    server.get("/v1/du/:name/ue-list", [&aio, &t](const Request& req) {
        if (req.params.at("name") != t.gnb_name + "-du" || !aio.hosts_du()) {
            return Reply::fail(Exit::unknown, "no such DU");
        }
        auto s = aio.call<Reply>([&aio] {
            Reply r;
            r.set("CELL_ACTIVE", aio.du().cell_active() ? "1" : "0");
            r.set("UES", static_cast<std::int64_t>(aio.du().ues()));
            r.set("UL_SDUS", static_cast<std::int64_t>(aio.du().stats().ul_sdus));
            r.set("DL_SDUS", static_cast<std::int64_t>(aio.du().stats().dl_sdus));
            r.set("WRONG_PPID", static_cast<std::int64_t>(aio.du().stats().wrong_ppid));
            r.set("DDDS_TX", static_cast<std::int64_t>(aio.du().stats().ddds_tx));
            r.set("SI_TX", static_cast<std::int64_t>(aio.du().stats().si_tx));
            return r;
        });
        return s ? *s : unsound();
    });
    server.get("/v1/cuup/:name/bearers", [&aio, &t](const Request& req) {
        if (req.params.at("name") != t.gnb_name + "-cuup" || !aio.hosts_cuup()) {
            return Reply::fail(Exit::unknown, "no such CU-UP");
        }
        auto s = aio.call<Reply>([&aio] {
            Reply r;
            r.set("E1_READY", aio.cuup().e1_ready() ? "1" : "0");
            r.set("CONTEXTS", static_cast<std::int64_t>(aio.cuup().contexts()));
            r.set("DL_PACKETS", static_cast<std::int64_t>(aio.cuup().stats().dl_packets));
            r.set("UL_PACKETS", static_cast<std::int64_t>(aio.cuup().stats().ul_packets));
            r.set("DROPPED", static_cast<std::int64_t>(aio.cuup().stats().dropped));
            r.set("DDDS_RX", static_cast<std::int64_t>(aio.cuup().stats().ddds_rx));
            r.set("INACTIVITY_REPORTS", static_cast<std::int64_t>(aio.cuup().stats().inactivity_reports));
            return r;
        });
        return s ? *s : unsound();
    });
    // P2 Q7, metrics v0 (KS-CTL-005 in part): the Prometheus text format. The CU-UP's
    // counters and the loop lag are read on the shard.
    server.stream("/v1/metrics", [&aio](const Request&, const api::Server::Write& write) {
        auto text = aio.call<std::string>([&aio] {
            std::map<std::uint8_t, QfiCounters> per_qfi;
            if (aio.hosts_cuup()) {
                for (const auto& [qfi, q] : aio.cuup().per_qfi()) {
                    per_qfi[qfi] = QfiCounters{q.ul_bytes, q.dl_bytes, q.ul_packets, q.dl_packets};
                }
            }
            return aio.metrics().render(per_qfi, aio.max_lag_ms());
        });
        (void)write(text ? *text : std::string("# the run's loop did not answer\n"));
    });
    // P2 Q7: blocks this process's loop for ms (at most 5000), so the watchdog has
    // something to see (row ksim-p2.loop-lag-abort). The answer comes after.
    server.post("/v1/debug/stall", [&aio](const Request& req) {
        long ms = 0;
        try {
            ms = std::stol(req.arg("ms"));
        } catch (const std::exception&) {
            ms = -1;
        }
        if (ms < 1 || ms > 5'000) {
            return Reply::fail(Exit::usage, "debug stall takes 1..5000 ms");
        }
        auto s = aio.call<Reply>(
            [ms] {
                std::this_thread::sleep_for(std::chrono::milliseconds(ms));
                Reply r;
                r.set("STALLED_MS", static_cast<std::int64_t>(ms));
                return r;
            },
            std::chrono::milliseconds(ms + 5'000));
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
