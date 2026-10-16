// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "supervisor.hpp"

#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <httplib.h>

#include <algorithm>
#include <cstdlib>
#include <array>
#include <atomic>
#include <chrono>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <memory>
#include <mutex>
#include <sstream>
#include <thread>
#include <vector>

#include "api/events_stream.hpp"
#include "api/http.hpp"
#include "api/reply.hpp"
#include "api/wait.hpp"
#include "node/aio/run_dir.hpp"
#include "node/aio/topology.hpp"
#include "platform/clock.hpp"
#include "platform/event.hpp"
#include "platform/log.hpp"

extern char** environ;   // NOLINT: posix_spawn passes our environment on

namespace ksim::app {

namespace {

using api::Exit;
using api::json;
using api::Reply;
using api::Request;

constexpr std::chrono::milliseconds kMaxWait{600'000};

std::string encode(const std::string& s) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    for (const char c : s) {
        const auto ch = static_cast<unsigned char>(c);
        if (std::isalnum(ch) != 0 || ch == '-' || ch == '_' || ch == '.' || ch == '~' || ch == ':') {
            out += static_cast<char>(ch);
        } else {
            out += '%';
            out += hex[ch >> 4];
            out += hex[ch & 0xF];
        }
    }
    return out;
}

std::string self_exe() {
    std::array<char, 4096> buf{};
    const ssize_t n = ::readlink("/proc/self/exe", buf.data(), buf.size() - 1);
    return n > 0 ? std::string(buf.data(), static_cast<std::size_t>(n)) : std::string("ksim");
}

std::uint64_t number(const std::string& v, std::uint64_t fallback) {
    try {
        return v.empty() ? fallback : std::stoull(v);
    } catch (const std::exception&) {
        return fallback;
    }
}

struct Child {
    Child(std::string r, const std::string& run)
        : role(std::move(r)), dir(run + "/" + role), ctl(dir + "/ctl.sock"), pid(-1), generation(0), expected_exit(false) {}

    std::string role;
    std::string dir;
    std::string ctl;
    std::atomic<pid_t> pid;
    std::atomic<std::uint64_t> generation;   // a new process each time it is (re)started
    std::atomic<bool> expected_exit;         // a stop or a restart we asked for
};

class Supervisor {
public:
    Supervisor(const node::Topology& t, std::string topology_file, std::string run, RoleArgs a)
        : t_(t), topology_file_(std::move(topology_file)), run_(std::move(run)), args_(std::move(a)),
          events_(1U << 16, clock_) {
        // EventRing's constructor (platform/event.cpp) sets every field; the analyzer does not see into it.
        // A role the topology gives the interop peer (ADR 0012) is not ours to run.
        peers_ = {{"cucp", t.peer_cucp}, {"cuup", t.peer_cuup}};
        for (const char* r : {"cucp", "cuup", "du", "ue"}) {   // NOLINT(clang-analyzer-optin.cplusplus.UninitializedObject)
            if (peer_of(r).empty()) {
                children_.push_back(std::make_unique<Child>(r, run_));
            }
        }
    }
    ~Supervisor() {
        try {
            shutdown();
        } catch (const std::exception& e) {
            std::fputs("ksim: the supervisor's shutdown failed\n", stderr);
        }
    }
    Supervisor(const Supervisor&) = delete;
    Supervisor& operator=(const Supervisor&) = delete;

    /// Our process for the role, or nullptr when the peer runs it.
    Child* child(const std::string& role) {
        for (auto& c : children_) {
            if (c->role == role) {
                return c.get();
            }
        }
        return nullptr;
    }
    std::string peer_of(const std::string& role) const {
        const auto it = peers_.find(role);
        return it == peers_.end() ? std::string() : it->second;
    }
    /// The answer for a verb of a role the peer runs: it has no ksim control API.
    Reply peer_reply(const std::string& role) const {
        return Reply::fail(Exit::capability, "the " + role + " is " + peer_of(role) + "'s (topology peers): no ksim verbs");
    }

    bool start(std::string& why) {
        auto ef = node::EventFile::open(run_ + "/events.ndjson");
        if (!ef) {
            why = ef.error().what;
            return false;
        }
        event_file_ = std::move(*ef);
        events_.on_emit([f = event_file_.get()](const Event& e) { f->write(e); });
        for (auto& c : children_) {
            if (!spawn(*c, why)) {
                return false;
            }
            relays_.emplace_back([this, p = c.get()] { relay(*p); });
        }
        link_captures();
        reaping_ = true;
        reaper_ = std::thread([this] { reap(); });
        return true;
    }

    void bind(api::Server& server, std::atomic<bool>& stop);
    void shutdown();
    std::string manifest_roles() const {
        json r = json::object();
        for (const auto& c : children_) {
            r[c->role] = {{"pid", static_cast<std::int64_t>(c->pid.load())}, {"dir", c->dir}};
        }
        return r.dump();
    }

private:
    bool spawn(Child& c, std::string& why);
    void stop_child(Child& c);
    void relay(Child& c);
    void reap();
    void link_captures();
    /// `wait`: how long the role may take to answer (P2 Q7: a call to a role that does not
    /// answer holds one of the supervisor's server threads that long, so never longer than
    /// the request itself can take).
    Reply call(const Child& c, const std::string& method, const std::string& path, const json& body = json(),
               std::chrono::milliseconds wait = std::chrono::seconds(45)) const;
    Reply forward(const Child& c, const Request& r) const;
    void restart_gnb();

    const node::Topology& t_;
    std::string topology_file_;
    std::string run_;
    RoleArgs args_;
    MonotonicClock clock_;
    EventRing events_;
    std::unique_ptr<node::EventFile> event_file_;
    std::vector<std::unique_ptr<Child>> children_;
    std::map<std::string, std::string> peers_;   // role to peer ("ocudu"), empty: ours
    std::vector<std::thread> relays_;
    std::thread reaper_;
    std::thread restarter_;
    std::mutex restart_mu_;
    std::atomic<bool> stopping_{false};
    std::atomic<bool> restarting_{false};
    std::atomic<bool> reaping_{false};
    std::atomic<std::uint64_t> torn_lines_{0};
};

bool Supervisor::spawn(Child& c, std::string& why) {
    // The role makes its own run directory (it must be new or empty); its output goes beside it.
    // A restart keeps what the role's last process wrote as <role>.<n>/ (the evidence before it).
    std::error_code ec;
    if (std::filesystem::exists(c.dir)) {
        std::filesystem::rename(c.dir, c.dir + "." + std::to_string(c.generation.load()), ec);
        std::filesystem::rename(run_ + "/" + c.role + ".out", c.dir + "." + std::to_string(c.generation.load()) + ".out", ec);
    }
    std::vector<std::string> argv{self_exe(), "run", "-c", topology_file_, "--run-dir", c.dir, "--role", c.role,
                                  "--kair", run_ + "/kair.sock"};
    if (args_.lab) {
        argv.emplace_back("--lab");
    }
    if (args_.plain_nas) {
        argv.emplace_back("--plain-nas");
    }
    if (!args_.sealed.empty()) {
        argv.insert(argv.end(), {"--sealed", args_.sealed});
    }
    if (!args_.kek.empty()) {
        argv.insert(argv.end(), {"--kek", args_.kek});
    }
    const std::string out = run_ + "/" + c.role + ".out";
    const int fd = ::open(out.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        why = "cannot create " + out;
        return false;
    }
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, fd, 1);
    posix_spawn_file_actions_adddup2(&fa, fd, 2);
    std::vector<char*> args;
    args.reserve(argv.size() + 1);
    for (auto& a : argv) {
        args.push_back(a.data());
    }
    args.push_back(nullptr);
    pid_t pid = -1;
    const int rc = posix_spawn(&pid, args[0], &fa, nullptr, args.data(), environ);
    posix_spawn_file_actions_destroy(&fa);
    ::close(fd);
    if (rc != 0) {
        why = "cannot start the " + c.role + " role";
        return false;
    }
    c.pid = pid;
    c.expected_exit = false;
    ++c.generation;
    // Ready when it prints CTL= (its links listen or are being dialled by then).
    const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    while (std::chrono::steady_clock::now() < end) {
        std::ifstream in(out);
        std::stringstream ss;
        ss << in.rdbuf();
        if (ss.str().find("\nCTL=") != std::string::npos || ss.str().rfind("CTL=", 0) == 0) {
            events_.emit("run.role.start", "run:" + c.role, {{"role", c.role}, {"pid", std::to_string(pid)}});
            return true;
        }
        // Before the reaper runs this thread reaps; after, the reaper does and says so in c.pid.
        int status = 0;
        if ((!reaping_.load() && ::waitpid(pid, &status, WNOHANG) == pid) || c.pid.load() <= 0) {
            c.pid = -1;
            why = "the " + c.role + " role exited at start: " + ss.str();
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    why = "the " + c.role + " role did not come up";
    return false;
}

void Supervisor::stop_child(Child& c) {
    const pid_t pid = c.pid.load();
    if (pid <= 0) {
        return;
    }
    c.expected_exit = true;
    (void)call(c, "POST", "/v1/stop", json(), std::chrono::seconds(5));   // one that does not answer is signalled
    for (int i = 0; i < 100; ++i) {   // 10 s for a graceful stop
        if (c.pid.load() <= 0) {
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    ::kill(pid, SIGTERM);
    for (int i = 0; i < 50 && c.pid.load() > 0; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    if (c.pid.load() > 0) {
        ::kill(pid, SIGKILL);
    }
}

void Supervisor::reap() {
    while (!stopping_.load() || std::any_of(children_.begin(), children_.end(), [](const auto& c) { return c->pid.load() > 0; })) {
        int status = 0;
        const pid_t pid = ::waitpid(-1, &status, WNOHANG);
        if (pid > 0) {
            for (auto& c : children_) {
                if (c->pid.load() == pid) {
                    c->pid = -1;
                    if (!c->expected_exit.load()) {
                        const std::string how = WIFEXITED(status) ? "exit " + std::to_string(WEXITSTATUS(status))
                                                                  : "signal " + std::to_string(WTERMSIG(status));
                        events_.emit("run.role.exit", "run:" + c->role, {{"role", c->role}, {"status", how}});
                        log::warn("ksim", "the {} role ended on its own ({})", c->role, how);
                    }
                }
            }
            continue;
        }
        if (pid < 0 && stopping_.load()) {
            return;   // no children left
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

void Supervisor::relay(Child& c) {
    std::uint64_t since = 0;
    std::uint64_t gen = c.generation.load();
    while (!stopping_.load()) {
        if (c.generation.load() != gen) {
            gen = c.generation.load();
            since = 0;   // a new process numbers its events from 1
        }
        if (c.pid.load() <= 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            continue;
        }
        httplib::Client cli(api::socket_target(c.ctl));
        cli.set_address_family(AF_UNIX);
        cli.set_connection_timeout(std::chrono::seconds(2));
        // A role's stream sends a blank line each quiet second (KS-PLAT-D14), so 5 s with
        // nothing at all is a role in trouble: reconnect and go on after `since`.
        cli.set_read_timeout(std::chrono::seconds(5));
        std::string buf;
        (void)cli.Get("/v1/events?follow=1&since=" + std::to_string(since), [&](const char* data, std::size_t n) {
            buf.append(data, n);
            for (std::size_t nl = buf.find('\n'); nl != std::string::npos; nl = buf.find('\n')) {
                const std::string line = buf.substr(0, nl);
                buf.erase(0, nl + 1);
                if (line.empty()) {
                    continue;   // the stream's keepalive
                }
                try {
                    const json j = json::parse(line);
                    Event e;
                    e.time_ms = j.value("t_ms", Millis{0});
                    e.wall_ns = j.value("wall_ns", std::int64_t{0});
                    e.name = j.value("event", std::string());
                    e.subject = j.value("subject", std::string());
                    if (j.contains("fields") && j.at("fields").is_object()) {
                        for (const auto& [k, v] : j.at("fields").items()) {
                            e.fields.push_back(EventField{k, v.is_string() ? v.get<std::string>() : v.dump()});
                        }
                    }
                    since = j.value("seq", since);
                    events_.relay(std::move(e));
                } catch (const std::exception&) {
                    ++torn_lines_;   // a torn line from a dying role; the next connection starts after `since`
                }
            }
            return !stopping_.load() && c.generation.load() == gen;
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
}

void Supervisor::link_captures() {
    // With a peer CU-CP or CU-UP our DU captures F1AP or F1-U itself; the peer's NGAP
    // and E1AP are in its own captures (tools/ocudu-peer.sh writes them in the run).
    const bool own_cucp = child("cucp") != nullptr;
    const bool own_cuup = child("cuup") != nullptr;
    const std::pair<const char*, const char*> links[] = {
        {"ngap.pcapng", own_cucp ? "cucp" : nullptr}, {"f1ap.pcapng", own_cucp ? "cucp" : "du"},
        {"e1ap.pcapng", own_cucp ? "cucp" : (own_cuup ? "cuup" : nullptr)}, {"gtpu.pcapng", own_cuup ? "cuup" : "du"},
        {"uu.pcapng", "ue"}, {"sim.pcapng", "ue"}};
    for (const auto& [file, role] : links) {
        if (role != nullptr) {
            std::error_code ec;
            std::filesystem::create_symlink(std::string(role) + "/" + file, run_ + "/" + file, ec);
        }
    }
}

Reply Supervisor::call(const Child& c, const std::string& method, const std::string& path, const json& body,
                       std::chrono::milliseconds wait) const {
    httplib::Client cli(api::socket_target(c.ctl));
    cli.set_address_family(AF_UNIX);
    cli.set_connection_timeout(std::chrono::seconds(5));
    cli.set_read_timeout(std::min(wait, kMaxWait + std::chrono::seconds(10)));
    auto res = method == "GET" ? cli.Get(path) : cli.Post(path, body.is_null() ? "{}" : body.dump(), "application/json");
    if (!res) {
        return Reply::fail(Exit::abort, "the " + c.role + " role does not answer");
    }
    auto r = Reply::parse(res->body);
    return r ? *r : Reply::fail(Exit::internal, "the " + c.role + " role's answer is not a control API reply");
}

Reply Supervisor::forward(const Child& c, const Request& r) const {
    std::string path = r.path;
    char sep = '?';
    for (const auto& [k, v] : r.query) {
        path += sep;
        path += encode(k) + "=" + encode(v);
        sep = '&';
    }
    // The request's own bound: ksim-ctl waits its --timeout (30 s by default) plus the
    // wait_ms or timeout_ms it sends with what may block, then 5 s; the role gets 15 s past.
    long extra = 0;
    for (const char* k : {"wait_ms", "timeout_ms"}) {
        if (r.has(k)) {
            extra = std::max(extra, std::atol(r.arg(k, "0").c_str()));
        }
    }
    return call(c, r.method, path, r.body, std::chrono::milliseconds(30'000 + extra) + std::chrono::seconds(15));
}

void Supervisor::restart_gnb() {
    // ksim-ctl gnb restart in split mode: the gNB's processes stop and start again
    // (row amf-ueransim.032). The UEs find out on the air, the core from a new association.
    const std::lock_guard<std::mutex> lock(restart_mu_);
    restarting_ = true;
    events_.emit("ran.gnb.restart", "gnb:" + t_.gnb_name, {{"mode", "split"}});
    for (const char* r : {"du", "cuup", "cucp"}) {
        if (Child* c = child(r)) {
            stop_child(*c);
        }
    }
    std::string why;
    for (const char* r : {"cucp", "cuup", "du"}) {
        Child* c = child(r);
        if (c != nullptr && !spawn(*c, why)) {
            log::warn("ksim", "gNB restart: {}", why);
            events_.emit("run.role.exit", "run:" + std::string(r), {{"role", r}, {"status", "restart failed"}});
            break;
        }
    }
    restarting_ = false;
}

void Supervisor::shutdown() {
    if (stopping_.exchange(true)) {
        return;
    }
    if (restarter_.joinable()) {
        restarter_.join();
    }
    for (const char* r : {"ue", "du", "cuup", "cucp"}) {
        if (Child* c = child(r)) {
            stop_child(*c);
        }
    }
    for (auto& t : relays_) {
        if (t.joinable()) {
            t.join();
        }
    }
    if (reaper_.joinable()) {
        reaper_.join();
    }
}

void Supervisor::bind(api::Server& server, std::atomic<bool>& stop) {
    Child& ue = *child("ue");
    Child& du = *child("du");
    Child* cucp = child("cucp");   // nullptr: the peer's (ADR 0012)
    auto to = [this, &server](const char* method, const std::string& pattern, const char* role) {
        Child* c = child(role);
        auto h = [this, c, role = std::string(role)](const Request& r) { return c != nullptr ? forward(*c, r) : peer_reply(role); };
        if (std::string(method) == "GET") {
            server.get(pattern, h);
        } else {
            server.post(pattern, h);
        }
    };
    // The UE farm's verbs.
    to("GET", "/v1/ues", "ue");
    to("GET", "/v1/capabilities", "ue");
    for (const char* p : {"status", "sim", "sim-read", "sms", "ps", "ifaces"}) {
        to("GET", std::string("/v1/ue/:sel/") + p, "ue");
    }
    for (const char* p : {"power", "sim", "sim-trace", "airplane", "sms-send", "sms-memory", "service-request",
                          "register", "deregister", "ps-establish", "ps-release", "ping", "exec"}) {
        to("POST", std::string("/v1/ue/:sel/") + p, "ue");
    }
    // The gNB's.
    to("GET", "/v1/version", cucp != nullptr ? "cucp" : "du");
    to("GET", "/v1/gnb/:name/ue-list", "cucp");
    to("GET", "/v1/gnb/:name/amf-list", "cucp");
    to("POST", "/v1/gnb/:name/up-policy", "cucp");   // P2 Q9
    to("GET", "/v1/du/:name/ue-list", "du");
    to("POST", "/v1/debug/stall", "du");   // P2 Q7: the DU's loop has timers that come due
    to("GET", "/v1/cuup/:name/bearers", "cuup");
    server.get("/v1/faults", [](const Request&) {
        Reply r;
        r.set("FAULTS", "0");   // fault injection is P3
        return r;
    });
    server.get("/v1/nodes", [this](const Request&) {
        Reply r;
        int n = 0;
        for (const char* role : {"cucp", "cuup", "du", "ue"}) {
            const std::string k = "NODE." + std::to_string(++n);
            const std::string rs(role);
            r.set(k + ".NAME", rs == "ue" ? std::string("ue-farm") : t_.gnb_name + (rs == "cucp" ? "" : "-" + rs));
            r.set(k + ".ROLE", rs);
            if (const Child* c = child(rs)) {
                r.set(k + ".PID", static_cast<std::int64_t>(c->pid.load()));
                r.set(k + ".UP", c->pid.load() > 0 ? "1" : "0");
            } else {
                r.set(k + ".PEER", peer_of(rs));   // not ours: no PID, no UP
            }
        }
        r.set("NODES", static_cast<std::int64_t>(n));
        return r;
    });
    server.get("/v1/info", [this, &ue, cucp, &du](const Request&) {
        const Reply a = cucp != nullptr ? call(*cucp, "GET", "/v1/info") : peer_reply("cucp");
        const Reply b = call(du, "GET", "/v1/info");
        const Reply c = call(ue, "GET", "/v1/info");
        Reply r;
        r.set("ROLE", "split");
        auto copy = [&r](const Reply& from, const char* key) {
            if (from.kv.contains(key)) {
                r.kv[key] = from.kv.at(key);
            }
        };
        for (const char* k : {"NG_UP", "NG_SETUP", "F1_SETUP", "RAN_UES"}) {
            copy(a, k);
        }
        for (const char* k : {"CELL_ACTIVE", "KAIR_FRAMES", "KAIR_ERRORS"}) {
            copy(b, k);
        }
        copy(c, "UES");
        std::int64_t lag = 0;
        for (const Reply* x : {&a, &b, &c}) {
            if (x->kv.contains("LOOP_LAG_MAX_MS")) {
                lag = std::max<std::int64_t>(lag, std::stoll(x->kv.at("LOOP_LAG_MAX_MS").get<std::string>()));
            }
        }
        r.set("GNB", t_.gnb_name);
        if (cucp == nullptr) {
            r.set("PEER_CUCP", peer_of("cucp"));
        } else {
            copy(a, "AS_NEA");   // P2 Q8
            copy(a, "AS_NIA");
        }
        if (child("cuup") == nullptr) {
            r.set("PEER_CUUP", peer_of("cuup"));
        }
        r.set("PLMN", t_.mcc + t_.mnc);
        r.set("AMF", t_.amf.to_string());
        r.set("RUN_DIR", run_);
        r.set("EVENT_SEQ", static_cast<std::int64_t>(events_.last_seq()));
        r.set("LOOP_LAG_MAX_MS", lag);
        return r;
    });
    server.get("/v1/wait", [this, &ue](const Request& req) {
        api::WaitQuery q;
        q.until = api::split_names(req.arg("event"));
        q.fail = api::split_names(req.arg("fail"));
        if (q.until.empty()) {
            return Reply::fail(Exit::usage, "wait needs an event name");
        }
        if (const std::string sel = req.arg("ue"); !sel.empty()) {
            const Reply st = call(ue, "GET", "/v1/ue/" + encode(sel) + "/status");
            if (st.exit != Exit::ok || !st.kv.contains("UE")) {
                return Reply::fail(Exit::unknown, "no such UE");
            }
            q.subject = "ue:" + st.kv.at("UE").get<std::string>();
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
        q.since = req.arg("new") == "1" ? events_.last_seq() : number(req.arg("since"), 0);
        q.timeout = std::min(std::chrono::milliseconds(number(req.arg("timeout_ms"), 30'000)), kMaxWait);
        return api::wait(events_, q);
    });
    server.stream("/v1/events", [this, &stop](const Request& req, const api::Server::Write& write) {
        std::uint64_t since = number(req.arg("since"), 0);
        const std::string subject = req.arg("subject");
        const std::string prefix = req.arg("filter");
        const bool follow = req.arg("follow") == "1";
        api::stream_events(
            events_, since,
            [&](const Event& e) {
                return (subject.empty() || e.subject == subject) && (prefix.empty() || e.name.rfind(prefix, 0) == 0);
            },
            follow, stop, write);
    });
    // P2 Q10: the UE's DRBs at the CU-CP and a QoS flow the gNB releases itself, the UE
    // found at the farm by its C-RNTI as for ue-release.
    const auto with_crnti = [this, &ue, cucp](const Request& req, const std::string& method, const std::string& route,
                                              json body) -> Reply {
        if (req.params.at("name") != t_.gnb_name) {
            return Reply::fail(Exit::unknown, "no such gNB");
        }
        if (cucp == nullptr) {
            return peer_reply("cucp");
        }
        Reply st = call(ue, "GET", "/v1/ue/" + encode(req.arg("ue")) + "/status");
        if (st.exit != Exit::ok) {
            return st;
        }
        const std::string crnti = st.kv.contains("C_RNTI") ? st.kv.at("C_RNTI").get<std::string>() : std::string();
        if (crnti.empty() || crnti == "-") {
            return Reply::fail(Exit::wrong_state, "the UE has no RRC connection at this gNB");
        }
        const std::string path = "/v1/gnb/" + encode(t_.gnb_name) + "/" + route;
        if (method == "GET") {
            return call(*cucp, "GET", path + "?c_rnti=" + encode(crnti));
        }
        body["c_rnti"] = crnti;
        return call(*cucp, method, path, body);
    };
    server.get("/v1/gnb/:name/qos", [with_crnti](const Request& req) { return with_crnti(req, "GET", "qos", json::object()); });
    server.post("/v1/gnb/:name/qos-release", [with_crnti](const Request& req) {
        return with_crnti(req, "POST", "qos-release", json{{"psi", req.arg("psi")}, {"qfi", req.arg("qfi")}});
    });
    server.post("/v1/gnb/:name/ue-release", [this, &ue, cucp](const Request& req) {
        if (req.params.at("name") != t_.gnb_name) {
            return Reply::fail(Exit::unknown, "no such gNB");
        }
        if (cucp == nullptr) {
            return peer_reply("cucp");
        }
        // The UE by its farm selector, found at the CU-CP by its C-RNTI, as in one process.
        Reply st = call(ue, "GET", "/v1/ue/" + encode(req.arg("ue")) + "/status");
        if (st.exit != Exit::ok) {
            return st;
        }
        const std::string crnti = st.kv.contains("C_RNTI") ? st.kv.at("C_RNTI").get<std::string>() : std::string();
        if (crnti.empty() || crnti == "-") {
            return Reply::fail(Exit::wrong_state, "the UE has no RRC connection at this gNB");
        }
        json body = {{"c_rnti", crnti}, {"cause", req.arg("cause", "user-inactivity")},
                     {"ue_label", st.kv.contains("UE") ? st.kv.at("UE").get<std::string>() : std::string()}};
        return call(*cucp, "POST", "/v1/gnb/" + encode(t_.gnb_name) + "/ue-release", body);
    });
    server.post("/v1/gnb/:name/restart", [this](const Request& req) {
        if (req.params.at("name") != t_.gnb_name) {
            return Reply::fail(Exit::unknown, "no such gNB");
        }
        if (restarting_.load()) {
            return Reply::fail(Exit::wrong_state, "the gNB is restarting");
        }
        const std::uint64_t since = events_.last_seq();
        if (restarter_.joinable()) {
            restarter_.join();
        }
        restarter_ = std::thread([this] { restart_gnb(); });
        Reply out;
        out.set("RESULT", "STARTED");
        out.set("EVENT_SEQ", static_cast<std::int64_t>(since));
        return out;
    });
    // P2 Q3: one role's process alone stops and starts again (rows ksim-p2.f1-reassociation and
    // ksim-p2.f1-loss-release): the others see their association go and come back.
    for (const char* role : {"cucp", "du", "cuup"}) {
        const std::string name = t_.gnb_name + (std::string(role) == "cucp" ? "" : std::string("-") + role);
        server.post(std::string("/v1/") + role + "/:name/restart", [this, role, name](const Request& req) {
            if (req.params.at("name") != name) {
                return Reply::fail(Exit::unknown, "no such node");
            }
            if (child(role) == nullptr) {
                return peer_reply(role);
            }
            if (restarting_.load()) {
                return Reply::fail(Exit::wrong_state, "the gNB is restarting");
            }
            const std::uint64_t since = events_.last_seq();
            if (restarter_.joinable()) {
                restarter_.join();
            }
            restarter_ = std::thread([this, role] {
                const std::lock_guard<std::mutex> lock(restart_mu_);
                restarting_ = true;
                Child& c = *child(role);
                stop_child(c);
                std::string why;
                if (!spawn(c, why)) {
                    events_.emit("run.role.exit", "run:" + c.role, {{"role", c.role}, {"status", "restart failed"}});
                }
                restarting_ = false;
            });
            Reply out;
            out.set("RESULT", "STARTED");
            out.set("EVENT_SEQ", static_cast<std::int64_t>(since));
            return out;
        });
    }
    // P2 Q7: every role's metrics, each line labelled with its role; HELP and TYPE once.
    server.stream("/v1/metrics", [this](const Request&, const api::Server::Write& write) {
        std::string out;
        std::set<std::string> said;
        for (const auto& c : children_) {
            httplib::Client cli(api::socket_target(c->ctl));
            cli.set_address_family(AF_UNIX);
            cli.set_read_timeout(std::chrono::seconds(10));
            auto res = cli.Get("/v1/metrics");
            if (!res) {
                continue;
            }
            std::istringstream in(res->body);
            for (std::string line; std::getline(in, line);) {
                if (line.empty()) {
                    continue;
                }
                if (line[0] == '#') {
                    if (said.insert(line).second) {
                        out += line + "\n";
                    }
                    continue;
                }
                const std::string role = "role=\"" + c->role + "\"";
                if (const auto b = line.find('{'); b != std::string::npos) {
                    out += line.substr(0, b + 1) + role + "," + line.substr(b + 1) + "\n";
                } else if (const auto sp = line.find(' '); sp != std::string::npos) {
                    out += line.substr(0, sp) + "{" + role + "}" + line.substr(sp) + "\n";
                }
            }
        }
        (void)write(out);
    });
    server.post("/v1/stop", [&stop](const Request&) {
        stop.store(true);
        Reply r;
        r.set("STOPPING", "1");
        return r;
    });
}

} // namespace

int supervise(const node::Topology& t, const std::string& topology_file, const std::string& run_dir, const RoleArgs& a,
              const volatile std::sig_atomic_t& signal) {
    Supervisor s(t, topology_file, run_dir, a);
    std::string why;
    json m = {{"run", std::filesystem::path(run_dir).filename().string()}, {"mode", "split"}, {"status", "starting"}};
    if (!s.start(why)) {
        std::cerr << "ksim: " << why << "\n";
        m["status"] = "failed";
        m["error"] = why;
        (void)node::write_file(run_dir + "/manifest.json", m.dump(2) + "\n");
        return 1;
    }
    std::atomic<bool> stop{false};
    api::Server server;
    s.bind(server, stop);
    const std::string ctl = run_dir + "/ctl.sock";
    if (auto r = server.listen_unix(ctl); !r) {
        std::cerr << "ksim: " << ctl << ": " << r.error().what << "\n";
        return 1;
    }
    m["status"] = "running";
    m["roles"] = json::parse(s.manifest_roles());
    (void)node::write_file(run_dir + "/manifest.json", m.dump(2) + "\n");
    std::cout << "RUN_DIR=" << run_dir << "\nCTL=" << ctl << "\n" << std::flush;
    while (signal == 0 && !stop.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    server.stop();
    s.shutdown();
    m["status"] = "stopped";
    (void)node::write_file(run_dir + "/manifest.json", m.dump(2) + "\n");
    return 0;
}

} // namespace ksim::app
