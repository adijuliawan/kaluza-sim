// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// ksim-ctl v0 (P1 N8; cli.md): the run's control API from a shell.
//
//   ksim-ctl [--run D | --socket S] [--json | --format kv|json|nrcli] [--timeout DUR]
//            [--parallel N] [--stagger DUR] <command>
//   ksim-ctl [options] <imsi-… | gNB name> --exec '<command>'   (nr-cli's form, N16)
//     nodes | info | version | capabilities | faults list | ues | stop
//     ue <sel> status
//     ue <sel> power on|off [--switch-off] [--wait DUR]
//     ue <sel> register [--wait DUR]
//     ue <sel> deregister normal|switch-off [--wait DUR]
//     ue <sel> ps-list
//     ue <sel> ps-establish ipv4 [--dnn D] [--sst S [--sd SD]] [--psi N] [--wait DUR]
//     ue <sel> ps-release <psi>|--all [--wait DUR]
//     ue <sel> ping <IPv4> [--psi N] [-c N] [--interval MS] [--size N] [--df]
//     ue <sel> ifaces
//     ue <sel> exec [--] <command> [args…]     (inside the UE's namespace; the command's words verbatim)
//     ue <sel> wait <event>[,<event>…] [--fail <event>,…] [--where k=v]… [--since N | --new] [--timeout DUR]
//     ue <sel> events [--since N] [--follow] [--filter PREFIX]
//     wait <event> … (any subject)      events …      metrics (P2 Q7: Prometheus text)
//     gnb <name> ue-list | amf-list | ue-release <ue sel> [--cause C] | restart
//     ue <sel> service-request [--wait DUR] | sim remove|insert | airplane on|off
//     ue <sel> sms-send <digits> <text> [--ucs2] [--srr] [--vp N] | sms-list | sms-memory full|available
//     ue <sel> register --update
//     ue <sel> sim info | sim read <EF> | sim trace on|off
//     netd list | setup-node <ns> [--parent P --addr A/N] | veth <ns> <A/N> | teardown <ns>
//          | exec <ns> --log FILE -- <argv…>      (P2 Q7: ksim-netd for scripts, --netd PATH or
//          $KSIM_NETD, default /run/ksim/netd.sock; exec prints PID= and does not wait)
//     stub [release --ue SUPI --psi N [--cause C] | ping-ue --ue SUPI --psi N [--seq N]
//           | deregister --ue SUPI [--rereg] | restart | t3512 --seconds N | sms-sub --ue SUPI [--off]]
//           (--socket <stub ctl>)
//
// <sel> is imsi-…, a farm index, a range of them (P2 Q7: 1-100), group:<name> or
// all; several UEs print one block each, in farm order, separated by a blank line.
// --parallel N (P2 Q7) runs a command for N of them at a time, --stagger DUR
// starts one every DUR. debug stall <ms> (P2 Q7) blocks the run's loop that long
// (the DU's in a split run): the watchdog's test. Output is KEY=value lines (--json: one
// object per UE); the exit code is cli.md §2's. The run is --run, else
// $KSIM_RUN, else $KSIM_RUNS/latest (runs/latest).

#include <ksim/build_info.hpp>

#include <CLI/CLI.hpp>

#include <fcntl.h>
#include <unistd.h>

#include <array>
#include <cstdio>
#include <exception>
#include <httplib.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "api/http.hpp"
#include "api/reply.hpp"
#include "net/netd.hpp"

namespace {

using ksim::api::Exit;
using ksim::api::json;
using ksim::api::Reply;

struct Ctx {
    std::string socket;
    bool json = false;
    bool nrcli = false;   // --format=nrcli: "key: value" lines as nr-cli prints them (N16)
    long timeout_ms = 30'000;
    unsigned parallel = 1;   // P2 Q7: UEs worked on at a time
    long stagger_ms = 0;     // P2 Q7: between two UEs' starts
};

std::optional<long> duration_ms(const std::string& s) {
    std::size_t n = 0;
    while (n < s.size() && s[n] >= '0' && s[n] <= '9') {
        ++n;
    }
    if (n == 0 || n > 9) {
        return std::nullopt;
    }
    const long v = std::stol(s.substr(0, n));
    const std::string unit = s.substr(n);
    if (unit == "ms") {
        return v;
    }
    if (unit.empty() || unit == "s") {
        return v * 1000;
    }
    if (unit == "m") {
        return v * 60'000;
    }
    return std::nullopt;
}

std::string encode(const std::string& v) {
    std::string out;
    for (const char ch : v) {
        const auto c = static_cast<unsigned char>(ch);
        if (std::isalnum(c) != 0 || c == '-' || c == '_' || c == '.' || c == '~' || c == ',') {
            out += static_cast<char>(c);
        } else {
            static const char* hex = "0123456789ABCDEF";
            out += '%';
            out += hex[c >> 4];
            out += hex[c & 0xF];
        }
    }
    return out;
}

Reply call(const Ctx& c, const std::string& method, const std::string& path, const json& body = json(),
           long extra_ms = 0) {
    httplib::Client cli(ksim::api::socket_target(c.socket));
    cli.set_address_family(AF_UNIX);
    const long total = c.timeout_ms + extra_ms + 5'000;
    cli.set_read_timeout(std::chrono::milliseconds(total));
    cli.set_connection_timeout(std::chrono::seconds(5));
    auto res = method == "GET" ? cli.Get(path) : cli.Post(path, body.is_null() ? "{}" : body.dump(), "application/json");
    if (!res) {
        if (res.error() == httplib::Error::Read) {
            return Reply::fail(Exit::timeout, "the node did not answer in time");
        }
        return Reply::fail(Exit::unknown, "no run answers at " + c.socket);
    }
    auto r = Reply::parse(res->body);
    if (!r) {
        return Reply::fail(Exit::internal, "the node's answer is not a control API reply");
    }
    return *r;
}

void print(const Ctx& c, const Reply& r) {
    if (c.json) {
        std::cout << r.kv.dump() << "\n";
    } else if (c.nrcli) {
        // nr-cli's shape: YAML-like "key: value", keys in lower case with dashes.
        std::istringstream in(ksim::api::kv_lines(r.kv));
        for (std::string line; std::getline(in, line);) {
            const auto eq = line.find('=');
            if (eq == std::string::npos) {
                std::cout << line << "\n";
                continue;
            }
            std::string k = line.substr(0, eq);
            std::transform(k.begin(), k.end(), k.begin(), [](unsigned char ch) {
                return ch == '_' || ch == '.' ? '-' : static_cast<char>(std::tolower(ch));
            });
            std::cout << k << ": " << line.substr(eq + 1) << "\n";
        }
    } else {
        std::cout << ksim::api::kv_lines(r.kv);
    }
}

/// nr-cli's form, `<node> --exec '<command>'` (cli.md §5): an imsi-… node is a
/// UE, any other a gNB; the command's words follow. nr-cli writes IPv4 where
/// ksim-ctl takes ipv4.
std::vector<std::string> from_exec(const std::string& node, const std::string& command) {
    std::vector<std::string> out{node.rfind("imsi-", 0) == 0 ? "ue" : "gnb", node};
    std::istringstream in(command);
    for (std::string w; in >> w;) {
        if (out.size() >= 3 && out.back() == "ps-establish") {
            std::transform(w.begin(), w.end(), w.begin(), [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        }
        out.push_back(w);
    }
    return out;
}

/// Flags after the command words: --name value, --name=value, or a bare --flag.
struct Flags {
    std::vector<std::string> words;
    std::multimap<std::string, std::string> opts;
    bool has(const std::string& k) const { return opts.count(k) != 0; }
    std::string get(const std::string& k, const std::string& fallback = {}) const {
        auto it = opts.find(k);
        return it == opts.end() ? fallback : it->second;
    }
};

Flags parse_flags(const std::vector<std::string>& args, std::size_t from) {
    static const std::vector<std::string> valued{"wait", "timeout", "where", "since", "fail", "filter", "cause",
                                                 "dnn", "sst", "sd", "psi", "count", "interval", "size", "type", "ue",
                                                 "seq", "seconds", "vp", "log", "netd", "parent", "addr"};
    Flags f;
    for (std::size_t i = from; i < args.size(); ++i) {
        const std::string& a = args[i];
        if (a == "-c" && i + 1 < args.size()) {   // ping's count, as ping(8) spells it
            f.opts.emplace("count", args[++i]);
            continue;
        }
        if (a.rfind("--", 0) != 0) {
            f.words.push_back(a);
            continue;
        }
        std::string k = a.substr(2);
        if (const auto eq = k.find('='); eq != std::string::npos) {
            f.opts.emplace(k.substr(0, eq), k.substr(eq + 1));
            continue;
        }
        if (std::find(valued.begin(), valued.end(), k) != valued.end() && i + 1 < args.size()) {
            f.opts.emplace(k, args[++i]);
        } else {
            f.opts.emplace(k, "1");
        }
    }
    return f;
}

/// The UEs a selector names: one for imsi-… or an index, several for all and group:<name>.
std::optional<std::vector<std::string>> resolve(const Ctx& c, const std::string& sel, Reply& err) {
    // P2 Q7: a range of farm indices, "1-100".
    if (const auto dash = sel.find('-'); dash != std::string::npos && sel.rfind("imsi-", 0) != 0 &&
                                         sel.find_first_not_of("0123456789-") == std::string::npos) {
        unsigned long lo = 0;
        unsigned long hi = 0;
        try {
            lo = std::stoul(sel.substr(0, dash));
            hi = std::stoul(sel.substr(dash + 1));
        } catch (const std::exception&) {
            lo = 0;
        }
        if (lo == 0 || hi < lo || hi - lo >= 4096) {
            err = Reply::fail(Exit::usage, "a range is first-last farm indices, 1 or more, at most 4096 of them");
            return std::nullopt;
        }
        std::vector<std::string> out;
        for (unsigned long i = lo; i <= hi; ++i) {
            out.push_back(std::to_string(i));
        }
        return out;
    }
    if (sel != "all" && sel.rfind("group:", 0) != 0) {
        return std::vector<std::string>{sel};
    }
    Reply ues = call(c, "GET", "/v1/ues");
    if (ues.exit != Exit::ok) {
        err = ues;
        return std::nullopt;
    }
    std::vector<std::string> out;
    const std::string group = sel == "all" ? "" : sel.substr(6);
    for (const auto& [k, v] : ues.kv.items()) {
        if (k.rfind("UE.", 0) != 0 || k.find(".GROUP") != std::string::npos) {
            continue;
        }
        const std::string g = ues.kv.value(k + ".GROUP", std::string());
        if (group.empty() || g == group) {
            out.push_back(v.get<std::string>());
        }
    }
    if (out.empty()) {
        err = Reply::fail(Exit::unknown, "no UE in " + sel);
        return std::nullopt;
    }
    return out;
}

Reply wait_query(const Ctx& c, const Flags& f, const std::string& events, const std::string& ue_or_empty) {
    std::string q = "/v1/wait?event=" + encode(events);
    if (f.has("fail")) {
        q += "&fail=" + encode(f.get("fail"));
    }
    if (!ue_or_empty.empty()) {
        q += "&ue=" + encode(ue_or_empty);
    }
    for (auto [it, end] = f.opts.equal_range("where"); it != end; ++it) {
        q += "&where=" + encode(it->second);
    }
    if (f.has("new")) {
        q += "&new=1";
    } else if (f.has("since")) {
        q += "&since=" + encode(f.get("since"));
    }
    long t = c.timeout_ms;
    if (f.has("timeout")) {
        auto d = duration_ms(f.get("timeout"));
        if (!d) {
            return Reply::fail(Exit::usage, "--timeout takes a duration (30s, 500ms, 2m)");
        }
        t = *d;
    }
    q += "&timeout_ms=" + std::to_string(t);
    return call(c, "GET", q, json(), t);
}

/// "172.30.30.36/24" into its address and length.
bool v4_net(const std::string& s, std::array<std::uint8_t, 4>& a, std::uint8_t& len) {
    const auto slash = s.find('/');
    if (slash == std::string::npos) {
        return false;
    }
    unsigned o[4] = {};
    char tail = 0;
    if (std::sscanf(s.substr(0, slash).c_str(), "%u.%u.%u.%u%c", &o[0], &o[1], &o[2], &o[3], &tail) != 4) {
        return false;
    }
    for (int i = 0; i < 4; ++i) {
        if (o[i] > 255) {
            return false;
        }
        a[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(o[i]);
    }
    const int n = std::atoi(s.substr(slash + 1).c_str());
    if (n < 1 || n > 32) {
        return false;
    }
    len = static_cast<std::uint8_t>(n);
    return true;
}

/// P2 Q7: ksim-netd for scripts (an interop peer's namespaces on kaluza-uesim, ADR 0012).
int netd_command(const Flags& f) {
    namespace nd = ksim::net::netd;
    const char* env = std::getenv("KSIM_NETD");
    const std::string sock = f.get("netd", env != nullptr ? env : nd::kSocketPath);
    auto c = nd::Client::connect(sock);
    if (!c) {
        std::cerr << "CAUSE=no ksim-netd answers at " << sock << "\n";
        return static_cast<int>(Exit::abort);
    }
    const auto& w = f.words;
    const auto done = [&](bool ok) {
        if (!ok) {
            std::cerr << "CAUSE=" << c->last_error() << "\n";
            return static_cast<int>(Exit::failed);
        }
        std::cout << "NETD=OK\n";
        return 0;
    };
    if (!w.empty() && w[0] == "list") {
        auto l = c->list();
        if (!l) {
            return done(false);
        }
        std::cout << "NAMESPACES=" << l->size() << "\n";
        for (std::size_t i = 0; i < l->size(); ++i) {
            std::cout << "NS." << (i + 1) << "=" << (*l)[i] << "\n";
        }
        return 0;
    }
    if (w.size() == 2 && w[0] == "setup-node") {
        std::array<std::uint8_t, 4> a{};
        std::uint8_t len = 0;
        if (f.has("parent") && !v4_net(f.get("addr"), a, len)) {
            std::cerr << "CAUSE=--parent needs --addr A/N\n";
            return static_cast<int>(Exit::usage);
        }
        return done(static_cast<bool>(c->setup_node(w[1], f.get("parent"), a, len)));
    }
    if (w.size() == 3 && w[0] == "veth") {
        std::array<std::uint8_t, 4> a{};
        std::uint8_t len = 0;
        if (!v4_net(w[2], a, len)) {
            std::cerr << "CAUSE=veth <ns> A/N\n";
            return static_cast<int>(Exit::usage);
        }
        return done(static_cast<bool>(c->veth(w[1], a, len)));
    }
    if (w.size() == 2 && w[0] == "teardown") {
        return done(static_cast<bool>(c->teardown(w[1])));
    }
    if (w.size() >= 3 && w[0] == "exec") {
        // The command's output goes to --log; netd's helper waits for it, we do not.
        const std::string log = f.get("log", "/dev/null");
        const int in = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
        const int out = ::open(log.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
        int st[2] = {-1, -1};
        if (in < 0 || out < 0 || ::pipe2(st, O_CLOEXEC) != 0) {
            std::cerr << "CAUSE=cannot open " << log << "\n";
            return static_cast<int>(Exit::failed);
        }
        std::vector<std::string> argv(w.begin() + 2, w.end());
        auto pid = c->exec(w[1], argv, {in, out, out, st[1]});
        ::close(in);
        ::close(out);
        ::close(st[1]);
        ::close(st[0]);   // the status goes unread: the peer runs on
        if (!pid) {
            std::cerr << "CAUSE=" << c->last_error() << "\n";
            return static_cast<int>(Exit::failed);
        }
        std::cout << "PID=" << *pid << "\n";
        return 0;
    }
    std::cerr << "CAUSE=netd list | setup-node <ns> [--parent P --addr A/N] | veth <ns> <A/N> | teardown <ns> | "
                 "exec <ns> --log FILE -- <argv…>\n";
    return static_cast<int>(Exit::usage);
}

/// P2 Q7: /v1/metrics as the run gives it (the Prometheus text format).
int metrics(const Ctx& c) {
    httplib::Client cli(ksim::api::socket_target(c.socket));
    cli.set_address_family(AF_UNIX);
    cli.set_read_timeout(std::chrono::milliseconds(c.timeout_ms));
    auto res = cli.Get("/v1/metrics");
    if (!res) {
        std::cerr << "CAUSE=no run answers at " << c.socket << "\n";
        return static_cast<int>(Exit::unknown);
    }
    std::cout << res->body;
    return 0;
}

int events(const Ctx& c, const Flags& f, const std::string& subject) {
    httplib::Client cli(ksim::api::socket_target(c.socket));
    cli.set_address_family(AF_UNIX);
    cli.set_read_timeout(std::chrono::hours(24));
    std::string q = "/v1/events?since=" + encode(f.get("since", "0"));
    if (f.has("follow")) {
        q += "&follow=1";
    }
    if (f.has("filter")) {
        q += "&filter=" + encode(f.get("filter"));
    }
    if (!subject.empty()) {
        q += "&subject=" + encode(subject);
    }
    auto res = cli.Get(q, [](const char* data, std::size_t n) {
        std::cout.write(data, static_cast<std::streamsize>(n));
        std::cout.flush();
        return true;
    });
    if (!res) {
        std::cerr << "CAUSE=no run answers at " << c.socket << "\n";
        return static_cast<int>(Exit::unknown);
    }
    return 0;
}

std::optional<long> wait_flag(const Flags& f, Reply& err) {
    if (!f.has("wait")) {
        return 0;
    }
    const std::string v = f.get("wait");
    auto d = duration_ms(v == "1" ? "30s" : v);
    if (!d) {
        err = Reply::fail(Exit::usage, "--wait takes a duration (30s, 500ms, 2m)");
        return std::nullopt;
    }
    return d;
}

Reply ue_command(const Ctx& c, const std::string& ue, const Flags& f) {
    if (f.words.empty()) {
        return Reply::fail(Exit::usage, "ue <sel> <command>");
    }
    const std::string& cmd = f.words[0];
    const std::string base = "/v1/ue/" + encode(ue);
    Reply err;
    if (cmd == "status") {
        return call(c, "GET", base + "/status");
    }
    if (cmd == "power" || cmd == "register" || cmd == "deregister") {
        auto w = wait_flag(f, err);
        if (!w) {
            return err;
        }
        json body = json::object();
        body["wait_ms"] = std::to_string(*w);
        std::string path;
        if (cmd == "power") {
            if (f.words.size() < 2 || (f.words[1] != "on" && f.words[1] != "off")) {
                return Reply::fail(Exit::usage, "power on|off");
            }
            body["state"] = f.words[1];
            for (const char* m : {"switch-off", "graceful", "abrupt"}) {
                if (f.has(m)) {
                    body["mode"] = m;
                }
            }
            path = base + "/power";
        } else if (cmd == "register") {
            body["type"] = f.has("update") ? "update" : f.get("type", "initial");
            path = base + "/register";
        } else {
            body["type"] = f.words.size() > 1 ? f.words[1] : "normal";
            path = base + "/deregister";
        }
        return call(c, "POST", path, body, *w);
    }
    if (cmd == "wait") {
        if (f.words.size() < 2) {
            return Reply::fail(Exit::usage, "wait <event>");
        }
        return wait_query(c, f, f.words[1], ue);
    }
    if (cmd == "ps-list") {
        return call(c, "GET", base + "/ps");
    }
    if (cmd == "service-request") {
        auto w = wait_flag(f, err);
        if (!w) {
            return err;
        }
        json body = json::object();
        body["wait_ms"] = std::to_string(*w);
        return call(c, "POST", base + "/service-request", body, *w);
    }
    if (cmd == "ifaces") {
        return call(c, "GET", base + "/ifaces");
    }
    if (cmd == "sms-send") {
        if (f.words.size() < 3) {
            return Reply::fail(Exit::usage, "sms-send <digits> <text> [--ucs2] [--srr] [--vp N] [--wait DUR]");
        }
        auto w = wait_flag(f, err);
        if (!w) {
            return err;
        }
        json body = json::object();
        body["to"] = f.words[1];
        std::string text = f.words[2];
        for (std::size_t i = 3; i < f.words.size(); ++i) {
            text += " " + f.words[i];   // the rest of the line is the text
        }
        body["text"] = text;
        body["ucs2"] = f.has("ucs2") ? "1" : "0";
        body["srr"] = f.has("srr") ? "1" : "0";
        if (f.has("vp")) {
            body["vp"] = f.get("vp");
        }
        body["wait_ms"] = std::to_string(*w);
        return call(c, "POST", base + "/sms-send", body, *w);
    }
    if (cmd == "sms-list") {
        return call(c, "GET", base + "/sms");
    }
    if (cmd == "sms-memory" && f.words.size() >= 2 && (f.words[1] == "full" || f.words[1] == "available")) {
        json body = json::object();
        body["state"] = f.words[1];
        return call(c, "POST", base + "/sms-memory", body);
    }
    if (cmd == "sim" && f.words.size() >= 2 && f.words[1] == "info") {
        return call(c, "GET", base + "/sim");
    }
    if (cmd == "sim" && f.words.size() >= 3 && f.words[1] == "read") {
        return call(c, "GET", base + "/sim-read?ef=" + encode(f.words[2]));
    }
    if (cmd == "sim" && f.words.size() >= 3 && f.words[1] == "trace" && (f.words[2] == "on" || f.words[2] == "off")) {
        json body = json::object();
        body["state"] = f.words[2];
        return call(c, "POST", base + "/sim-trace", body);
    }
    if (cmd == "sim" && f.words.size() >= 2 && (f.words[1] == "remove" || f.words[1] == "insert")) {
        json body = json::object();
        body["action"] = f.words[1];
        return call(c, "POST", base + "/sim", body);
    }
    if (cmd == "airplane" && f.words.size() >= 2 && (f.words[1] == "on" || f.words[1] == "off")) {
        json body = json::object();
        body["state"] = f.words[1];
        return call(c, "POST", base + "/airplane", body);
    }
    if (cmd == "ps-establish") {
        auto w = wait_flag(f, err);
        if (!w) {
            return err;
        }
        json body = json::object();
        body["wait_ms"] = std::to_string(*w);
        body["type"] = f.words.size() > 1 ? f.words[1] : "ipv4";
        for (const char* k : {"dnn", "sst", "sd", "psi"}) {
            if (f.has(k)) {
                body[k] = f.get(k);
            }
        }
        return call(c, "POST", base + "/ps-establish", body, *w);
    }
    if (cmd == "ps-release") {
        auto w = wait_flag(f, err);
        if (!w) {
            return err;
        }
        std::vector<std::string> psis;
        if (f.has("all")) {
            Reply list = call(c, "GET", base + "/ps");
            if (list.exit != Exit::ok) {
                return list;
            }
            for (const auto& [k, v] : list.kv.items()) {
                if (k.rfind("PS.", 0) == 0 && k.size() > 6 && k.compare(k.size() - 6, 6, ".STATE") == 0) {
                    psis.push_back(k.substr(3, k.size() - 9));
                }
            }
            if (psis.empty()) {
                Reply r;
                r.set("RELEASED", "0");
                return r;
            }
        } else if (f.words.size() > 1) {
            psis.push_back(f.words[1]);
        } else {
            return Reply::fail(Exit::usage, "ps-release <psi>|--all");
        }
        Reply last;
        for (const auto& psi : psis) {
            json body = json::object();
            body["wait_ms"] = std::to_string(*w);
            body["psi"] = psi;
            last = call(c, "POST", base + "/ps-release", body, *w);
            if (last.exit != Exit::ok) {
                return last;
            }
        }
        return last;
    }
    if (cmd == "ping") {
        if (f.words.size() < 2) {
            return Reply::fail(Exit::usage, "ping <IPv4> [--psi N] [-c N]");
        }
        json body = json::object();
        body["dst"] = f.words[1];
        const long count = std::strtol(f.get("count", "3").c_str(), nullptr, 10);
        const long interval = std::strtol(f.get("interval", "1000").c_str(), nullptr, 10);
        body["count"] = std::to_string(count);
        body["interval_ms"] = std::to_string(interval);
        for (const char* k : {"psi", "size", "df"}) {
            if (f.has(k)) {
                body[k] = f.get(k);
            }
        }
        // The run waits for the last reply: the requests, then two seconds' linger and some slack.
        const long w = std::max(1L, count) * std::max(10L, interval) + 5'000;
        body["wait_ms"] = std::to_string(w);
        return call(c, "POST", base + "/ping", body, w);
    }
    return Reply::fail(Exit::capability, "ue " + cmd + " is not in ksim-ctl v0");
}

/// ue <sel> exec [--] <words…>: the words go as they are; the command's output
/// is printed raw (stdout, stderr), then EXIT_CODE and TIMED_OUT.
int exec_command(const Ctx& c, const std::string& ue, std::vector<std::string> words) {
    if (!words.empty() && words.front() == "--") {
        words.erase(words.begin());
    }
    if (words.empty()) {
        Reply r = Reply::fail(Exit::usage, "exec <command> [args…]");
        print(c, r);
        return static_cast<int>(r.exit);
    }
    json body = json::object();
    body["argv"] = words;
    const long budget = std::max(1000L, c.timeout_ms - 1000);
    body["timeout_ms"] = std::to_string(budget);
    Reply r = call(c, "POST", "/v1/ue/" + encode(ue) + "/exec", body, 2000);
    if (c.json) {
        print(c, r);
        return static_cast<int>(r.exit);
    }
    std::cout << r.kv.value("STDOUT", std::string());
    std::cerr << r.kv.value("STDERR", std::string());
    r.kv.erase("STDOUT");
    r.kv.erase("STDERR");
    print(c, r);
    return static_cast<int>(r.exit);
}

int run(const Ctx& c, const std::vector<std::string>& in_args) {
    if (in_args.empty()) {
        std::cerr << "usage: ksim-ctl [--run D] [--json] <command> (see cli.md)\n";
        return static_cast<int>(Exit::usage);
    }
    std::vector<std::string> args = in_args;
    if (args.size() == 3 && args[1] == "--exec") {
        args = from_exec(args[0], args[2]);
    } else if (args.size() == 2 && args[1].rfind("--exec=", 0) == 0) {
        args = from_exec(args[0], args[1].substr(7));
    }
    if (args.size() >= 3 && args[0] == "ue" && args[2] == "exec") {
        return exec_command(c, args[1], std::vector<std::string>(args.begin() + 3, args.end()));
    }
    if (args.size() >= 3 && args[0] == "netd" && args[1] == "exec") {
        // P2 Q7: netd exec <ns> [--log F] -- <argv…>: the words after -- go as they are.
        const auto dash = std::find(args.begin(), args.end(), std::string("--"));
        Flags f = parse_flags(std::vector<std::string>(args.begin(), dash), 1);
        if (dash != args.end()) {
            f.words.insert(f.words.end(), dash + 1, args.end());
        }
        return netd_command(f);
    }
    const std::string& verb = args[0];
    const Flags f = parse_flags(args, 1);
    Reply r;
    if (verb == "nodes" || verb == "info" || verb == "version" || verb == "capabilities" || verb == "ues") {
        r = call(c, "GET", "/v1/" + verb);
    } else if (verb == "faults") {
        r = call(c, "GET", "/v1/faults");
    } else if (verb == "stub") {
        // ksim-corestub (--socket): its report, or a network-side trigger for the gates.
        if (!f.words.empty() && (f.words[0] == "release" || f.words[0] == "ping-ue" || f.words[0] == "deregister" ||
                                 f.words[0] == "restart" || f.words[0] == "t3512" || f.words[0] == "sms-sub")) {
            json body = json::object();
            for (const char* k : {"ue", "psi", "cause", "seq", "seconds"}) {
                if (f.has(k)) {
                    body[k] = f.get(k);
                }
            }
            if (f.has("rereg")) {
                body["rereg"] = "1";
            }
            if (f.words[0] == "sms-sub") {
                body["on"] = f.has("off") ? "0" : "1";
            }
            r = call(c, "POST", "/v1/stub/" + f.words[0], body);
        } else {
            r = call(c, "GET", "/v1/stub");
        }
    } else if (verb == "stop") {
        r = call(c, "POST", "/v1/stop");
    } else if (verb == "wait") {
        if (f.words.empty()) {
            r = Reply::fail(Exit::usage, "wait <event>");
        } else {
            r = wait_query(c, f, f.words[0], "");
        }
    } else if (verb == "events") {
        return events(c, f, "");
    } else if (verb == "metrics") {
        return metrics(c);
    } else if (verb == "netd") {
        return netd_command(f);
    } else if (verb == "gnb" || verb == "cucp") {
        if (f.words.size() >= 2 && (f.words[1] == "ue-list" || f.words[1] == "amf-list")) {
            r = call(c, "GET", "/v1/gnb/" + encode(f.words[0]) + "/" + f.words[1]);
        } else if (f.words.size() >= 3 && f.words[1] == "ue-release") {
            json body = json::object();
            body["ue"] = f.words[2];
            if (f.has("cause")) {
                body["cause"] = f.get("cause");
            }
            r = call(c, "POST", "/v1/gnb/" + encode(f.words[0]) + "/ue-release", body);
        } else if (f.words.size() >= 2 && f.words[1] == "restart") {
            // gnb: the whole gNB; cucp: the CU-CP's process alone (a split run, P2 Q3)
            r = call(c, "POST", std::string(verb == "cucp" ? "/v1/cucp/" : "/v1/gnb/") + encode(f.words[0]) + "/restart");
        } else {
            r = Reply::fail(Exit::usage, "gnb|cucp <name> ue-list|amf-list|ue-release <ue>|restart");
        }
    } else if (verb == "du") {
        // P2 Q3 (cli.md): the DU's own verbs; restart is a split run's DU process alone.
        if (f.words.size() >= 2 && f.words[1] == "ue-list") {
            r = call(c, "GET", "/v1/du/" + encode(f.words[0]) + "/ue-list");
        } else if (f.words.size() >= 2 && f.words[1] == "restart") {
            r = call(c, "POST", "/v1/du/" + encode(f.words[0]) + "/restart");
        } else {
            r = Reply::fail(Exit::usage, "du <name> ue-list|restart");
        }
    } else if (verb == "debug") {
        // P2 Q7: the watchdog's test (row ksim-p2.loop-lag-abort).
        if (f.words.size() >= 2 && f.words[0] == "stall") {
            json body = json::object();
            body["ms"] = f.words[1];
            r = call(c, "POST", "/v1/debug/stall", body);
        } else {
            r = Reply::fail(Exit::usage, "debug stall <ms>");
        }
    } else if (verb == "cuup") {
        if (f.words.size() >= 2 && f.words[1] == "bearers") {
            r = call(c, "GET", "/v1/cuup/" + encode(f.words[0]) + "/bearers");
        } else if (f.words.size() >= 2 && f.words[1] == "restart") {
            r = call(c, "POST", "/v1/cuup/" + encode(f.words[0]) + "/restart");
        } else {
            r = Reply::fail(Exit::usage, "cuup <name> bearers|restart");
        }
    } else if (verb == "ue") {
        if (f.words.empty()) {
            r = Reply::fail(Exit::usage, "ue <sel> <command>");
        } else {
            const std::string sel = f.words[0];
            Flags rest = f;
            rest.words.erase(rest.words.begin());
            if (!rest.words.empty() && rest.words[0] == "events") {
                if (sel.rfind("imsi-", 0) != 0) {
                    r = Reply::fail(Exit::usage, "ue events takes imsi-…");
                } else {
                    return events(c, rest, "ue:" + sel);
                }
            } else {
                Reply err;
                auto ues = resolve(c, sel, err);
                if (!ues) {
                    r = err;
                } else {
                    // P2 Q7: --parallel N workers, each UE started --stagger after the one before;
                    // the answers print in farm order once all are in.
                    std::vector<Reply> answers(ues->size());
                    const std::size_t workers = std::min<std::size_t>(std::max(1U, c.parallel), ues->size());
                    std::atomic<std::size_t> next{0};
                    const auto t0 = std::chrono::steady_clock::now();
                    auto work = [&] {
                        for (std::size_t i = next++; i < ues->size(); i = next++) {
                            if (c.stagger_ms > 0) {
                                std::this_thread::sleep_until(t0 + std::chrono::milliseconds(c.stagger_ms * static_cast<long>(i)));
                            }
                            answers[i] = ue_command(c, (*ues)[i], rest);
                        }
                    };
                    if (workers == 1) {
                        work();
                    } else {
                        std::vector<std::thread> pool;
                        pool.reserve(workers);
                        for (std::size_t w = 0; w < workers; ++w) {
                            pool.emplace_back(work);
                        }
                        for (auto& t : pool) {
                            t.join();
                        }
                    }
                    int worst = 0;
                    for (std::size_t i = 0; i < answers.size(); ++i) {
                        if (i > 0 && !c.json) {
                            std::cout << "\n";
                        }
                        print(c, answers[i]);
                        worst = std::max(worst, static_cast<int>(answers[i].exit));
                    }
                    return worst;
                }
            }
        }
    } else {
        r = Reply::fail(Exit::usage, "unknown command " + verb);
    }
    print(c, r);
    return static_cast<int>(r.exit);
}

} // namespace

static int run_main(int argc, char** argv) {
    CLI::App app{"ksim-ctl: the kaluza-sim control CLI (cli.md)"};
    app.set_version_flag("--version", std::string("ksim-ctl ") + ksim::build::kVersion + " " + ksim::build::kGitDescribe);
    app.prefix_command();
    std::string run_dir;
    std::string socket;
    std::string timeout = "30s";
    Ctx c;
    app.add_option("--run", run_dir, "the run directory");
    app.add_option("--socket", socket, "the control socket (instead of --run)");
    app.add_flag("--json", c.json, "print JSON");
    std::string format = "kv";
    app.add_option("--format", format, "kv, json or nrcli")->check(CLI::IsMember({"kv", "json", "nrcli"}));
    app.add_option("--timeout", timeout, "how long to wait for an answer (30s, 500ms, 2m)");
    std::string stagger;
    app.add_option("--parallel", c.parallel, "UEs worked on at a time (a UE range, group: or all)")->check(CLI::Range(1, 64));
    app.add_option("--stagger", stagger, "between two UEs' starts (100ms)");
    CLI11_PARSE(app, argc, argv);
    if (!stagger.empty()) {
        if (auto s = duration_ms(stagger)) {
            c.stagger_ms = *s;
        } else {
            std::cerr << "CAUSE=--stagger takes a duration\n";
            return static_cast<int>(Exit::usage);
        }
    }
    c.json = c.json || format == "json";
    c.nrcli = format == "nrcli";
    if (auto t = duration_ms(timeout)) {
        c.timeout_ms = *t;
    } else {
        std::cerr << "CAUSE=--timeout takes a duration\n";
        return static_cast<int>(Exit::usage);
    }
    if (!socket.empty()) {
        c.socket = socket;
    } else {
        if (run_dir.empty()) {
            const char* env = std::getenv("KSIM_RUN");   // NOLINT(concurrency-mt-unsafe): read at start-up only
            const char* base = std::getenv("KSIM_RUNS");  // NOLINT(concurrency-mt-unsafe)
            run_dir = env != nullptr && *env != '\0' ? env
                                                     : std::string(base != nullptr && *base != '\0' ? base : "runs") + "/latest";
        }
        c.socket = run_dir + "/ctl.sock";
    }
    return run(c, app.remaining());
}

int main(int argc, char** argv) {
    // An exception that reaches here is a bug: exit 10 (cli.md's internal error).
    try {
        return run_main(argc, argv);
    } catch (const std::exception& e) {
        std::fputs("ksim-ctl: internal error: ", stderr);
        std::fputs(e.what(), stderr);
        std::fputs("\n", stderr);
    } catch (...) {
        std::fputs("ksim-ctl: internal error\n", stderr);
    }
    return 10;
}
