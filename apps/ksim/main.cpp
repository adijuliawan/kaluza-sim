// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// ksim: the all-in-one simulator (P1 N8; architecture §2.1, verification.md §6).
//
//   ksim run -c <topology.yaml> [--run-dir D] [--lab] [--tcp PORT] [--role cucp|cuup|du|ue --kair S]
//   ksim-cucp|ksim-cuup|ksim-du|ksim-ue run -c <topology.yaml> …   (the role fixed, P2 Q3)
//   ksim stop [--run-dir D]
//   ksim --version
//
// `run` checks the dev-PC guard, creates the run directory (manifest.json,
// events.ndjson, ksim.log, the captures, ctl.sock), starts the gNB and the UE
// farm, prints RUN_DIR= and CTL= and serves the control API until SIGINT,
// SIGTERM or `ksim stop`. The UEs stay off until `ksim-ctl ue <sel> power on`.
//
// P2 Q3 (ADR 0011): a topology of mode: split makes `ksim run` the supervisor
// (supervisor.hpp): it starts each role as this program with --role, in
// <run>/<role>/, and serves the control API for all of them. With --role a
// process runs that role alone; --kair is the DU's KAIR socket.

#include <ksim/build_info.hpp>

#include <sys/stat.h>
#include <unistd.h>

#include <CLI/CLI.hpp>
#include <httplib.h>

#include <atomic>
#include <chrono>
#include <array>
#include <csignal>
#include <cstdio>
#include <exception>
#include <ctime>
#include <filesystem>
#include <iostream>
#include <thread>

#include "api/http.hpp"
#include "api/reply.hpp"
#include "node/aio/aio.hpp"
#include "node/aio/control.hpp"
#include "node/aio/guard.hpp"
#include "node/aio/run_dir.hpp"
#include "node/aio/topology.hpp"
#include "platform/log.hpp"
#include "supervisor.hpp"

namespace {

using ksim::api::json;

volatile std::sig_atomic_t g_signal = 0;

extern "C" void on_signal(int sig) { g_signal = sig; }

/// UTC now: "2026-10-15T06:00:00Z" (iso) or "20261015T060000Z" (a run directory's name).
std::string utc_now(bool iso) {
    std::array<char, 32> buf{};
    const std::time_t t = std::time(nullptr);
    std::tm tm{};
    gmtime_r(&t, &tm);
    if (iso) {
        std::strftime(buf.data(), buf.size(), "%Y-%m-%dT%H:%M:%SZ", &tm);
    } else {
        std::strftime(buf.data(), buf.size(), "%Y%m%dT%H%M%SZ", &tm);
    }
    return std::string(buf.data());
}

std::string runs_base() {
    const char* env = std::getenv("KSIM_RUNS");   // NOLINT(concurrency-mt-unsafe): read at start-up only
    return env != nullptr && *env != '\0' ? std::string(env) : std::string("runs");
}

json manifest(const ksim::node::Topology& t, const std::string& run_dir, bool lab) {
    json m = json::object();
    m["run"] = std::filesystem::path(run_dir).filename().string();
    m["started_utc"] = utc_now(true);
    m["host"] = ksim::node::host_name();
    m["pid"] = static_cast<std::int64_t>(::getpid());
    m["build"] = {{"version", ksim::build::kVersion},
                  {"commit", ksim::build::kGitDescribe},
                  {"configure_utc", ksim::build::kConfigureUtc},
                  {"build_type", ksim::build::kBuildType},
                  {"sanitize", ksim::build::kSanitize},
                  {"compiler", ksim::build::kCxxCompiler},
                  {"arch_flags", ksim::build::kArchFlags}};
    m["topology"] = {{"file", std::filesystem::absolute(t.file).string()}, {"sha256", ksim::node::file_sha256(t.file)}};
    m["seed"] = t.seed;
    m["spec"] = {{"index_sha256", ksim::build::kSpecIndexSha256}, {"asn1c", ksim::build::kAsn1cPin}};
    json peer = json::object();
    for (const auto& [k, v] : t.peer) {
        peer[k] = v;
    }
    m["peer"] = peer;
    m["lab"] = lab;
    m["plain_nas"] = t.plain_nas;
    // P2 Q8: what p2_exit checks (no exit run with the NULL bisect switch) and the capture kept.
    m["security"] = {{"allow_null", t.allow_null}, {"as_nea", t.nea_pref}, {"as_nia", t.nia_pref}};
    m["capture"] = {{"user_plane", t.capture_up == ksim::node::UserPlaneCapture::full      ? "full"
                                   : t.capture_up == ksim::node::UserPlaneCapture::headers ? "headers"
                                                                                           : "off"}};
    m["link"] = {{"delay_ms", t.link_delay_ms}, {"jitter_ms", t.link_jitter_ms}};   // P2 Q12
    m["amf"] = t.amf.to_string();
    m["ues"] = 0;
    for (const auto& g : t.ues) {
        m["ues"] = m["ues"].get<unsigned>() + g.count;
    }
    m["status"] = "starting";
    return m;
}

struct Overrides {
    std::string sealed;
    std::string kek;
    bool plain_nas = false;
    std::string role;    // P2 Q3: one role of a split run
    std::string kair;    // P2 Q3: the DU's KAIR socket
};

int run(const std::string& topology_file, std::string run_dir, bool lab, int tcp_port, const Overrides& o) {
    std::string why;
    auto topo = ksim::node::load_topology(topology_file, why);
    if (!topo) {
        std::cerr << "ksim: " << why << "\n";
        return 2;
    }
    if (!o.sealed.empty()) {
        topo->sealed_dir = std::filesystem::absolute(o.sealed).string();
    }
    if (!o.kek.empty()) {
        topo->kek_file = std::filesystem::absolute(o.kek).string();
    }
    topo->plain_nas = o.plain_nas;
    if (!o.role.empty()) {
        auto r = ksim::node::parse_role(o.role);
        if (!r || topo->mode != ksim::node::Mode::split || o.kair.empty()) {
            std::cerr << "ksim: --role is cucp, cuup, du or ue, of a mode: split topology, with --kair\n";
            return 2;
        }
        topo->role = *r;
        topo->kair_socket = o.kair;
    }
    ksim::node::GuardInput guard;
    guard.addresses = {topo->amf, topo->ng_bind};
    guard.lab = lab;
    guard.host = ksim::node::host_name();
    guard.processes = ksim::node::process_names();
    if (const std::string refused = ksim::node::check_guard(guard); !refused.empty()) {
        std::cerr << "ksim: refused: " << refused << "\n";
        return 7;
    }
    const bool named = !run_dir.empty();
    if (!named) {
        run_dir = runs_base() + "/" + utc_now(false);
    }
    if (auto r = ksim::node::make_run_dir(run_dir); !r) {
        std::cerr << "ksim: " << run_dir << ": " << r.error().what << "\n";
        return 2;
    }
    run_dir = std::filesystem::absolute(run_dir).lexically_normal().string();
    if (!named) {
        const std::string latest = runs_base() + "/latest";
        std::error_code ec;
        std::filesystem::remove(latest, ec);
        std::filesystem::create_directory_symlink(std::filesystem::path(run_dir).filename(), latest, ec);
    }

    std::FILE* log = std::fopen((run_dir + "/ksim.log").c_str(), "a");
    if (log != nullptr) {
        ::fchmod(::fileno(log), 0600);
        ksim::log::set_sink([log](std::string_view line) {
            (void)std::fwrite(line.data(), 1, line.size(), log);
            (void)std::fputc('\n', log);
            std::fflush(log);
        });
    }
    if (topo->mode == ksim::node::Mode::split && topo->role == ksim::node::Role::all) {
        // The supervisor of a split run (P2 Q3).
        ksim::app::RoleArgs ra;
        ra.lab = lab;
        ra.plain_nas = o.plain_nas;
        ra.sealed = topo->sealed_dir;
        ra.kek = topo->kek_file;
        const int rc = ksim::app::supervise(*topo, std::filesystem::absolute(topology_file).string(), run_dir, ra, g_signal);
        ksim::log::set_sink({});
        if (log != nullptr) {
            std::fclose(log);
        }
        return rc;
    }
    json m = manifest(*topo, run_dir, lab);
    m["role"] = ksim::node::role_name(topo->role);
    (void)ksim::node::write_file(run_dir + "/manifest.json", m.dump(2) + "\n");

    auto aio = ksim::node::AllInOne::start(*topo, run_dir, why);
    if (!aio) {
        std::cerr << "ksim: " << why << "\n";
        m["status"] = "failed";
        m["error"] = why;
        (void)ksim::node::write_file(run_dir + "/manifest.json", m.dump(2) + "\n");
        return 1;
    }
    std::atomic<bool> stop{false};
    ksim::api::Server server;
    ksim::node::bind_control(server, *aio, stop);
    const std::string ctl = run_dir + "/ctl.sock";
    if (auto r = server.listen_unix(ctl); !r) {
        std::cerr << "ksim: " << ctl << ": " << r.error().what << "\n";
        aio->stop();
        return 1;
    }
    if (tcp_port > 0) {
        if (auto r = server.listen_tcp("127.0.0.1", static_cast<std::uint16_t>(tcp_port)); !r) {
            std::cerr << "ksim: TCP " << tcp_port << ": " << r.error().what << "\n";
            server.stop();
            aio->stop();
            return 1;
        }
    }
    m["status"] = "running";
    (void)ksim::node::write_file(run_dir + "/manifest.json", m.dump(2) + "\n");
    ksim::log::info("ksim", "run {} up: gNB {} towards AMF {}", run_dir, topo->gnb_name, topo->amf.to_string());
    std::cout << "RUN_DIR=" << run_dir << "\nCTL=" << ctl << "\n" << std::flush;

    while (g_signal == 0 && !stop.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    server.stop();
    aio->stop();
    const auto c = aio->capture()->stats();
    m["status"] = "stopped";
    m["stopped_utc"] = utc_now(true);
    m["events"] = aio->events().last_seq();
    m["capture"] = {{"ngap", c.ngap}, {"f1ap", c.f1ap}, {"uu", c.uu}, {"keys_zeroed", c.keys_zeroed}, {"left_out", c.left_out}};
    m["loop_lag_max_ms"] = aio->max_lag_ms();
    (void)ksim::node::write_file(run_dir + "/manifest.json", m.dump(2) + "\n");
    ksim::log::info("ksim", "run {} stopped", run_dir);
    ksim::log::set_sink({});
    if (log != nullptr) {
        std::fclose(log);
    }
    return 0;
}

int stop_run(std::string run_dir) {
    if (run_dir.empty()) {
        run_dir = runs_base() + "/latest";
    }
    httplib::Client cli(ksim::api::socket_target(run_dir + "/ctl.sock"));
    cli.set_address_family(AF_UNIX);
    auto res = cli.Post("/v1/stop");
    if (!res) {
        std::cerr << "ksim: no run answers at " << run_dir << "/ctl.sock\n";
        return 4;
    }
    std::cout << "STOPPING=1\n";
    return 0;
}

} // namespace

static int run_main(int argc, char** argv) {
    CLI::App app{"ksim: the kaluza-sim all-in-one UE and RAN simulator"};
    app.set_version_flag("--version", std::string("ksim ") + ksim::build::kVersion + " " + ksim::build::kGitDescribe);
    app.require_subcommand(1);
    std::string topology;
    std::string run_dir;
    bool lab = false;
    int tcp = 0;
    auto* run_cmd = app.add_subcommand("run", "start a run");
    run_cmd->add_option("-c,--topology", topology, "the topology YAML")->required();
    run_cmd->add_option("--run-dir", run_dir, "the run directory (default $KSIM_RUNS or runs/<UTC time>)");
    run_cmd->add_flag("--lab", lab, "reach the lab network (kaluza-uesim only)");
    run_cmd->add_option("--tcp", tcp, "also serve the control API on 127.0.0.1:PORT");
    Overrides o;
    run_cmd->add_option("--sealed", o.sealed, "the sealed card directory (instead of the topology's)");
    run_cmd->add_option("--kek", o.kek, "the KEK file (instead of the topology's)");
    run_cmd->add_flag("--plain-nas", o.plain_nas, "put NAS in clear into the Uu capture (KS-CTL-004)");
#ifdef KSIM_FIXED_ROLE
    o.role = KSIM_FIXED_ROLE;
#else
    run_cmd->add_option("--role", o.role, "one role of a split run: cucp, cuup, du or ue (the supervisor starts them)");
#endif
    run_cmd->add_option("--kair", o.kair, "a split run's KAIR socket (the DU's)");
    auto* stop_cmd = app.add_subcommand("stop", "stop a run");
    stop_cmd->add_option("--run-dir", run_dir, "the run directory (default the latest)");
    CLI11_PARSE(app, argc, argv);

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    std::signal(SIGPIPE, SIG_IGN);
    if (run_cmd->parsed()) {
        return run(topology, run_dir, lab, tcp, o);
    }
    return stop_run(run_dir);
}

int main(int argc, char** argv) {
    // An exception that reaches here is a bug: exit 10 (cli.md's internal error).
    try {
        return run_main(argc, argv);
    } catch (const std::exception& e) {
        std::fputs("ksim: internal error: ", stderr);
        std::fputs(e.what(), stderr);
        std::fputs("\n", stderr);
    } catch (...) {
        std::fputs("ksim: internal error\n", stderr);
    }
    return 10;
}
