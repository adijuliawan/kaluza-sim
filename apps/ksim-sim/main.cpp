// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// ksim-sim: the offline card lifecycle (P1 N8 part; architecture §2.1,
// sim-uicc.md §8, ADR 0010).
//
//   ksim-sim range init --master <file> --kek <file>
//       creates whichever of the two key files is missing: 32 random octets, 0600
//   ksim-sim range derive --block <first IMSI>/<count> --master <file> --kek <file> --out <dir> [--force]
//       writes <dir>/imsi-<IMSI>.sec: the card's secrets (K, OPc, PINs, ADM1)
//       from the master, sealed under the KEK; prints BATCH_SALT, then one
//       IMSI= K_FPR= line per card, never a key
//   ksim-sim range provision --target open5gs --block <…> --master <file> --ssh <host>
//            [--db-config <remote yaml>] [--sst 1] [--sd 000001] [--dnn internet] [--replace]
//            [--pcc-gbr KBPS]   (P2 Q13: open5gs, a GBR PCC rule on the first DNN's session)
//   ksim-sim range deprovision --target open5gs --block <…> --ssh <host> [--db-config <remote yaml>]
//   ksim-sim serve --pcsc <reader> --listen <host:port> --allow <address> [--admin]
//       the card bridge (P2 Q1; lab.md §7): a real card lent to one remote terminal
//   ksim-sim adm1 seal --out <file> --kek <file> [--stdin]
//   ksim-sim burn --pcsc <reader> --imsi <IMSI> --master <file> --adm1 <file> --kek <file> [--dry-run]
//       a spare real card written as a sim-range card (burn.hpp; the user runs both)
//       the block into or out of the Open5GS fork's PostgreSQL on the rig
//       (ADR 0010 point 2): one ogs_subscriber_upsert() per subscriber, the
//       fork's own write path. The documents travel in a COPY data block on
//       ssh's stdin, so K and OPc are in no argv, no statement text a server
//       log could keep, no file; the database credentials are read on the rig
//       from the NFs' db_uri into PG* variables, never a command line.
//
// Keys exist only in memory and in sealed files. A clear list of keys never
// exists, and nothing here prints one (requirements §3.6).

#include <fcntl.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <CLI/CLI.hpp>

#include "burn.hpp"
#include "card.hpp"

#include <cstdio>
#include <exception>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cerrno>
#include <span>
#include <filesystem>
#include <iostream>
#include <regex>
#include <sstream>
#include <cstdlib>
#include <vector>

#include "crypto/aead.hpp"
#include "kaluza.hpp"
#include "platform/secret.hpp"
#include "uicc/image/image.hpp"
#include "uicc/secrets/secrets.hpp"

extern char** environ;   // NOLINT: posix_spawnp passes our environment on

namespace {

namespace secrets = ksim::uicc::secrets;

struct Block {
    std::string first;
    unsigned count = 0;
};

std::string imsi_at(const std::string& first, unsigned i) {
    std::string s = std::to_string(std::stoull(first) + i);
    return std::string(15 - s.size(), '0') + s;
}

bool parse_block(const std::string& s, Block& b) {
    const auto slash = s.find('/');
    b.first = s.substr(0, slash);
    const std::string n = slash == std::string::npos ? "1" : s.substr(slash + 1);
    if (n.empty() || n.size() > 4 || n.find_first_not_of("0123456789") != std::string::npos ||
        !ksim::uicc::image::range_subscriber(b.first)) {
        return false;
    }
    b.count = static_cast<unsigned>(std::stoul(n));
    // Both ends inside the same sim range.
    return b.count >= 1 && b.count <= 1000 && ksim::uicc::image::range_subscriber(imsi_at(b.first, b.count - 1)) &&
           imsi_at(b.first, b.count - 1).substr(0, 12) == b.first.substr(0, 12);
}

int init(const std::string& master, const std::string& kek) {
    int created = 0;
    for (const auto& path : {master, kek}) {
        if (std::filesystem::exists(path)) {
            std::cout << "KEPT=" << path << "\n";
            continue;
        }
        const auto dir = std::filesystem::path(path).parent_path();
        if (!dir.empty() && !std::filesystem::exists(dir)) {
            std::filesystem::create_directories(dir);
            std::filesystem::permissions(dir, std::filesystem::perms::owner_all);
        }
        if (auto r = secrets::create_key_file(path); !r) {
            std::cerr << "ksim-sim: " << path << ": " << r.error().what << "\n";
            return 1;
        }
        std::cout << "CREATED=" << path << "\n";
        ++created;
    }
    std::cout << "CREATED_FILES=" << created << "\n";
    return 0;
}

int derive(const Block& b, const std::string& master_file, const std::string& kek_file, const std::string& out, bool force) {
    auto master = secrets::load_kek(master_file);
    if (!master) {
        std::cerr << "ksim-sim: the range master: " << master.error().what << "\n";
        return 1;
    }
    auto kek = secrets::load_kek(kek_file);
    if (!kek) {
        std::cerr << "ksim-sim: the KEK: " << kek.error().what << "\n";
        return 1;
    }
    if (!std::filesystem::exists(out)) {
        std::filesystem::create_directories(out);
    }
    std::filesystem::permissions(out, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace);
    auto salt = ksim::crypto::aead::random_bytes(16);
    if (!salt) {
        std::cerr << "ksim-sim: no random source\n";
        return 1;
    }
    std::cout << "BATCH_SALT=" << ksim::to_hex(*salt) << "\n";
    for (unsigned i = 0; i < b.count; ++i) {
        const std::string imsi = imsi_at(b.first, i);
        const secrets::SecretMap m = secrets::card_secrets(*master, imsi);
        auto sealed = secrets::seal(*kek, m);
        if (!sealed) {
            std::cerr << "ksim-sim: imsi-" << imsi << ": " << sealed.error().what << "\n";
            return 1;
        }
        std::string path = out;
        path += "/imsi-";
        path += imsi;
        path += ".sec";
        const int flags = O_WRONLY | O_CREAT | O_CLOEXEC | (force ? O_TRUNC : O_EXCL);
        const int fd = ::open(path.c_str(), flags, 0600);
        if (fd < 0) {
            std::cerr << "ksim-sim: " << path << ": cannot create (exists? --force)\n";
            return 1;
        }
        const ssize_t n = ::write(fd, sealed->data(), sealed->size());
        ::fchmod(fd, 0600);
        ::close(fd);
        if (n != static_cast<ssize_t>(sealed->size())) {
            std::cerr << "ksim-sim: " << path << ": short write\n";
            return 1;
        }
        std::cout << "IMSI=" << imsi << " K_FPR=" << secrets::key_fingerprint(*salt, *m.get("k")) << "\n";
    }
    std::cout << "DERIVED=" << b.count << "\n";
    return 0;
}

// ---- Open5GS (ADR 0010 point 2) --------------------------------------------------------------

void wipe(std::string& s) noexcept {
    ksim::secure_zero(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(s.data()), s.size()));   // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    s.clear();
}

/// Runs argv with `input` on its stdin and returns its exit status; its
/// stdout lines go to `out`. stderr passes through.
int run_with_stdin(const std::vector<std::string>& argv, std::string& input, std::vector<std::string>& out) {
    int in[2];
    int outp[2];
    if (::pipe2(in, O_CLOEXEC) != 0 || ::pipe2(outp, O_CLOEXEC) != 0) {
        return -1;
    }
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, in[0], 0);
    posix_spawn_file_actions_adddup2(&fa, outp[1], 1);
    std::vector<char*> args;
    args.reserve(argv.size() + 1);
    for (const auto& a : argv) {
        args.push_back(const_cast<char*>(a.c_str()));   // NOLINT(cppcoreguidelines-pro-type-const-cast): posix_spawn's signature
    }
    args.push_back(nullptr);
    pid_t pid = 0;
    const int rc = posix_spawnp(&pid, args[0], &fa, nullptr, args.data(), environ);
    posix_spawn_file_actions_destroy(&fa);
    ::close(in[0]);
    ::close(outp[1]);
    if (rc != 0) {
        ::close(in[1]);
        ::close(outp[0]);
        wipe(input);
        return -1;
    }
    std::size_t done = 0;
    while (done < input.size()) {
        const ssize_t n = ::write(in[1], input.data() + done, input.size() - done);
        if (n <= 0) {
            break;
        }
        done += static_cast<std::size_t>(n);
    }
    wipe(input);
    ::close(in[1]);
    std::string text;
    std::array<char, 4096> buf{};
    for (;;) {
        const ssize_t n = ::read(outp[0], buf.data(), buf.size());
        if (n <= 0) {
            break;
        }
        text.append(buf.data(), static_cast<std::size_t>(n));
    }
    ::close(outp[0]);
    int status = 0;
    ::waitpid(pid, &status, 0);
    std::istringstream lines(text);
    for (std::string l; std::getline(lines, l);) {
        if (!l.empty()) {
            out.push_back(l);
        }
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/// The command the rig runs: psql on the NFs' database, its credentials taken
/// from `cfg`'s db_uri into the environment. No secret is in this text.
std::string remote_psql(const std::string& cfg) {
    std::string s = "set -eu\ncfg=";
    s += cfg;
    s += "\n"
           "uri=$(sed -n 's/^[[:space:]]*db_uri:[[:space:]]*//p' \"$cfg\" | head -n 1)\n"
           "case \"$uri\" in postgresql://*@*/*) ;; *) echo 'ksim-sim: no postgresql db_uri in the config' >&2; exit 3 ;; esac\n"
           "rest=${uri#postgresql://}; cred=${rest%%@*}; hostdb=${rest#*@}; hp=${hostdb%%/*}\n"
           "PGUSER=${cred%%:*}; PGPASSWORD=${cred#*:}; PGDATABASE=${hostdb#*/}\n"
           "case \"$hp\" in *:*) PGHOST=${hp%%:*}; PGPORT=${hp#*:} ;; *) PGHOST=$hp; PGPORT=5432 ;; esac\n"
           "export PGUSER PGPASSWORD PGHOST PGPORT PGDATABASE\n"
           "exec psql -X -q -A -t -v ON_ERROR_STOP=1 -v VERBOSITY=terse\n";
    return s;
}

struct Rig {
    std::string ssh;
    std::string cfg;
};

int psql(const Rig& rig, std::string& sql, std::vector<std::string>& out) {
    const std::vector<std::string> argv{"ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", rig.ssh, remote_psql(rig.cfg)};
    return run_with_stdin(argv, sql, out);
}

std::string imsi_list(const Block& b) {
    std::string s;
    for (unsigned i = 0; i < b.count; ++i) {
        s += (i ? ",'" : "'") + imsi_at(b.first, i) + "'";
    }
    return s;
}

/// The DNNs of a comma-separated --dnn list (N17: internet,ims for the session gate).
std::vector<std::string> dnn_list(const std::string& dnns) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : dnns + ",") {
        if (c == ',') {
            if (!cur.empty()) {
                out.push_back(cur);
            }
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    return out;
}

/// The fork's subscriber document (misc/db/open5gs-dbctl-pgsql subscriber_doc
/// at 741c29d8d: Milenage with OPc, AMF 8000, one slice, 1 Gbps), one session
/// per DNN, the first the default.
/// P2 Q13 (D2): a GBR PCC rule for the rig's GBR row: 5QI 1, the GFBR given and twice it
/// as MFBR (kbit/s), ICMP to and from the DN reflector 10.55.0.1. Flows are written from the
/// remote end to the UE (TS 29.212 5.4.2); the fork's SMF swaps the uplink one.
nlohmann::json gbr_pcc_rule(unsigned kbps) {
    using nlohmann::json;
    const auto rate = [](unsigned v) { return json{{"value", v}, {"unit", 1}}; };   // unit 1: kbit/s
    const std::string desc = "permit out icmp from 10.55.0.1 to any";
    return {{"flow", json::array({{{"direction", 1}, {"description", desc}}, {{"direction", 2}, {"description", desc}}})},
            {"qos",
             {{"index", 1},
              {"arp", {{"priority_level", 2}, {"pre_emption_capability", 1}, {"pre_emption_vulnerability", 2}}},
              {"mbr", {{"downlink", rate(kbps * 2)}, {"uplink", rate(kbps * 2)}}},
              {"gbr", {{"downlink", rate(kbps)}, {"uplink", rate(kbps)}}}}}};
}

nlohmann::json subscriber_doc(const std::string& imsi, unsigned sst, const std::string& sd, const std::string& dnns,
                              unsigned pcc_gbr_kbps = 0) {
    using nlohmann::json;
    const json ambr = {{"downlink", {{"value", 1000000000}, {"unit", 0}}}, {"uplink", {{"value", 1000000000}, {"unit", 0}}}};
    json sessions = json::array();
    for (const auto& dnn : dnn_list(dnns)) {
        json pcc = json::array();
        if (pcc_gbr_kbps != 0 && sessions.empty()) {
            pcc.push_back(gbr_pcc_rule(pcc_gbr_kbps));
        }
        sessions.push_back({{"name", dnn},
                            {"type", 3},
                            {"qos", {{"index", 9}, {"arp", {{"priority_level", 8}, {"pre_emption_capability", 1}, {"pre_emption_vulnerability", 2}}}}},
                            {"ambr", ambr},
                            {"pcc_rule", pcc}});
    }
    json slice = {{"sst", sst}, {"default_indicator", true}, {"session", sessions}};
    if (!sd.empty()) {
        slice["sd"] = sd;
    }
    return {{"imsi", imsi},
            {"schema_version", 1},
            {"slice", json::array({slice})},
            {"ambr", ambr},
            {"access_restriction_data", 32},
            {"network_access_mode", 0},
            {"subscribed_rau_tau_timer", 12},
            {"__v", 0}};
}

int provision(const Block& b, const std::string& master_file, const Rig& rig, unsigned sst, const std::string& sd,
              const std::string& dnn, bool replace, unsigned pcc_gbr_kbps) {
    auto master = secrets::load_kek(master_file);
    if (!master) {
        std::cerr << "ksim-sim: the range master: " << master.error().what << "\n";
        return 1;
    }
    // First the collision check: nothing in the block may exist unless --replace.
    std::vector<std::string> out;
    std::string check = "SELECT 'EXISTING=' || imsi FROM subscribers WHERE imsi IN (" + imsi_list(b) + ") ORDER BY imsi;\n";
    if (psql(rig, check, out) != 0) {
        std::cerr << "ksim-sim: the rig's database did not answer\n";
        return 1;
    }
    for (const auto& l : out) {
        std::cout << l << "\n";
    }
    if (!out.empty() && !replace) {
        std::cerr << "ksim-sim: subscribers of the block exist already (--replace to overwrite them)\n";
        return 1;
    }
    auto salt = ksim::crypto::aead::random_bytes(16);
    if (!salt) {
        return 1;
    }
    std::cout << "BATCH_SALT=" << ksim::to_hex(*salt) << "\n";
    std::string sql = "BEGIN;\nCREATE TEMP TABLE ksim_sub (doc jsonb) ON COMMIT DROP;\nCOPY ksim_sub (doc) FROM STDIN;\n";
    for (unsigned i = 0; i < b.count; ++i) {
        const std::string imsi = imsi_at(b.first, i);
        const auto k = secrets::derive(*master, "K", imsi);
        const auto opc = secrets::derive(*master, "OPc", imsi);
        nlohmann::json doc = subscriber_doc(imsi, sst, sd, dnn, pcc_gbr_kbps);
        // auth_method 1, 5G AKA: without it the fork's UDR picks EAP-TTLS
        // (src/udr/nudr-handler.c at 741c29d8d).
        doc["security"] = {{"k", ksim::to_hex(k.expose())}, {"op", nullptr}, {"opc", ksim::to_hex(opc.expose())},
                           {"amf", "8000"}, {"auth_method", 1}};
        std::string line = doc.dump();   // no tab, backslash or newline: COPY text as is
        doc["security"]["k"].get_ref<std::string&>().assign(32, '0');
        doc["security"]["opc"].get_ref<std::string&>().assign(32, '0');
        sql += line;
        sql += '\n';
        wipe(line);
        std::cout << "IMSI=" << imsi << " K_FPR=" << secrets::key_fingerprint(*salt, k) << "\n";
    }
    sql += "\\.\nSELECT 'UPSERTED=' || count(ogs_subscriber_upsert(doc)) FROM ksim_sub;\nCOMMIT;\n"
           "SELECT 'PRESENT=' || imsi FROM subscribers WHERE imsi IN (" + imsi_list(b) + ") ORDER BY imsi;\n";
    out.clear();
    const int rc = psql(rig, sql, out);   // wipes sql
    unsigned present = 0;
    for (const auto& l : out) {
        if (l.rfind("UPSERTED=", 0) == 0 || l.rfind("PRESENT=", 0) == 0) {
            std::cout << l << "\n";
            present += l.rfind("PRESENT=", 0) == 0 ? 1U : 0U;
        }
    }
    std::cout << "PROVISIONED=" << present << "/" << b.count << "\n";
    return rc == 0 && present == b.count ? 0 : 1;
}

int deprovision(const Block& b, const Rig& rig) {
    std::vector<std::string> out;
    std::string sql = "WITH d AS (DELETE FROM subscribers WHERE imsi IN (" + imsi_list(b) +
                      ") RETURNING imsi) SELECT 'DELETED=' || imsi FROM d ORDER BY imsi;\n"
                      "SELECT 'REMAINING=' || count(*) FROM subscribers WHERE imsi IN (" + imsi_list(b) + ");\n";
    const int rc = psql(rig, sql, out);
    for (const auto& l : out) {
        std::cout << l << "\n";
    }
    const bool none_left = std::find(out.begin(), out.end(), "REMAINING=0") != out.end();
    return rc == 0 && none_left ? 0 : 1;
}

bool safe_remote_path(const std::string& p) {
    static const std::regex ok("^(~/|/)[A-Za-z0-9_./-]+$");
    return std::regex_match(p, ok) && p.find("..") == std::string::npos;
}

} // namespace

static int run_main(int argc, char** argv) {
    CLI::App app{"ksim-sim: sim-range cards and subscribers"};
    app.require_subcommand(1);
    auto* range = app.add_subcommand("range", "the sim ranges (sim-uicc.md section 8)");
    range->require_subcommand(1);
    std::string master;
    std::string kek;
    std::string block;
    std::string out;
    std::string target;
    std::string ssh;
    std::string db_config = "~/kaluza-sim-rig/etc/udr.yaml";
    std::string sd;
    std::string dnn = "internet,ims";
    unsigned sst = 1;
    bool force = false;
    bool replace = false;
    bool dry_run = false;
    ksim::sim::KaluzaApi api;
    const char* home = std::getenv("HOME");   // NOLINT(concurrency-mt-unsafe): read at start-up only
    api.cred_dir = std::string(home != nullptr ? home : "") + "/.config/kaluza-sim/provisioning";
    std::vector<std::string> resolve;
    auto* init_cmd = range->add_subcommand("init", "create the range master and the KEK if missing");
    init_cmd->add_option("--master", master, "the range master file")->required();
    init_cmd->add_option("--kek", kek, "the KEK file")->required();
    auto* derive_cmd = range->add_subcommand("derive", "write sealed card secrets for a block");
    derive_cmd->add_option("--block", block, "<first IMSI>/<count>")->required();
    derive_cmd->add_option("--master", master, "the range master file")->required();
    derive_cmd->add_option("--kek", kek, "the KEK file")->required();
    derive_cmd->add_option("--out", out, "the sealed card directory")->required();
    derive_cmd->add_flag("--force", force, "overwrite existing sealed files");
    auto* prov_cmd = range->add_subcommand("provision", "put a block into a core");
    auto* deprov_cmd = range->add_subcommand("deprovision", "remove a block from a core");
    for (auto* c : {prov_cmd, deprov_cmd}) {
        c->add_option("--target", target, "open5gs or kaluza")->required();
        c->add_option("--block", block, "<first IMSI>/<count>")->required();
        c->add_option("--ssh", ssh, "open5gs: the rig's ssh host");
        c->add_option("--db-config", db_config, "open5gs: the rig's NF config holding db_uri");
        c->add_option("--token-url", api.token_url, "kaluza: the Keycloak token endpoint (https)");
        c->add_option("--udr-url", api.udr_url, "kaluza: the UDR provisioning listener (https://host:port)");
        c->add_option("--resolve", resolve, "kaluza: host=address, as curl --resolve (repeatable)");
        c->add_option("--cred-dir", api.cred_dir, "kaluza: the provisioning credentials' directory");
        c->add_option("--secret-file", api.secret_file, "kaluza: the client secret's file name in --cred-dir");
        c->add_flag("--token-mtls", api.token_mtls, "kaluza: the client certificate on the token request too");
    }
    prov_cmd->add_option("--master", master, "the range master file")->required();
    prov_cmd->add_option("--sst", sst, "the slice's SST");
    prov_cmd->add_option("--sd", sd, "the slice's SD (6 hex digits)");
    prov_cmd->add_option("--dnn", dnn, "the sessions' DNNs, comma-separated (internet,ims)");
    prov_cmd->add_flag("--replace", replace, "overwrite subscribers of the block that exist");
    unsigned pcc_gbr_kbps = 0;
    prov_cmd->add_option("--pcc-gbr", pcc_gbr_kbps, "open5gs: a GBR PCC rule (5QI 1, this GFBR in kbit/s) on the first DNN's session");
    prov_cmd->add_flag("--dry-run", dry_run, "kaluza: print each bundle with its keys as placeholders, send nothing");
    // P1 N14: the card on a virtual reader, and the card images.
    ksim::sim::ServeOptions so;
    auto* serve_cmd = app.add_subcommand("serve", "the soft card on pcscd's vpcd reader (sim-uicc.md section 5)");
    serve_cmd->add_option("--template", so.card.tmpl, "the card image template");
    serve_cmd->add_option("--imsi", so.card.imsi, "the sim-range IMSI the card is personalised for");
    serve_cmd->add_option("--sealed", so.card.sealed_dir, "the sealed card secrets' directory");
    serve_cmd->add_option("--kek", so.card.kek, "the KEK file");
    serve_cmd->add_flag("--test-keys", so.card.test_keys, "TS 35.208 test set 1 and test PINs (CI and lab cards only)");
    serve_cmd->add_option("--vpcd", so.vpcd, "vpcd's host:port (reader 0 is 35963)");
    serve_cmd->add_option("--trace-udp", so.trace_udp, "GSMTAP-SIM to host:port (4729)");
    serve_cmd->add_option("--trace-pcap", so.trace_pcap, "GSMTAP-SIM into a pcapng file (0600)");
    serve_cmd->add_flag("--no-redact", so.no_redact, "trace keys and PINs in clear (with --test-keys only)");
    serve_cmd->add_option("--seconds", so.seconds, "stop after this long (0: on SIGINT or SIGTERM)");
    serve_cmd->add_option("--personality", so.card.personality, "present a real card's ATR (sysmoISIM-SJA5)");
    // P2 Q1: the card bridge, a real card lent over the vpcd framing (lab.md section 7).
    ksim::sim::BridgeOptions bo;
    serve_cmd->add_option("--pcsc", bo.reader, "bridge: the card in this PC/SC reader (a name, #n or a unique part)");
    serve_cmd->add_option("--listen", bo.listen, "bridge: host:port to listen on (35970)");
    serve_cmd->add_option("--allow", bo.allow, "bridge: the one peer address it takes");
    serve_cmd->add_flag("--admin", bo.admin, "bridge: let VERIFY ADM1 and AF20/AF30 writes through");
    auto* adm1_cmd = app.add_subcommand("adm1", "a real card's ADM1, sealed (P2 Q1; the user runs it)");
    adm1_cmd->require_subcommand(1);
    std::string seal_out;
    bool seal_stdin = false;
    auto* seal_cmd = adm1_cmd->add_subcommand("seal", "ask for the ADM1 without echo and write it sealed under the KEK");
    seal_cmd->add_option("--out", seal_out, "the sealed file (0600, never overwritten)")->required();
    seal_cmd->add_option("--kek", kek, "the KEK file")->required();
    seal_cmd->add_flag("--stdin", seal_stdin, "read one line from stdin instead (tests)");
    ksim::sim::BurnOptions burn_o;
    auto* burn_cmd = app.add_subcommand("burn", "write a real card over PC/SC as a sim-range card (the user runs it)");
    burn_cmd->add_option("--pcsc", burn_o.reader, "the PC/SC reader (a name, #n or a unique part)")->required();
    burn_cmd->add_option("--imsi", burn_o.imsi, "the sim-range IMSI the card becomes")->required();
    burn_cmd->add_option("--master", burn_o.master, "the range master file")->required();
    burn_cmd->add_option("--adm1", burn_o.adm1, "the sealed ADM1 (ksim-sim adm1 seal)")->required();
    burn_cmd->add_option("--kek", burn_o.kek, "the KEK the ADM1 is sealed under")->required();
    burn_cmd->add_option("--template", burn_o.tmpl, "the card image template for the EF contents");
    burn_cmd->add_flag("--dry-run", burn_o.dry_run, "read the card and its ADM1 tries; write nothing");
    std::string image;
    bool access = false;
    auto* validate_cmd = app.add_subcommand("validate", "check a card image (TS 102 221, TS 31.102)");
    validate_cmd->add_option("image", image, "the card image")->required();
    validate_cmd->add_flag("--access", access, "each EF's READ access after a reset");
    ksim::sim::CardSource es;
    auto* export_cmd = app.add_subcommand("export", "the card's contents as a pySim-shell script, keys left out");
    export_cmd->add_option("--template", es.tmpl, "the card image template");
    export_cmd->add_option("--imsi", es.imsi, "the sim-range IMSI");
    export_cmd->add_option("--sealed", es.sealed_dir, "the sealed card secrets' directory");
    export_cmd->add_option("--kek", es.kek, "the KEK file");
    export_cmd->add_flag("--test-keys", es.test_keys, "TS 35.208 test set 1 and test PINs");
    std::string fsdump;
    std::string import_out;
    std::string import_tmpl = "cards/usim-5g.yaml";
    auto* import_cmd = app.add_subcommand("import", "a template's contents from a pySim-shell fsdump");
    import_cmd->add_option("--fsdump", fsdump, "pySim-shell fsdump output (without --json)")->required();
    import_cmd->add_option("--template", import_tmpl, "the template it starts from");
    import_cmd->add_option("--out", import_out, "the new image (0600)")->required();
    CLI11_PARSE(app, argc, argv);
    ::umask(077);
    if (serve_cmd->parsed()) {
        if (!bo.reader.empty()) {
            bo.trace_udp = so.trace_udp;
            bo.trace_pcap = so.trace_pcap;
            bo.seconds = so.seconds;
            return ksim::sim::serve_bridge(bo);
        }
        return ksim::sim::serve(so);
    }
    if (seal_cmd->parsed()) {
        return ksim::sim::adm1_seal(seal_out, kek, seal_stdin);
    }
    if (burn_cmd->parsed()) {
        return ksim::sim::burn_pcsc(burn_o);
    }
    if (validate_cmd->parsed()) {
        return ksim::sim::validate(image, access);
    }
    if (export_cmd->parsed()) {
        return ksim::sim::export_script(es);
    }
    if (import_cmd->parsed()) {
        return ksim::sim::import_fsdump(fsdump, import_tmpl, import_out);
    }
    if (init_cmd->parsed()) {
        return init(master, kek);
    }
    Block b;
    if (!parse_block(block, b)) {
        std::cerr << "ksim-sim: --block is <first IMSI>/<count 1..1000> inside one sim range\n";
        return 2;
    }
    if (derive_cmd->parsed()) {
        return derive(b, master, kek, out, force);
    }
    if (target == "kaluza") {
        // 001/01 only: the 999/70 home UDR has no provisioning listener (ADR 0008).
        if (b.first.rfind("001010000300", 0) != 0) {
            std::cerr << "ksim-sim: --target kaluza takes the 001/01 sim range only\n";
            return 2;
        }
        for (const auto& r : resolve) {
            const auto eq = r.find('=');
            if (eq == std::string::npos) {
                std::cerr << "ksim-sim: --resolve is host=address\n";
                return 2;
            }
            api.resolve[r.substr(0, eq)] = r.substr(eq + 1);
        }
        if (prov_cmd->parsed()) {
            return ksim::sim::kaluza_provision(b.first, b.count, master, api, dry_run, replace);
        }
        return ksim::sim::kaluza_deprovision(b.first, b.count, api);
    }
    if (target != "open5gs") {
        std::cerr << "ksim-sim: --target open5gs or kaluza\n";
        return 2;
    }
    if (!safe_remote_path(db_config) || ssh.empty() || ssh.find_first_of(" ;'\"$`\\") != std::string::npos ||
        ssh.front() == '-' || !std::regex_match(dnn, std::regex("^[A-Za-z0-9.-]{1,63}(,[A-Za-z0-9.-]{1,63}){0,7}$")) ||
        (!sd.empty() && !std::regex_match(sd, std::regex("^[0-9A-Fa-f]{6}$"))) || sst > 255) {
        std::cerr << "ksim-sim: --ssh, --db-config, --dnn, --sst or --sd is not acceptable\n";
        return 2;
    }
    Rig rig{ssh, db_config.rfind("~/", 0) == 0 ? "\"$HOME\"/" + db_config.substr(2) : db_config};
    return prov_cmd->parsed() ? provision(b, master, rig, sst, sd, dnn, replace, pcc_gbr_kbps) : deprovision(b, rig);
}

int main(int argc, char** argv) {
    // An exception that reaches here is a bug: exit 10 (cli.md's internal error).
    try {
        return run_main(argc, argv);
    } catch (const std::exception& e) {
        std::fputs("ksim-sim: internal error: ", stderr);
        std::fputs(e.what(), stderr);
        std::fputs("\n", stderr);
    } catch (...) {
        std::fputs("ksim-sim: internal error\n", stderr);
    }
    return 10;
}
