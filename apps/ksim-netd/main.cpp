// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// ksim-netd: kaluza-sim's privileged helper (P1 N9; ADR 0009 point 3), a
// systemd service (tools/systemd/ksim-netd.service). It serves one uid; on
// kaluza-uesim it may make ipvlans on the configured parent with addresses
// from the configured range, anywhere else no parent link at all.
//
//   ksim-netd --uid <uid> [--socket /run/ksim/netd.sock]
//             [--parent ens19 --range 172.30.30.30-172.30.30.39 --prefix 24]
//             [--mid 10.250.0.0/24] [--dn 10.60.0.0/24]
//
// A parent is refused unless the host is kaluza-uesim (ADR 0009 point 11), and
// so is --mid (P2 Q6: the ksim-mid bridge and veth legs; a veth on the dev PC
// flaps its VMware guests, kaluza-core P-64). --dn allows DN namespaces whose
// TUN carries an address of that network (both hosts).

#include <CLI/CLI.hpp>

#include <unistd.h>

#include <csignal>
#include <cstdio>
#include <exception>
#include <iostream>

#include "net/netd.hpp"
#include "platform/transport.hpp"

namespace {

volatile int g_stop = 0;

extern "C" void on_signal(int) { g_stop = 1; }

bool parse_v4(const std::string& s, std::array<std::uint8_t, 4>& out) {
    auto e = ksim::Endpoint::parse(s, 0);
    if (!e || e->family != ksim::Endpoint::Family::v4) {
        return false;
    }
    std::copy(e->addr.begin(), e->addr.begin() + 4, out.begin());
    return true;
}

/// "10.250.0.0/24": the network's host addresses (first, last) and the length.
bool parse_net(const std::string& s, std::array<std::uint8_t, 4>& first, std::array<std::uint8_t, 4>& last,
               std::uint8_t& len) {
    const auto slash = s.find('/');
    std::array<std::uint8_t, 4> a{};
    if (slash == std::string::npos || !parse_v4(s.substr(0, slash), a)) {
        return false;
    }
    int n = -1;
    try {
        n = std::stoi(s.substr(slash + 1));
    } catch (const std::exception&) {
        return false;
    }
    if (n < 8 || n > 30) {
        return false;
    }
    const std::uint32_t v = static_cast<std::uint32_t>(a[0]) << 24 | static_cast<std::uint32_t>(a[1]) << 16 |
                            static_cast<std::uint32_t>(a[2]) << 8 | a[3];
    const std::uint32_t mask = ~std::uint32_t{0} << (32 - n);
    const std::uint32_t lo = (v & mask) + 1;
    const std::uint32_t hi = (v | ~mask) - 1;
    for (int i = 0; i < 4; ++i) {
        first[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(lo >> (24 - 8 * i));
        last[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(hi >> (24 - 8 * i));
    }
    len = static_cast<std::uint8_t>(n);
    return true;
}

std::string host() {
    std::array<char, 256> b{};
    return ::gethostname(b.data(), b.size() - 1) == 0 ? std::string(b.data()) : std::string();
}

int run_main(int argc, char** argv) {
    CLI::App app{"ksim-netd: kaluza-sim's privileged helper"};
    unsigned uid = 0;
    std::string socket = ksim::net::netd::kSocketPath;
    std::string parent;
    std::string range;
    unsigned prefix = 24;
    app.add_option("--uid", uid, "the only uid served")->required();
    app.add_option("--socket", socket, "the socket");
    app.add_option("--parent", parent, "the parent link for ipvlans (kaluza-uesim only)");
    app.add_option("--range", range, "the addresses allowed: first-last");
    app.add_option("--prefix", prefix, "the prefix length of those addresses");
    std::string mid;
    std::string dn;
    app.add_option("--mid", mid, "the ksim-mid network for node legs, e.g. 10.250.0.0/24 (kaluza-uesim only)");
    app.add_option("--dn", dn, "the network DN namespaces' TUNs take addresses from, e.g. 10.60.0.0/24");
    CLI11_PARSE(app, argc, argv);

    ksim::net::netd::Policy p;
    p.uid = uid;
    if (!parent.empty()) {
        if (host() != "kaluza-uesim") {
            std::cerr << "ksim-netd: refused: a parent link only on kaluza-uesim (ADR 0009 point 11)\n";
            return 7;
        }
        const auto dash = range.find('-');
        if (dash == std::string::npos || !parse_v4(range.substr(0, dash), p.first) ||
            !parse_v4(range.substr(dash + 1), p.last) || prefix > 32) {
            std::cerr << "ksim-netd: --parent needs --range first-last and --prefix\n";
            return 2;
        }
        p.parent = parent;
        p.prefix = static_cast<std::uint8_t>(prefix);
    }
    if (!mid.empty()) {
        if (host() != "kaluza-uesim") {
            std::cerr << "ksim-netd: refused: ksim-mid only on kaluza-uesim (P-64: no bridge or veth on the dev PC)\n";
            return 7;
        }
        if (!parse_net(mid, p.mid_first, p.mid_last, p.mid_prefix)) {
            std::cerr << "ksim-netd: --mid is a network, e.g. 10.250.0.0/24\n";
            return 2;
        }
        p.mid = true;
    }
    if (!dn.empty()) {
        std::uint8_t dn_len = 0;
        if (!parse_net(dn, p.dn_first, p.dn_last, dn_len)) {
            std::cerr << "ksim-netd: --dn is a network, e.g. 10.60.0.0/24\n";
            return 2;
        }
        p.dn = true;
    }
    if (::geteuid() != 0) {
        std::cerr << "ksim-netd: not root: every operation will fail\n";
    }
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    std::signal(SIGPIPE, SIG_IGN);
    ksim::net::netd::LinuxOps ops;
    ksim::net::netd::Server server(p, ops);
    std::cerr << "ksim-netd: serving uid " << uid << " on " << socket << (p.parent.empty() ? " (no parent link)" : " (parent " + p.parent + ")")
              << (p.mid ? ", ksim-mid " + mid : std::string()) << (p.dn ? ", DN " + dn : std::string()) << "\n";
    if (auto r = ksim::net::netd::run_server(socket, server, g_stop); !r) {
        std::cerr << "ksim-netd: " << r.error().what << "\n";
        return 1;
    }
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    // An exception that reaches here is a bug: exit 10 (cli.md's internal error).
    try {
        return run_main(argc, argv);
    } catch (const std::exception& e) {
        std::fputs("ksim-netd: internal error: ", stderr);
        std::fputs(e.what(), stderr);
        std::fputs("\n", stderr);
    } catch (...) {
        std::fputs("ksim-netd: internal error\n", stderr);
    }
    return 10;
}
