// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// ksim-bench (P2 Q8; plan Q8, Q12): the user plane's per-packet costs, one
// process, no network.
//
//   ksim-bench [--ms N] [--size BYTES] [--check <bounds.tsv>]
//
// Each case runs N ms (default 300) on BYTES-octet packets (default 1400) and prints
// BENCH.<case>.NS=<ns per packet> and BENCH.<case>.MBITS=<Mbit/s of payload>:
//
//   pdcp_drb_nea2        a DRB entity's TX into its peer's RX, 128-NEA2, no integrity
//   pdcp_drb_nea2_nia2   the same with integrity (a DRB with integrityProtection)
//   pdcp_drb_nea1        128-NEA1 (SNOW 3G)
//   pdcp_drb_nea1_nia1   128-NEA1 and 128-NIA1
//   pdcp_drb_null        NEA0, no integrity: the entity's own cost
//   nea2_context         128-NEA2 with the key set once (crypto/as_security.hpp)
//   nea2_oneshot         128-NEA2 setting its key up per packet, as PDCP did before Q8
//   nia2_context         128-NIA2 (CMAC) keyed once
//   nia2_oneshot         128-NIA2 keyed per packet
//   sdap_ul_dl           an SDAP UL mapping with its header, then the DL strip
//   gtpu_n3              a G-PDU with a PDU SESSION INFORMATION frame, encoded and decoded
//   gtpu_nru             a G-PDU with an NR-U DL USER DATA frame, encoded and decoded
//
// --check compares each NS with the bound of its row in the file (case, max_ns,
// why) and prints BENCH=PASS or BENCH=FAIL with the cases over; exit 1 on a FAIL.
// The bounds are a regression guard, generous enough for a loaded CI host.

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "crypto/as_security.hpp"
#include "crypto/nea.hpp"
#include "entity/gtpu/gtpu.hpp"
#include "entity/pdcp/pdcp.hpp"
#include "entity/sdap/sdap.hpp"
#include "platform/secret.hpp"
#include "platform/sim_loop.hpp"

namespace {

using namespace ksim;

struct Timing {
    double ns = 0;
    double mbits = 0;
};

Timing run(int ms, std::size_t size, const std::function<void()>& f) {
    using clock = std::chrono::steady_clock;
    for (int i = 0; i < 256; ++i) {
        f();   // warm-up: caches, allocators
    }
    std::uint64_t n = 0;
    const auto start = clock::now();
    const auto stop = start + std::chrono::milliseconds(ms);
    while (clock::now() < stop) {
        for (int i = 0; i < 64; ++i) {
            f();
        }
        n += 64;
    }
    const double s = std::chrono::duration<double>(clock::now() - start).count();
    Timing r;
    r.ns = s * 1e9 / static_cast<double>(n);
    r.mbits = static_cast<double>(n) * static_cast<double>(size) * 8.0 / s / 1e6;
    return r;
}

SecretBytes key(std::uint8_t seed) {
    Bytes k(16);
    for (std::size_t i = 0; i < k.size(); ++i) {
        k[i] = static_cast<std::uint8_t>(seed + i * 7);
    }
    return SecretBytes::copy_of(k);
}

/// A DRB pair (the UE transmits, the gNB receives) with the given algorithms.
Timing pdcp_case(int ms, std::size_t size, crypto::Nea nea, std::optional<crypto::Nia> nia) {
    SimLoop loop;
    std::size_t delivered = 0;
    Bytes wire;
    entity::PdcpConfig c;
    c.srb = false;
    c.rb_id = 1;
    c.sn_tx = c.sn_rx = pdcp::SnSize::len18;
    c.drb_integrity = nia.has_value();
    entity::Pdcp* rx_ptr = nullptr;
    entity::Pdcp tx(loop, c, [&wire](Bytes b) { wire = std::move(b); }, [](const Bytes&) {});
    c.side = entity::PdcpSide::gnb;
    entity::Pdcp rx(loop, c, [](const Bytes&) {}, [&delivered](const Bytes&) { ++delivered; });
    rx_ptr = &rx;
    const auto ia = nia.value_or(crypto::Nia::nia0);
    if (!tx.set_keys(ia, key(1), nea, key(2)) || !rx.set_keys(ia, key(1), nea, key(2))) {
        std::fprintf(stderr, "ksim-bench: the keys were refused\n");
        std::exit(2);
    }
    tx.set_ciphering(true, true);
    rx.set_ciphering(true, true);
    if (nia) {
        tx.set_integrity(true, true);
        rx.set_integrity(true, true);
    }
    const Bytes sdu(size, 0x5a);
    Timing r = run(ms, size, [&] {
        tx.write_sdu(sdu);
        rx_ptr->on_pdu(wire);
    });
    if (delivered == 0 || rx.stats().integrity_failures != 0) {
        std::fprintf(stderr, "ksim-bench: the PDCP pair delivered nothing or failed integrity\n");
        std::exit(2);
    }
    return r;
}

std::map<std::string, double> load_bounds(const std::string& path) {
    std::map<std::string, double> out;
    std::ifstream in(path);
    for (std::string line; std::getline(in, line);) {
        if (line.empty() || line[0] == '#') {
            continue;
        }
        std::istringstream ss(line);
        std::string name;
        double max = 0;
        if (std::getline(ss, name, '\t') && ss >> max) {
            out[name] = max;
        }
    }
    return out;
}

} // namespace

int main(int argc, char** argv) {
    int ms = 300;
    std::size_t size = 1400;
    std::string check;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--ms") == 0 && i + 1 < argc) {
            ms = std::atoi(argv[++i]);
        } else if (std::strcmp(argv[i], "--size") == 0 && i + 1 < argc) {
            size = static_cast<std::size_t>(std::atol(argv[++i]));
        } else if (std::strcmp(argv[i], "--check") == 0 && i + 1 < argc) {
            check = argv[++i];
        } else {
            std::fprintf(stderr, "usage: ksim-bench [--ms N] [--size BYTES] [--check <bounds.tsv>]\n");
            return 2;
        }
    }
    if (ms < 10 || size < 16 || size > 9000) {
        std::fprintf(stderr, "ksim-bench: --ms 10.. and --size 16..9000\n");
        return 2;
    }

    std::vector<std::pair<std::string, Timing>> results;
    auto add = [&results](const char* name, Timing r) {
        results.emplace_back(name, r);
        std::printf("BENCH.%s.NS=%.0f\nBENCH.%s.MBITS=%.0f\n", name, r.ns, name, r.mbits);
        std::fflush(stdout);
    };
    add("pdcp_drb_nea2", pdcp_case(ms, size, crypto::Nea::nea2, std::nullopt));
    add("pdcp_drb_nea2_nia2", pdcp_case(ms, size, crypto::Nea::nea2, crypto::Nia::nia2));
    add("pdcp_drb_nea1", pdcp_case(ms, size, crypto::Nea::nea1, std::nullopt));
    add("pdcp_drb_nea1_nia1", pdcp_case(ms, size, crypto::Nea::nea1, crypto::Nia::nia1));
    add("pdcp_drb_null", pdcp_case(ms, size, crypto::Nea::nea0, std::nullopt));

    Bytes packet(size, 0xa5);
    const crypto::SecInput in{0x12345678, 3, 1};
    const SecretBytes k = key(9);
    {
        auto c = crypto::NeaContext::make(crypto::Nea::nea2, k);
        add("nea2_context", run(ms, size, [&] { (void)c->apply(in, packet); }));
        add("nea2_oneshot", run(ms, size, [&] { (void)crypto::nea(crypto::Nea::nea2, k, in, packet); }));
    }
    {
        auto c = crypto::NiaContext::make(crypto::Nia::nia2, k);
        add("nia2_context", run(ms, size, [&] { (void)c->mac(in, {packet}); }));
        add("nia2_oneshot", run(ms, size, [&] { (void)crypto::nia(crypto::Nia::nia2, k, in, packet); }));
    }
    {
        entity::Sdap s(1);
        entity::SdapDrb d;
        d.drb_id = 1;
        d.header_ul = d.header_dl = true;
        d.default_drb = true;
        d.qfis = {1};
        s.configure(d);
        const Bytes sdu(size, 0x11);
        add("sdap_ul_dl", run(ms, size, [&] {
            auto ul = s.map_ul(1, sdu);
            if (ul) {
                (void)s.on_dl(1, std::move(ul->pdu));
            }
        }));
    }
    {
        const Bytes payload(size, 0x22);
        add("gtpu_n3", run(ms, size, [&] {
            auto w = entity::gtpu::encode(entity::gtpu::UserData::dl_psc(0x1001, 1, payload));
            if (w) {
                (void)entity::gtpu::decode_gpdu(*w);
            }
        }));
        std::uint32_t sn = 0;
        add("gtpu_nru", run(ms, size, [&] {
            auto w = entity::gtpu::encode(entity::gtpu::UserData::nru(0x2002, sn++, payload));
            if (w) {
                (void)entity::gtpu::decode_gpdu(*w);
            }
        }));
    }

    if (check.empty()) {
        return 0;
    }
    const auto bounds = load_bounds(check);
    if (bounds.empty()) {
        std::printf("BENCH=FAIL (no bounds in %s)\n", check.c_str());
        return 1;
    }
    std::string over;
    for (const auto& [name, r] : results) {
        auto it = bounds.find(name);
        if (it != bounds.end() && r.ns > it->second) {
            char b[160];
            std::snprintf(b, sizeof b, " %s=%.0f>%.0f", name.c_str(), r.ns, it->second);
            over += b;
        }
    }
    if (!over.empty()) {
        std::printf("BENCH=FAIL size=%zu over:%s\n", size, over.c_str());
        return 1;
    }
    std::printf("BENCH=PASS size=%zu cases=%zu bounded=%zu\n", size, results.size(), bounds.size());
    return 0;
}
