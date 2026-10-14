// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// ksim-selftest (plan M16): the build identity as KEY=value lines (cli.md
// output style), then the self-checks a deployed binary can run on its own,
// with no network and no files: the KATs of spec/kat embedded at build time
// (MILENAGE, TUAK, 128-EEA2, 128-EEA1, 128-EIA2, 128-EIA1), the committed
// corpus (NGAP, NAS, GTP-U, PSC, NR-U) decoded and re-encoded byte for byte,
// and a micro-benchmark of the crypto and codec paths. Exit 0 when every
// check passes.
//
//   ksim-selftest [--version] [--bench-ms N]

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#include "codec/asn1/asn1.hpp"
#include "codec/asn1/registry.hpp"
#include "codec/nas/nas.hpp"
#include "codec/up/frames.hpp"
#include "codec/up/gtpu.hpp"
#include "crypto/milenage.hpp"
#include "crypto/nea.hpp"
#include "crypto/tuak.hpp"
#include "ksim/build_info.hpp"
#include "platform/buf.hpp"
#include "platform/secret.hpp"
#include "selftest_data.hpp"

namespace {

using namespace ksim;
using namespace ksim::crypto;

void print_identity() {
    std::printf("KSIM_VERSION=%s\n", build::kVersion);
    std::printf("COMMIT=%s\n", build::kGitDescribe);
    std::printf("BUILD_TYPE=%s\n", build::kBuildType);
    std::printf("SANITIZE=%s\n", build::kSanitize);
    std::printf("ARCH_FLAGS=%s\n", build::kArchFlags);
    std::printf("CXX=%s\n", build::kCxxCompiler);
    std::printf("CONFIGURED_UTC=%s\n", build::kConfigureUtc);
}

// ---- KAT files (spec/kat, one row per set and field) ----------------------------------

using Set = std::map<std::string, std::string>;   // field -> hex (or the bit length / text)

std::map<std::string, Set> parse(std::string_view tsv) {
    std::map<std::string, Set> sets;
    std::size_t pos = 0;
    bool header = true;
    while (pos < tsv.size()) {
        const std::size_t end = tsv.find('\n', pos);
        const std::string_view line = tsv.substr(pos, end == std::string_view::npos ? std::string_view::npos : end - pos);
        pos = end == std::string_view::npos ? tsv.size() : end + 1;
        if (line.empty() || line[0] == '#') {
            continue;
        }
        if (header) {   // set field hex bits text clause
            header = false;
            continue;
        }
        std::vector<std::string_view> cols;
        for (std::size_t a = 0, b; a <= line.size(); a = b + 1) {
            b = line.find('\t', a);
            if (b == std::string_view::npos) {
                b = line.size();
            }
            cols.push_back(line.substr(a, b - a));
        }
        if (cols.size() < 5) {
            continue;
        }
        std::string value(cols[2].empty() ? (cols[3].empty() ? cols[4] : cols[3]) : cols[2]);
        sets[std::string(cols[0])][std::string(cols[1])] = value;
    }
    return sets;
}

Bytes bytes(const Set& s, const std::string& f) {
    auto it = s.find(f);
    if (it == s.end()) {
        return {};
    }
    std::string h = it->second;
    if (h.size() % 2 != 0) {
        h += '0';
    }
    auto r = from_hex(h);
    return r ? *r : Bytes{};
}

std::uint64_t num(const Set& s, const std::string& f) {
    auto it = s.find(f);
    return it == s.end() ? 0 : std::strtoull(it->second.c_str(), nullptr, 16);   // numbers are hex, as in kat_file.hpp
}

std::string hex(const SecretBytes& b) {
    return to_hex(b.expose());   // a spec vector's own key, compared with the spec's value
}

Bytes first_bits(Bytes b, std::size_t bits) {
    b.resize((bits + 7) / 8);
    if (bits % 8 != 0 && !b.empty()) {
        b.back() = static_cast<std::uint8_t>(b.back() & (0xFF << (8 - bits % 8)));
    }
    return b;
}

struct Tally {
    int checks = 0;
    int failed = 0;
    void check(bool ok, const char* what, const std::string& set) {
        ++checks;
        if (!ok) {
            ++failed;
            std::printf("FAIL %s set %s\n", what, set.c_str());
        }
    }
};

void kats(Tally& t) {
    for (const auto& [name, s] : parse(selftest::kat("milenage"))) {
        const SecretBytes k = SecretBytes::copy_of(bytes(s, "K"));
        auto opc = milenage::opc(k, SecretBytes::copy_of(bytes(s, "OP")));
        auto o = opc ? milenage::compute(k, *opc, bytes(s, "RAND"), bytes(s, "SQN"), bytes(s, "AMF"))
                     : Result<milenage::Outputs>(opc.error());
        t.check(opc && o && to_hex(o->mac_a) == s.at("f1") && to_hex(o->mac_s) == s.at("f1*") &&
                    hex(o->res) == s.at("f2") && hex(o->ck) == s.at("f3") && hex(o->ik) == s.at("f4") &&
                    hex(o->ak) == s.at("f5") && hex(o->ak_star) == s.at("f5*"),
                "MILENAGE (35.208)", name);
    }
    for (const auto& [name, s] : parse(selftest::kat("tuak"))) {
        tuak::Sizes sz;
        sz.k = num(s, "Klength") / 8;
        sz.mac = num(s, "MAClength") / 8;
        sz.res = num(s, "RESLength") / 8;
        sz.ck = num(s, "CKlength") / 8;
        sz.ik = num(s, "IKlength") / 8;
        sz.iterations = static_cast<unsigned>(num(s, "KeccakIterations"));
        const SecretBytes k = SecretBytes::copy_of(bytes(s, "K"));
        auto topc = tuak::topc(k, SecretBytes::copy_of(bytes(s, "TOP")), sz);
        auto o = topc ? tuak::compute(k, *topc, bytes(s, "RAND"), bytes(s, "SQN"), bytes(s, "AMF"), sz)
                      : Result<tuak::Outputs>(topc.error());
        t.check(topc && o && to_hex(o->mac_a) == s.at("f1") && hex(o->res) == s.at("f2") && hex(o->ck) == s.at("f3") &&
                    hex(o->ik) == s.at("f4"),
                "TUAK (35.233)", name);
    }
    for (const auto& [name, s] : parse(selftest::kat("eea2"))) {
        const std::size_t bits = num(s, "Length");
        const SecInput in{static_cast<std::uint32_t>(num(s, "Count")), static_cast<std::uint8_t>(num(s, "Bearer")),
                          static_cast<std::uint8_t>(num(s, "Direction"))};
        auto c = nea(Nea::nea2, SecretBytes::copy_of(bytes(s, "Key")), in, bytes(s, "Plaintext"), bits);
        t.check(c && to_hex(*c) == to_hex(first_bits(bytes(s, "Ciphertext"), bits)), "128-EEA2 (33.401 C.1)", name);
    }
    for (const auto& [name, s] : parse(selftest::kat("uea2"))) {
        const std::size_t bits = num(s, "Length");
        const SecInput in{static_cast<std::uint32_t>(num(s, "Count-C")), static_cast<std::uint8_t>(num(s, "Bearer")),
                          static_cast<std::uint8_t>(num(s, "Direction"))};
        auto c = nea(Nea::nea1, SecretBytes::copy_of(bytes(s, "CK")), in, bytes(s, "Plaintext"), bits);
        t.check(c && to_hex(*c) == to_hex(first_bits(bytes(s, "Ciphertext"), bits)), "128-EEA1 (UEA2 SAGE)", name);
    }
    for (const auto& [alg, file, what] : {std::tuple{Nia::nia2, "eia2", "128-EIA2 (33.401 C.2)"},
                                          std::tuple{Nia::nia1, "eia1", "128-EIA1 (33.401 C.4)"}}) {
        for (const auto& [name, s] : parse(selftest::kat(file))) {
            const SecInput in{static_cast<std::uint32_t>(num(s, "Count-I")), static_cast<std::uint8_t>(num(s, "Bearer")),
                              static_cast<std::uint8_t>(num(s, "Direction"))};
            auto m = nia(alg, SecretBytes::copy_of(bytes(s, "IK")), in, bytes(s, "Message"), num(s, "Length"));
            t.check(m && to_hex(ByteView(m->data(), m->size())) == s.at("MACT"), what, name);
        }
    }
}

// ---- the corpus -----------------------------------------------------------------------

void codecs(Tally& t) {
    for (const auto& v : selftest::vectors()) {
        const auto in = from_hex(v.hex).value();
        bool ok = false;
        const std::string_view proto = v.proto;
        if (proto == "nas") {
            if (nas::is_protected(in)) {
                auto p = nas::decode_protected(in);
                ok = p && nas::encode_protected(*p) == in;
            } else {
                auto m = nas::decode(in);
                auto again = m ? nas::encode(*m) : Result<Bytes>(m.error());
                ok = again && *again == in;
            }
        } else if (proto == "gtpu") {
            auto p = gtpu::decode(in);
            auto again = p ? gtpu::encode(*p) : Result<Bytes>(p.error());
            ok = again && *again == in;
        } else if (proto == "psc" || proto == "nru") {
            auto f = up::decode(proto == "psc" ? up::Protocol::psc : up::Protocol::nru, in);
            auto again = f ? up::encode(*f) : Result<Bytes>(f.error());
            ok = again && *again == in;
        } else {
            const auto* td = asn1::find_type(proto, v.type);
            const auto rules = asn1::rules_for(proto);
            auto d = td != nullptr ? asn1::decode(*td, rules, in) : Result<asn1::Owned<>>(Error{Errc::internal, 0, "type"});
            auto again = d ? asn1::encode(*d, rules, asn1::Check::relay) : Result<Bytes>(d.error());
            ok = again && *again == in;
        }
        t.check(ok, v.proto, v.id);
    }
}

// ---- micro-benchmark ------------------------------------------------------------------

template <class F>
void bench(const char* key, const char* unit, double per_op_units, int ms, F&& f) {
    using clock = std::chrono::steady_clock;
    const auto stop = clock::now() + std::chrono::milliseconds(ms);
    std::uint64_t n = 0;
    const auto start = clock::now();
    while (clock::now() < stop) {
        for (int i = 0; i < 64; ++i) {
            f();
        }
        n += 64;
    }
    const double s = std::chrono::duration<double>(clock::now() - start).count();
    std::printf("%s=%.0f %s\n", key, static_cast<double>(n) * per_op_units / s, unit);
}

/// Returns the number of benchmark inputs that did not decode (a failure).
int benchmarks(int ms) {
    int failed = 0;
    const auto k = SecretBytes::from_hex("465b5ce8b199b49faa5f0a2ee238a6bc").value();
    const auto opc = SecretBytes::from_hex("cd63cb71954a9f4e48a5994e37a02baf").value();
    const Bytes rand = from_hex("23553cbe9637a89d218ae64dae47bf35").value();
    const Bytes sqn = from_hex("ff9bb4d0b607").value();
    const Bytes amf = from_hex("b9b9").value();
    bench("BENCH_MILENAGE", "ops/s", 1.0, ms, [&] { (void)milenage::compute(k, opc, rand, sqn, amf); });
    const Bytes packet(1500, 0x5a);
    const SecInput in{7, 1, 1};
    bench("BENCH_NIA2_1500", "Mbit/s", 1500.0 * 8 / 1e6, ms, [&] { (void)nia(Nia::nia2, k, in, packet, packet.size() * 8); });
    bench("BENCH_NEA2_1500", "Mbit/s", 1500.0 * 8 / 1e6, ms, [&] { (void)nea(Nea::nea2, k, in, packet, packet.size() * 8); });
    for (const auto& v : selftest::vectors()) {
        const std::string_view proto = v.proto;
        if (proto == "ngap") {
            const auto bytes = from_hex(v.hex).value();
            const auto* td = asn1::find_type("ngap", v.type);
            const auto rules = asn1::rules_for("ngap");
            if (td == nullptr || !asn1::decode(*td, rules, bytes)) {
                std::printf("BENCH_NGAP=FAIL (%s does not decode)\n", v.id);
                ++failed;
                break;
            }
            std::printf("BENCH_NGAP_PDU=%s (%zu octets)\n", v.id, bytes.size());
            bench("BENCH_NGAP_DECODE_ENCODE", "PDUs/s", 1.0, ms, [&] {
                auto d = asn1::decode(*td, rules, bytes);
                (void)asn1::encode(*d, rules, asn1::Check::relay);
            });
            break;
        }
    }
    // a REGISTRATION REQUEST with 5GMM capability and UE security capability
    const Bytes reg = from_hex("7e004179000d0100f110000000000000000001" "100107" "2e0480e0e0e0").value();
    if (nas::decode(reg)) {
        bench("BENCH_NAS_DECODE_ENCODE", "messages/s", 1.0, ms, [&] {
            auto m = nas::decode(reg);
            (void)nas::encode(*m);
        });
    } else {
        std::printf("BENCH_NAS=FAIL\n");
        ++failed;
    }
    // a G-PDU with a PDU Session Container (DL, QFI 9) and an 8-octet T-PDU
    const Bytes gpdu = from_hex("34ff001000000001" "00000085" "01000900" "4500001c00000000").value();
    if (gtpu::decode(gpdu)) {
        bench("BENCH_GTPU_DECODE_ENCODE", "PDUs/s", 1.0, ms, [&] {
            auto p = gtpu::decode(gpdu);
            (void)gtpu::encode(*p);
        });
    } else {
        std::printf("BENCH_GTPU=FAIL\n");
        ++failed;
    }
    return failed;
}

} // namespace

int main(int argc, char** argv) {
    print_identity();
    int bench_ms = 300;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--version") == 0) {
            return 0;
        }
        if (std::strcmp(argv[i], "--bench-ms") == 0 && i + 1 < argc) {
            bench_ms = std::atoi(argv[++i]);
        }
    }
    Tally kat;
    kats(kat);
    std::printf("KAT_CHECKS=%d\nKAT_FAILED=%d\n", kat.checks, kat.failed);
    Tally codec;
    codecs(codec);
    std::printf("CODEC_CHECKS=%d\nCODEC_FAILED=%d\n", codec.checks, codec.failed);
    std::fflush(stdout);
    const int bench_failed = benchmarks(bench_ms);
    const int failed = kat.failed + codec.failed + bench_failed;
    std::printf("CHECKS=%d\nFAILED=%d\nSELFTEST=%s\n", kat.checks + codec.checks, failed, failed == 0 ? "PASS" : "FAIL");
    return failed == 0 ? 0 : 1;
}
