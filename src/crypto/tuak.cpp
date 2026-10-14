// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// TS 35.231 §6 builds IN bit by bit, each input reversed: IN[0..255] =
// TOP[255..0] and so on. With the state's bit i in octet i / 8 at weight
// 2^(i % 8) (keccak.hpp), a reversed bit string is the same octets in reverse
// order, so each field below is copied octet-reversed into its position, and
// each output is read octet-reversed from its position.

#include "crypto/tuak.hpp"

#include <openssl/crypto.h>

#include "crypto/keccak.hpp"

namespace ksim::crypto::tuak {

namespace {

constexpr char kAlgoName[] = "TUAK1.0";  // ALGONAME, 56 bits (§5.3)

/// Copy v into the state at octet `at`, octet-reversed.
void put_reversed(KeccakState& s, std::size_t at, ByteView v) {
    for (std::size_t i = 0; i < v.size(); ++i) {
        s[at + i] = v[v.size() - 1 - i];
    }
}

/// n octets at octet `at`, octet-reversed.
Bytes get_reversed(const KeccakState& s, std::size_t at, std::size_t n) {
    Bytes out(n);
    for (std::size_t i = 0; i < n; ++i) {
        out[i] = s[at + n - 1 - i];
    }
    return out;
}

SecretBytes get_secret(const KeccakState& s, std::size_t at, std::size_t n) {
    Bytes b = get_reversed(s, at, n);
    SecretBytes out = SecretBytes::copy_of(b);
    OPENSSL_cleanse(b.data(), b.size());
    return out;
}

/// The common frame: TOP/TOPc at 0..31, INSTANCE at 32, ALGONAME at 33..39,
/// K at 64.., then the padding: IN[768..772] = 1 and IN[1087] = 1.
KeccakState frame(ByteView top, std::uint8_t instance, const SecretBytes& k) {
    KeccakState s{};
    put_reversed(s, 0, top);
    s[32] = instance;  // IN[256..263] = INSTANCE[7..0]: INSTANCE[0] is the top bit
    put_reversed(s, 33, ByteView(reinterpret_cast<const std::uint8_t*>(kAlgoName), 7));
    put_reversed(s, 64, k.expose());
    s[96] = 0x1F;
    s[135] = 0x80;
    return s;
}

void permute(KeccakState& s, unsigned iterations) {
    for (unsigned i = 0; i < iterations; ++i) {
        keccak_f1600(s);
    }
}

/// INSTANCE[2..4] for a MAC or RES length: 001 = 64 bits, 010 = 128, 100 = 256
/// (and 000 = 32 for RES).
std::uint8_t length_code(std::size_t octets) {
    switch (octets) {
    case 8: return 1;
    case 16: return 2;
    case 32: return 4;
    default: return 0;
    }
}

Error bad(const char* what) {
    return make_error(Errc::invalid_argument, 0, what);
}

Result<void> check(const Sizes& sz, const SecretBytes& k) {
    if (k.size() != sz.k || (sz.k != 16 && sz.k != 32)) {
        return bad("TUAK: K is 16 or 32 octets");
    }
    if (sz.mac != 8 && sz.mac != 16 && sz.mac != 32) {
        return bad("TUAK: MAC is 8, 16 or 32 octets");
    }
    if (sz.res != 4 && sz.res != 8 && sz.res != 16 && sz.res != 32) {
        return bad("TUAK: RES is 4, 8, 16 or 32 octets");
    }
    if ((sz.ck != 16 && sz.ck != 32) || (sz.ik != 16 && sz.ik != 32)) {
        return bad("TUAK: CK and IK are 16 or 32 octets");
    }
    if (sz.iterations == 0) {
        return bad("TUAK: at least one permutation");
    }
    return {};
}

} // namespace

Result<SecretBytes> topc(const SecretBytes& k, const SecretBytes& top, const Sizes& sz) {
    if (auto ok = check(sz, k); !ok) {
        return ok.error();
    }
    if (top.size() != 32) {
        return bad("TUAK: TOP is 32 octets");
    }
    const std::uint8_t instance = sz.k == 32 ? 0x01 : 0x00;
    KeccakState s = frame(top.expose(), instance, k);
    permute(s, sz.iterations);
    SecretBytes out = get_secret(s, 0, 32);
    OPENSSL_cleanse(s.data(), s.size());
    return out;
}

Result<Outputs> compute(const SecretBytes& k, const SecretBytes& topc_in, ByteView rand, ByteView sqn, ByteView amf,
                        const Sizes& sz) {
    if (auto ok = check(sz, k); !ok) {
        return ok.error();
    }
    if (topc_in.size() != 32 || rand.size() != 16 || sqn.size() != 6 || amf.size() != 2) {
        return bad("TUAK: TOPc 32, RAND 16, SQN 6, AMF 2 octets");
    }
    const std::uint8_t k256 = sz.k == 32 ? 0x01 : 0x00;
    Outputs o;

    // f1 (INSTANCE[0] = 0) and f1* (INSTANCE[0] = 1): RAND, AMF, SQN at 40, 56, 58.
    for (int star = 0; star < 2; ++star) {
        const auto inst = static_cast<std::uint8_t>((star != 0 ? 0x80 : 0x00) | (length_code(sz.mac) << 3) | k256);
        KeccakState s = frame(topc_in.expose(), inst, k);
        put_reversed(s, 40, rand);
        put_reversed(s, 56, amf);
        put_reversed(s, 58, sqn);
        permute(s, sz.iterations);
        (star != 0 ? o.mac_s : o.mac_a) = get_reversed(s, 0, sz.mac);
        OPENSSL_cleanse(s.data(), s.size());
    }

    // f2..f5 (INSTANCE[0..1] = 0,1) in one permutation; f5* (1,1) in another.
    {
        const auto inst = static_cast<std::uint8_t>(0x40 | (length_code(sz.res) << 3) | (sz.ck == 32 ? 0x04 : 0) |
                                                    (sz.ik == 32 ? 0x02 : 0) | k256);
        KeccakState s = frame(topc_in.expose(), inst, k);
        put_reversed(s, 40, rand);
        permute(s, sz.iterations);
        o.res = get_secret(s, 0, sz.res);
        o.ck = get_secret(s, 32, sz.ck);
        o.ik = get_secret(s, 64, sz.ik);
        o.ak = get_secret(s, 96, 6);
        OPENSSL_cleanse(s.data(), s.size());
    }
    {
        KeccakState s = frame(topc_in.expose(), static_cast<std::uint8_t>(0xC0 | k256), k);
        put_reversed(s, 40, rand);
        permute(s, sz.iterations);
        o.ak_star = get_secret(s, 96, 6);
        OPENSSL_cleanse(s.data(), s.size());
    }
    return o;
}

} // namespace ksim::crypto::tuak
