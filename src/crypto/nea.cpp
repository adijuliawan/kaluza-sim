// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "crypto/nea.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <algorithm>
#include <cstdlib>
#include <vector>

#include "crypto/aes.hpp"
#include "crypto/as_security.hpp"
#include "ocudu/security/s3g.h"  // third_party/ocudu-security: the SNOW 3G kernel and f9

namespace ksim::crypto {

namespace {

Error bad(const char* what) {
    return make_error(Errc::invalid_argument, 0, what);
}

Error zuc_gap() {
    return make_error(Errc::unsupported, 0, "128-NEA3/NIA3 (ZUC): declared gap, row KS-SEC-G1");
}

/// BEARER (5 bits) || DIRECTION (1 bit) || 00, the fifth octet of 128-NEA2's T1 and NIA2's M.
std::uint8_t bearer_direction(SecInput in) {
    return static_cast<std::uint8_t>((unsigned{in.bearer} << 3) | ((unsigned{in.direction} & 1U) << 2));
}

/// The first `bits` bits of data, the rest of the last octet zeroed.
Bytes take_bits(ByteView data, std::size_t bits) {
    Bytes out(data.begin(), data.begin() + static_cast<std::ptrdiff_t>((bits + 7) / 8));
    if (bits % 8 != 0) {
        out.back() &= static_cast<std::uint8_t>(0xFF00U >> (bits % 8));
    }
    return out;
}

using B16 = std::array<std::uint8_t, 16>;

B16 dbl(const B16& in) {
    // Multiply by x in GF(2^128) (SP 800-38B §6.1): shift left, xor 0x87 on carry.
    B16 out{};
    const bool carry = (in[0] & 0x80) != 0;
    for (std::size_t i = 0; i < 16; ++i) {
        out[i] = static_cast<std::uint8_t>((in[i] << 1) | (i + 1 < 16 ? in[i + 1] >> 7 : 0));
    }
    if (carry) {
        out[15] ^= 0x87;
    }
    return out;
}

} // namespace

Mac uia2_f9(const SecretBytes& ik, std::uint32_t count, std::uint32_t fresh, std::uint8_t direction, ByteView msg,
            std::size_t bits) {
    // f9 reads whole 64-bit words; give it a zero-padded copy.
    Bytes buf = take_bits(msg, bits);
    buf.resize((buf.size() + 7) / 8 * 8 + 8, 0);
    ocudu::security::sec_mac mac{};
    ocudu::security::s3g_f9(mac, ik.expose().data(), count, fresh, direction & 1U, buf.data(), bits);
    return {mac[0], mac[1], mac[2], mac[3]};
}

std::array<std::uint8_t, 16> aes_cmac_bits(const SecretBytes& key, ByteView msg, std::size_t bits) {
    const Aes128 aes(key.expose());
    const B16 l = aes.encrypt(B16{});
    B16 k1 = dbl(l);
    B16 k2 = dbl(k1);
    const std::size_t n = bits == 0 ? 1 : (bits + 127) / 128;
    const bool complete = bits != 0 && bits % 128 == 0;
    Bytes m = take_bits(msg, bits);
    m.resize(n * 16, 0);
    if (!complete) {
        m[bits / 8] |= static_cast<std::uint8_t>(0x80U >> (bits % 8));  // the single 1 of the padding
    }
    const B16& sub = complete ? k1 : k2;
    B16 c{};
    for (std::size_t i = 0; i < n; ++i) {
        B16 x{};
        for (std::size_t j = 0; j < 16; ++j) {
            x[j] = static_cast<std::uint8_t>(c[j] ^ m[16 * i + j] ^ (i + 1 == n ? sub[j] : 0));
        }
        c = aes.encrypt(x);
    }
    OPENSSL_cleanse(k1.data(), k1.size());
    OPENSSL_cleanse(k2.data(), k2.size());
    OPENSSL_cleanse(m.data(), m.size());
    return c;
}

Result<Bytes> nea(Nea alg, const SecretBytes& key, SecInput in, ByteView data, std::size_t bits) {
    if (bits > data.size() * 8) {
        return bad("NEA: bit length exceeds the data");
    }
    if (in.bearer > 31) {
        return bad("NEA: BEARER is five bits");
    }
    // P2 Q8: through the context the PDCP entities keep, so the known-answer sets check it.
    auto c = NeaContext::make(alg, key);
    if (!c) {
        return c.error();
    }
    Bytes out = take_bits(data, bits);
    if (auto r = c->apply(in, out, bits); !r) {
        return r.error();
    }
    return out;
}

Result<Mac> nia(Nia alg, const SecretBytes& key, SecInput in, ByteView msg, std::size_t bits) {
    if (bits > msg.size() * 8) {
        return bad("NIA: bit length exceeds the message");
    }
    if (in.bearer > 31) {
        return bad("NIA: BEARER is five bits");
    }
    switch (alg) {
    case Nia::nia0:
        return Mac{};
    case Nia::nia1:
    case Nia::nia2:
        if (key.size() != 16) {
            return bad("NIA: the key is 16 octets");
        }
        if (alg == Nia::nia1 && bits == 0) {
            // SNOW 3G f9 is defined for one bit or more; the vendored s3g_f9
            // reads past the message for an empty one (KS-SEC-D1)
            return bad("NIA1: the message is at least one bit");
        }
        if (bits % 8 == 0) {
            // P2 Q8: whole octets through the context the PDCP entities keep.
            auto c = NiaContext::make(alg, key);
            if (!c) {
                return c.error();
            }
            return c->mac(in, {msg.first(bits / 8)});
        }
        if (alg == Nia::nia1) {
            return uia2_f9(key, in.count, std::uint32_t{in.bearer} << 27, in.direction, msg, bits);  // 33.401 B.2.2
        } else {
            // M = COUNT || BEARER || DIRECTION || 0^26 || MESSAGE
            Bytes m = {static_cast<std::uint8_t>(in.count >> 24), static_cast<std::uint8_t>(in.count >> 16),
                       static_cast<std::uint8_t>(in.count >> 8), static_cast<std::uint8_t>(in.count),
                       bearer_direction(in), 0, 0, 0};
            const Bytes body = take_bits(msg, bits);
            m.insert(m.end(), body.begin(), body.end());
            const auto t = aes_cmac_bits(key, m, 64 + bits);
            return Mac{t[0], t[1], t[2], t[3]};
        }
    case Nia::nia3:
        return zuc_gap();
    }
    return bad("NIA: unknown algorithm");
}

} // namespace ksim::crypto
