// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The 5G ciphering and integrity algorithms (TS 33.501 Annex D). 128-NEA1/NIA1
// and 128-NEA2/NIA2 are 128-EEA1/EIA1 and 128-EEA2/EIA2 of TS 33.401 Annex B:
//
//  - NEA1: UEA2's f8 over SNOW 3G (SAGE UEA2/UIA2 Document 1 §3), with
//    COUNT-C = COUNT, BEARER and DIRECTION as given (33.401 B.1.2);
//  - NIA1: UIA2's f9 with COUNT-I = COUNT and FRESH = BEARER || 0^27 (33.401 B.2.2);
//  - NEA2: AES-128 in CTR mode from T1 = COUNT || BEARER || DIRECTION || 0^90 (B.1.3);
//  - NIA2: AES-CMAC over COUNT || BEARER || DIRECTION || 0^26 || MESSAGE, the
//    32 most significant bits (B.2.3).
//
// Inputs and outputs are bit strings: `bits` counts the significant bits of
// `data`, left-aligned; output bits past `bits` are zero. 128-NEA3/NIA3 (ZUC)
// are a declared gap (row KS-SEC-G1) and return Errc::unsupported.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "platform/buf.hpp"
#include "platform/result.hpp"
#include "platform/secret.hpp"

namespace ksim::crypto {

enum class Nea : std::uint8_t { nea0 = 0, nea1 = 1, nea2 = 2, nea3 = 3 };
enum class Nia : std::uint8_t { nia0 = 0, nia1 = 1, nia2 = 2, nia3 = 3 };

struct SecInput {
    std::uint32_t count = 0;
    std::uint8_t bearer = 0;     // 5 bits
    std::uint8_t direction = 0;  // 1 bit: 0 uplink, 1 downlink
};

using Mac = std::array<std::uint8_t, 4>;

/// Encrypt or decrypt (the same operation). key: 16 octets (ignored by NEA0).
Result<Bytes> nea(Nea alg, const SecretBytes& key, SecInput in, ByteView data, std::size_t bits);
inline Result<Bytes> nea(Nea alg, const SecretBytes& key, SecInput in, ByteView data) {
    return nea(alg, key, in, data, data.size() * 8);
}

/// The 32-bit MAC-I / NAS-MAC. key: 16 octets (ignored by NIA0, whose MAC is zero).
Result<Mac> nia(Nia alg, const SecretBytes& key, SecInput in, ByteView msg, std::size_t bits);
inline Result<Mac> nia(Nia alg, const SecretBytes& key, SecInput in, ByteView msg) {
    return nia(alg, key, in, msg, msg.size() * 8);
}

/// AES-CMAC (NIST SP 800-38B) over a bit string; the full 128-bit tag.
std::array<std::uint8_t, 16> aes_cmac_bits(const SecretBytes& key, ByteView msg, std::size_t bits);

/// UIA2's f9 with an arbitrary FRESH (SAGE Document 1 §4), which 128-NIA1
/// fixes to BEARER || 0^27. For the SAGE known-answer sets.
Mac uia2_f9(const SecretBytes& ik, std::uint32_t count, std::uint32_t fresh, std::uint8_t direction, ByteView msg,
            std::size_t bits);

} // namespace ksim::crypto
