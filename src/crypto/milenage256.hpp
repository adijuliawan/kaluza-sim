// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// MILENAGE-256 f1, f1*, f2, f3, f4, f5, f5* and f5** (TS 35.235 §8), over the
// Rijndael-256-256 kernel. Checked against the 25 cases of TS 35.236 §6.3.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "platform/buf.hpp"
#include "platform/result.hpp"
#include "platform/secret.hpp"

namespace ksim::crypto::milenage256 {

/// Parameter sizes in octets (TS 35.235 table 6-1).
struct Sizes {
    std::size_t k = 32;     // 16 or 32
    std::size_t rand = 16;  // 16, 18, .., 32
    std::size_t sqn = 6;    // 6..12
    std::size_t mac = 8;    // 8..32
    std::size_t res = 8;    // 4..32
    std::size_t ck = 16;    // 16..32
    std::size_t ik = 16;    // 16..32
    std::size_t ak = 6;     // 6..12
};

/// The operator constants c0..c7, 16 octets each.
using Constants = std::array<std::array<std::uint8_t, 16>, 8>;

/// The defaults of §8.2.1: c_i zero except c_i[15] = 1 << (i - 1) for i >= 1.
Constants default_constants();

/// "MILENAGE2.0", the ALGONAME for 3GPP use (§8.1).
inline constexpr std::string_view kAlgoName = "MILENAGE2.0";

/// OPc = OP xor PRF_K(PRF_K(OP) xor V) (EQ 1). op: 32 octets.
Result<SecretBytes> opc(const SecretBytes& k, const SecretBytes& op, std::string_view algoname = kAlgoName);

struct Outputs {
    Bytes mac_a;
    Bytes mac_s;
    SecretBytes res;
    SecretBytes ck;
    SecretBytes ik;
    SecretBytes ak;
    SecretBytes ak_star;       // f5*
    SecretBytes ak_star_star;  // f5**, over mac_s
};

/// All eight functions; f5** uses the f1* output of the same call as MAC-S.
Result<Outputs> compute(const SecretBytes& k, const SecretBytes& opc, ByteView rand, ByteView sqn, ByteView amf,
                        const Sizes& sz, const Constants& c);

/// f5** alone, for the network side, which has MAC-S from AUTS.
Result<SecretBytes> f5_star_star(const SecretBytes& k, const SecretBytes& opc, ByteView rand, ByteView mac_s,
                                 const Sizes& sz, const Constants& c);

} // namespace ksim::crypto::milenage256
