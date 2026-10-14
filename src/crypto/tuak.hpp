// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// TUAK f1, f1*, f2, f3, f4, f5, f5* and the TOPc derivation (TS 35.231 §6),
// over Keccak-f[1600]. Checked against the six sets of TS 35.233 §6.

#pragma once

#include <cstddef>

#include "platform/buf.hpp"
#include "platform/result.hpp"
#include "platform/secret.hpp"

namespace ksim::crypto::tuak {

/// Parameter lengths in octets (TS 35.231 §5.1). For 3GPP use (§7.2): K 16,
/// MAC 8, RES 4..16, CK 16, IK 16.
struct Sizes {
    std::size_t k = 16;    // 16 or 32
    std::size_t mac = 8;   // 8, 16 or 32
    std::size_t res = 8;   // 4, 8, 16 or 32
    std::size_t ck = 16;   // 16 or 32
    std::size_t ik = 16;   // 16 or 32
    unsigned iterations = 1;  // applications of the permutation (§7.2)
};

struct Outputs {
    Bytes mac_a;
    Bytes mac_s;
    SecretBytes res;
    SecretBytes ck;
    SecretBytes ik;
    SecretBytes ak;       // 6 octets
    SecretBytes ak_star;  // 6 octets
};

/// TOPc from TOP (32 octets) and K (§6.1).
Result<SecretBytes> topc(const SecretBytes& k, const SecretBytes& top, const Sizes& sz);

/// All seven functions. rand 16, sqn 6, amf 2 octets.
Result<Outputs> compute(const SecretBytes& k, const SecretBytes& topc, ByteView rand, ByteView sqn, ByteView amf,
                        const Sizes& sz);

} // namespace ksim::crypto::tuak
