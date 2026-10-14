// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// EAP-AKA' key derivation (RFC 9048 §3.3, §3.4.1) and the 5G anchor key it
// yields (TS 33.501 6.1.3.1). CK' and IK' come from keys5g::ck_ik_prime().
//
//   MK = PRF'(IK' || CK', "EAP-AKA'" || Identity)
//   K_encr = MK[0..15], K_aut = MK[16..47], K_re = MK[48..79],
//   MSK = MK[80..143], EMSK = MK[144..207]
//   PRF'(K, S) = T1 || T2 || ..., T1 = HMAC-SHA-256(K, S || 0x01),
//                Tn = HMAC-SHA-256(K, Tn-1 || S || n)

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "platform/buf.hpp"
#include "platform/secret.hpp"

namespace ksim::crypto::eap_aka_prime {

struct Keys {
    SecretBytes k_encr;  // 16 octets
    SecretBytes k_aut;   // 32
    SecretBytes k_re;    // 32
    SecretBytes msk;     // 64
    SecretBytes emsk;    // 64
};

/// PRF' output of n octets.
SecretBytes prf_prime(ByteView key, ByteView s, std::size_t n);

/// The keys for an identity (the identity string as sent in EAP-Response/Identity
/// or AT_IDENTITY, without a terminating null).
Keys derive(const SecretBytes& ck_prime, const SecretBytes& ik_prime, std::string_view identity);

/// K_AUSF: the 256 most significant bits of EMSK (TS 33.501 6.1.3.1).
SecretBytes kausf(const Keys& k);

/// AT_MAC: HMAC-SHA-256-128 under K_aut over the whole EAP packet, with the
/// AT_MAC value field zeroed by the caller (RFC 9048 §3.4.1, RFC 4187 10.15).
std::array<std::uint8_t, 16> at_mac(const SecretBytes& k_aut, ByteView packet);

} // namespace ksim::crypto::eap_aka_prime
