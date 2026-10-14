// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The generic key derivation function of TS 33.220 Annex B.2.0, used for every
// 5GC key (TS 33.501 Annex A.1.1):
//
//   S = FC || P0 || L0 || P1 || L1 || ... || Pn || Ln     (Li = 2-octet length of Pi)
//   derived key = HMAC-SHA-256(Key, S)
//
// and the HMAC-SHA-256 / SHA-256 primitives the other derivations use.

#pragma once

#include <cstdint>
#include <initializer_list>

#include "platform/buf.hpp"
#include "platform/secret.hpp"

namespace ksim::crypto {

/// The 256-bit KDF output for key `key`, function code `fc` and parameters P0..Pn.
SecretBytes kdf(ByteView key, std::uint8_t fc, std::initializer_list<ByteView> params);

/// HMAC-SHA-256(key, data): 32 octets.
SecretBytes hmac_sha256(ByteView key, ByteView data);

/// SHA-256(data): 32 octets (not secret by itself; used for HXRES*).
Bytes sha256(ByteView data);

/// The n least significant (rightmost) octets of v.
SecretBytes lsb(const SecretBytes& v, std::size_t n);

} // namespace ksim::crypto
