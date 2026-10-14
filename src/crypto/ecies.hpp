// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// SUPI concealment (TS 33.501 Annex C): the null scheme and ECIES Profiles A
// (X25519) and B (secp256r1, compressed points). The scheme output is the
// ephemeral public key || ciphertext || MAC tag (C.3.2), with
//
//   K = ANSI-X9.63-KDF(SHA-256, Z, SharedInfo1 = ephemeral public key), 64 octets
//   EK = K[0..15], ICB = K[16..31], MK = K[32..63]
//   ciphertext = AES-128-CTR(EK, ICB; 32-bit counter increment, C.3.4.0)
//   tag = the first 8 octets of HMAC-SHA-256(MK, ciphertext)

#pragma once

#include <cstdint>
#include <string_view>

#include "platform/buf.hpp"
#include "platform/result.hpp"
#include "platform/secret.hpp"

namespace ksim::crypto::ecies {

/// Protection scheme identifiers (TS 24.501 9.11.3.4, TS 33.501 C.1).
enum class Scheme : std::uint8_t { null = 0, profile_a = 1, profile_b = 2 };

/// The scheme input for an IMSI-type SUPI: the MSIN in packed BCD, first digit
/// in the low nibble, an odd count padded with 0xF (C.3.1).
Result<Bytes> msin_bcd(std::string_view msin);

/// The UE side. hn_public_key: 32 octets (A) or 33 compressed (B). The
/// ephemeral private key is fresh from the OpenSSL DRBG unless one is given
/// (known-answer tests).
Result<Bytes> conceal(Scheme scheme, ByteView hn_public_key, ByteView scheme_input,
                      const SecretBytes* ephemeral_private_key = nullptr);

/// The home network side (for tests and harnesses): the scheme input back,
/// or an error if the MAC tag does not verify.
Result<Bytes> deconceal(Scheme scheme, const SecretBytes& hn_private_key, ByteView scheme_output);

/// The public key for a private key: 32 octets (A) or 33 compressed (B).
Result<Bytes> public_key(Scheme scheme, const SecretBytes& private_key);

} // namespace ksim::crypto::ecies
