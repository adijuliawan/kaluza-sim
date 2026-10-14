// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// AES-256-GCM (NIST SP 800-38D) for sealed files (P1 N3; sim-uicc.md §7: card
// secrets live in a file sealed under a KEK, never in the card image), and the
// OS random source it takes its nonces from.

#pragma once

#include <cstddef>

#include "platform/buf.hpp"
#include "platform/result.hpp"
#include "platform/secret.hpp"

namespace ksim::crypto::aead {

inline constexpr std::size_t kKeySize = 32;
inline constexpr std::size_t kNonceSize = 12;
inline constexpr std::size_t kTagSize = 16;

/// The ciphertext followed by the 16-octet tag. The key is 32 octets and the
/// nonce 12; a nonce must never repeat under one key.
Result<Bytes> seal(const SecretBytes& key, ByteView nonce, ByteView aad, ByteView plaintext);
/// The plaintext, or Errc::malformed when the tag does not verify (nothing of
/// the plaintext is released then).
Result<SecretBytes> open(const SecretBytes& key, ByteView nonce, ByteView aad, ByteView sealed);

/// `n` octets from the OS's cryptographic random source (RAND_bytes).
Result<Bytes> random_bytes(std::size_t n);

} // namespace ksim::crypto::aead
