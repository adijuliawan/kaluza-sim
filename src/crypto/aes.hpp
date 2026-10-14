// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// AES-128 single-block encryption (FIPS 197) through OpenSSL, for MILENAGE
// (TS 35.206), 128-NEA2/NIA2 (TS 33.401 B.1.3, B.2.3) and the ECIES counter mode.
// The OpenSSL context holds the key schedule and wipes it when freed.

#pragma once

#include <array>
#include <cstdint>
#include <memory>

#include "platform/buf.hpp"

typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;

namespace ksim::crypto {

using Block = std::array<std::uint8_t, 16>;

class Aes128 {
public:
    /// key: exactly 16 octets (key material: pass SecretBytes::expose()).
    explicit Aes128(ByteView key);
    ~Aes128();
    Aes128(const Aes128&) = delete;
    Aes128& operator=(const Aes128&) = delete;

    Block encrypt(const Block& in) const;

private:
    EVP_CIPHER_CTX* ctx_;
};

} // namespace ksim::crypto
