// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "crypto/aes.hpp"

#include <openssl/evp.h>

#include <cstdlib>

namespace ksim::crypto {

Aes128::Aes128(ByteView key) : ctx_(EVP_CIPHER_CTX_new()) {
    if (ctx_ == nullptr || key.size() != 16 ||
        EVP_EncryptInit_ex(ctx_, EVP_aes_128_ecb(), nullptr, key.data(), nullptr) != 1 ||
        EVP_CIPHER_CTX_set_padding(ctx_, 0) != 1) {
        // A wrong key length is a programming error, never input from the network.
        std::abort();
    }
}

Aes128::~Aes128() {
    EVP_CIPHER_CTX_free(ctx_);
}

Block Aes128::encrypt(const Block& in) const {
    Block out{};
    int n = 0;
    if (EVP_EncryptUpdate(ctx_, out.data(), &n, in.data(), static_cast<int>(in.size())) != 1 || n != 16) {
        std::abort();
    }
    return out;
}

} // namespace ksim::crypto
