// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "crypto/aead.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <memory>

namespace ksim::crypto::aead {

namespace {

struct CtxFree {
    void operator()(EVP_CIPHER_CTX* c) const noexcept { EVP_CIPHER_CTX_free(c); }
};
using Ctx = std::unique_ptr<EVP_CIPHER_CTX, CtxFree>;

} // namespace

Result<Bytes> seal(const SecretBytes& key, ByteView nonce, ByteView aad, ByteView plaintext) {
    if (key.size() != kKeySize || nonce.size() != kNonceSize) {
        return make_error(Errc::invalid_argument, 0, "aead: a 32-octet key and a 12-octet nonce");
    }
    Ctx ctx(EVP_CIPHER_CTX_new());
    int len = 0;
    Bytes out(plaintext.size() + kTagSize);
    if (!ctx || EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.expose().data(), nonce.data()) != 1) {
        return make_error(Errc::internal, 0, "aead: cipher setup failed");
    }
    if (!aad.empty() && EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1) {
        return make_error(Errc::internal, 0, "aead: aad failed");
    }
    int total = 0;
    if (!plaintext.empty()) {
        if (EVP_EncryptUpdate(ctx.get(), out.data(), &len, plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
            return make_error(Errc::internal, 0, "aead: encryption failed");
        }
        total = len;
    }
    if (EVP_EncryptFinal_ex(ctx.get(), out.data() + total, &len) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(kTagSize), out.data() + plaintext.size()) != 1) {
        return make_error(Errc::internal, 0, "aead: final failed");
    }
    return out;
}

Result<SecretBytes> open(const SecretBytes& key, ByteView nonce, ByteView aad, ByteView sealed) {
    if (key.size() != kKeySize || nonce.size() != kNonceSize) {
        return make_error(Errc::invalid_argument, 0, "aead: a 32-octet key and a 12-octet nonce");
    }
    if (sealed.size() < kTagSize) {
        return make_error(Errc::truncated, 0, "aead: shorter than the tag");
    }
    const std::size_t n = sealed.size() - kTagSize;
    Ctx ctx(EVP_CIPHER_CTX_new());
    int len = 0;
    SecretBytes out(n);
    if (!ctx || EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.expose().data(), nonce.data()) != 1) {
        return make_error(Errc::internal, 0, "aead: cipher setup failed");
    }
    if (!aad.empty() && EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1) {
        return make_error(Errc::internal, 0, "aead: aad failed");
    }
    int total = 0;
    if (n > 0) {
        if (EVP_DecryptUpdate(ctx.get(), out.expose_mut().data(), &len, sealed.data(), static_cast<int>(n)) != 1) {
            return make_error(Errc::internal, 0, "aead: decryption failed");
        }
        total = len;
    }
    Bytes tag(sealed.begin() + static_cast<std::ptrdiff_t>(n), sealed.end());
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(kTagSize), tag.data()) != 1 ||
        EVP_DecryptFinal_ex(ctx.get(), out.expose_mut().data() + total, &len) != 1) {
        return make_error(Errc::malformed, 0, "aead: the tag does not verify");
    }
    return out;
}

Result<Bytes> random_bytes(std::size_t n) {
    Bytes out(n);
    if (n > 0 && RAND_bytes(out.data(), static_cast<int>(n)) != 1) {
        return make_error(Errc::internal, 0, "aead: RAND_bytes failed");
    }
    return out;
}

} // namespace ksim::crypto::aead
