// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "platform/secret.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>

namespace ksim {

namespace {

// The fingerprint key: random per process, created on first use.
const std::array<std::uint8_t, 32>& fpr_key() {
    static std::array<std::uint8_t, 32> key{};
    static std::once_flag once;
    std::call_once(once, [] {
        if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1) {
            // Without randomness the fingerprint would be a stable hash of the key;
            // refuse rather than leak that.
            std::abort();
        }
    });
    return key;
}

} // namespace

SecretBytes::SecretBytes(std::size_t n) : p_(n ? new std::uint8_t[n]() : nullptr), n_(n) {}

SecretBytes SecretBytes::copy_of(ByteView v) {
    SecretBytes s(v.size());
    if (!v.empty() && s.p_ != nullptr) {
        std::memcpy(s.p_, v.data(), v.size());
    }
    return s;
}

Result<SecretBytes> SecretBytes::from_hex(std::string_view hex) {
    auto raw = ksim::from_hex(hex);
    if (!raw) {
        return raw.error();
    }
    SecretBytes s = copy_of(*raw);
    OPENSSL_cleanse(raw->data(), raw->size());
    return s;
}

SecretBytes::SecretBytes(SecretBytes&& o) noexcept : p_(o.p_), n_(o.n_) {
    o.p_ = nullptr;
    o.n_ = 0;
}

SecretBytes& SecretBytes::operator=(SecretBytes&& o) noexcept {
    if (this != &o) {
        wipe();
        p_ = o.p_;
        n_ = o.n_;
        o.p_ = nullptr;
        o.n_ = 0;
    }
    return *this;
}

SecretBytes::~SecretBytes() {
    wipe();
}

void SecretBytes::wipe() noexcept {
    if (p_ != nullptr) {
        OPENSSL_cleanse(p_, n_);
        delete[] p_;
        p_ = nullptr;
        n_ = 0;
    }
}

SecretBytes SecretBytes::clone() const {
    return copy_of(expose());
}

std::string SecretBytes::redacted() const {
    std::array<std::uint8_t, EVP_MAX_MD_SIZE> mac{};
    unsigned int mac_len = 0;
    const auto& key = fpr_key();
    static const std::uint8_t kEmpty = 0;
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), p_ != nullptr ? p_ : &kEmpty, n_,
         mac.data(), &mac_len);
    char buf[64];
    std::snprintf(buf, sizeof buf, "<redacted:len=%zu:fpr=%02x%02x%02x%02x>", n_, mac[0], mac[1],
                  mac[2], mac[3]);
    return buf;
}

bool ct_equal(const SecretBytes& a, ByteView b) noexcept {
    if (a.n_ != b.size()) {
        return false;  // lengths are not secret
    }
    return a.n_ == 0 || CRYPTO_memcmp(a.p_, b.data(), a.n_) == 0;
}

bool ct_equal(const SecretBytes& a, const SecretBytes& b) noexcept {
    return ct_equal(a, b.expose());
}

void secure_zero(std::span<std::uint8_t> buf) noexcept {
    if (!buf.empty()) {
        OPENSSL_cleanse(buf.data(), buf.size());
    }
}

} // namespace ksim
