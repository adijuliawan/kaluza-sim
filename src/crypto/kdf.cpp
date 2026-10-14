// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "crypto/kdf.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <cstdlib>

namespace ksim::crypto {

SecretBytes hmac_sha256(ByteView key, ByteView data) {
    SecretBytes out(32);
    unsigned int len = 0;
    if (HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(), data.size(),
             out.expose_mut().data(), &len) == nullptr ||
        len != 32) {
        std::abort();
    }
    return out;
}

Bytes sha256(ByteView data) {
    Bytes out(32);
    unsigned int len = 0;
    if (EVP_Digest(data.data(), data.size(), out.data(), &len, EVP_sha256(), nullptr) != 1 || len != 32) {
        std::abort();
    }
    return out;
}

SecretBytes kdf(ByteView key, std::uint8_t fc, std::initializer_list<ByteView> params) {
    Bytes s;
    s.push_back(fc);
    for (ByteView p : params) {
        s.insert(s.end(), p.begin(), p.end());
        s.push_back(static_cast<std::uint8_t>(p.size() >> 8));
        s.push_back(static_cast<std::uint8_t>(p.size()));
    }
    SecretBytes out = hmac_sha256(key, s);
    OPENSSL_cleanse(s.data(), s.size());  // S can carry key material (e.g. SQN xor AK)
    return out;
}

SecretBytes lsb(const SecretBytes& v, std::size_t n) {
    ByteView all = v.expose();
    return SecretBytes::copy_of(all.subspan(all.size() - n, n));
}

} // namespace ksim::crypto
