// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "crypto/eap_aka_prime.hpp"

#include <openssl/crypto.h>

#include <algorithm>

#include "crypto/kdf.hpp"

namespace ksim::crypto::eap_aka_prime {

SecretBytes prf_prime(ByteView key, ByteView s, std::size_t n) {
    SecretBytes out(n);
    auto dst = out.expose_mut();
    Bytes t;  // T(i-1)
    std::size_t done = 0;
    for (unsigned i = 1; done < n; ++i) {
        Bytes in = t;
        in.insert(in.end(), s.begin(), s.end());
        in.push_back(static_cast<std::uint8_t>(i));
        const SecretBytes ti = hmac_sha256(key, in);
        OPENSSL_cleanse(in.data(), in.size());
        OPENSSL_cleanse(t.data(), t.size());
        t.assign(ti.expose().begin(), ti.expose().end());
        for (std::size_t j = 0; j < t.size() && done < n; ++j) {
            dst[done++] = t[j];
        }
    }
    OPENSSL_cleanse(t.data(), t.size());
    return out;
}

Keys derive(const SecretBytes& ck_prime, const SecretBytes& ik_prime, std::string_view identity) {
    SecretBytes key(ik_prime.size() + ck_prime.size());
    std::copy(ik_prime.expose().begin(), ik_prime.expose().end(), key.expose_mut().begin());
    std::copy(ck_prime.expose().begin(), ck_prime.expose().end(),
              key.expose_mut().begin() + static_cast<std::ptrdiff_t>(ik_prime.size()));
    static constexpr std::string_view kLabel = "EAP-AKA'";
    Bytes s(kLabel.begin(), kLabel.end());
    s.insert(s.end(), identity.begin(), identity.end());
    const SecretBytes mk = prf_prime(key.expose(), s, 208);
    const ByteView m = mk.expose();
    return {SecretBytes::copy_of(m.subspan(0, 16)), SecretBytes::copy_of(m.subspan(16, 32)),
            SecretBytes::copy_of(m.subspan(48, 32)), SecretBytes::copy_of(m.subspan(80, 64)),
            SecretBytes::copy_of(m.subspan(144, 64))};
}

SecretBytes kausf(const Keys& k) {
    return SecretBytes::copy_of(k.emsk.expose().first(32));
}

std::array<std::uint8_t, 16> at_mac(const SecretBytes& k_aut, ByteView packet) {
    const SecretBytes h = hmac_sha256(k_aut.expose(), packet);
    std::array<std::uint8_t, 16> out{};
    std::copy_n(h.expose().begin(), 16, out.begin());
    return out;
}

} // namespace ksim::crypto::eap_aka_prime
