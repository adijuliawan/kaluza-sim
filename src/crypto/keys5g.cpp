// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "crypto/keys5g.hpp"

#include <openssl/crypto.h>

#include <algorithm>
#include <array>

#include "crypto/kdf.hpp"

namespace ksim::crypto::keys5g {

namespace {

ByteView text(std::string_view s) {
    return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
}

/// CK || IK, the KEY of A.2, A.4 and 33.402 A.2.
SecretBytes ck_ik(const SecretBytes& ck, const SecretBytes& ik) {
    SecretBytes key(ck.size() + ik.size());
    auto out = key.expose_mut();
    auto a = ck.expose();
    auto b = ik.expose();
    std::copy(a.begin(), a.end(), out.begin());
    std::copy(b.begin(), b.end(), out.begin() + static_cast<std::ptrdiff_t>(a.size()));
    return key;
}

template <std::size_t N>
std::array<std::uint8_t, N> be(std::uint64_t v) {
    std::array<std::uint8_t, N> a{};
    for (std::size_t i = 0; i < N; ++i) {
        a[N - 1 - i] = static_cast<std::uint8_t>(v >> (8 * i));
    }
    return a;
}

bool all_digits(std::string_view s) {
    if (s.empty()) {
        return false;
    }
    for (char c : s) {
        if (c < '0' || c > '9') {
            return false;
        }
    }
    return true;
}

} // namespace

Result<std::string> serving_network_name(std::string_view mcc, std::string_view mnc) {
    if (mcc.size() != 3 || !all_digits(mcc) || (mnc.size() != 2 && mnc.size() != 3) || !all_digits(mnc)) {
        return make_error(Errc::invalid_argument, 0, "SNN: MCC is 3 digits, MNC 2 or 3");
    }
    std::string s = "5G:mnc";
    if (mnc.size() == 2) {
        s += '0';
    }
    s += mnc;
    s += ".mcc";
    s += mcc;
    s += ".3gppnetwork.org";
    return s;
}

SecretBytes kausf(const SecretBytes& ck, const SecretBytes& ik, std::string_view snn, ByteView sqn_xor_ak) {
    const SecretBytes key = ck_ik(ck, ik);
    return kdf(key.expose(), 0x6A, {text(snn), sqn_xor_ak});
}

SecretBytes res_star(const SecretBytes& ck, const SecretBytes& ik, std::string_view snn, ByteView rand,
                     const SecretBytes& res) {
    const SecretBytes key = ck_ik(ck, ik);
    const SecretBytes out = kdf(key.expose(), 0x6B, {text(snn), rand, res.expose()});
    return lsb(out, 16);
}

Bytes hres_star(ByteView rand, const SecretBytes& res_star) {
    Bytes s(rand.begin(), rand.end());
    auto r = res_star.expose();
    s.insert(s.end(), r.begin(), r.end());
    Bytes h = sha256(s);
    OPENSSL_cleanse(s.data(), s.size());
    return Bytes(h.end() - 16, h.end());
}

SecretBytes kseaf(const SecretBytes& kausf, std::string_view snn) {
    return kdf(kausf.expose(), 0x6C, {text(snn)});
}

Result<SecretBytes> kamf(const SecretBytes& kseaf, std::string_view supi, ByteView abba) {
    for (std::string_view prefix : {"imsi-", "nai-", "gci-", "gli-"}) {
        if (supi.starts_with(prefix)) {
            return make_error(Errc::invalid_argument, 0,
                              "K_AMF: P0 is the IMSI digits or the NAI, not the SUPI URI form");
        }
    }
    if (supi.empty()) {
        return make_error(Errc::invalid_argument, 0, "K_AMF: empty SUPI");
    }
    return kdf(kseaf.expose(), 0x6D, {text(supi), abba});
}

Result<SecretBytes> algorithm_key(const SecretBytes& key, AlgType type, std::uint8_t alg_id) {
    if (alg_id > 0x0F) {
        return make_error(Errc::invalid_argument, 0, "algorithm identity is four bits");
    }
    const std::uint8_t p0 = static_cast<std::uint8_t>(type);
    const SecretBytes out = kdf(key.expose(), 0x69, {ByteView(&p0, 1), ByteView(&alg_id, 1)});
    return lsb(out, 16);
}

SecretBytes kgnb(const SecretBytes& kamf, std::uint32_t ul_nas_count, AccessType access) {
    const auto count = be<4>(ul_nas_count);
    const std::uint8_t at = static_cast<std::uint8_t>(access);
    return kdf(kamf.expose(), 0x6E, {count, ByteView(&at, 1)});
}

SecretBytes nh(const SecretBytes& kamf, const SecretBytes& sync_input) {
    return kdf(kamf.expose(), 0x6F, {sync_input.expose()});
}

SecretBytes kng_ran_star(const SecretBytes& key, std::uint16_t pci, std::uint32_t arfcn_dl) {
    const auto p = be<2>(pci);
    const auto a = be<3>(arfcn_dl);
    return kdf(key.expose(), 0x70, {p, a});
}

SecretBytes kamf_prime(const SecretBytes& kamf, std::uint8_t direction, std::uint32_t count) {
    const auto c = be<4>(count);
    return kdf(kamf.expose(), 0x72, {ByteView(&direction, 1), c});
}

SecretBytes ksn(const SecretBytes& kgnb, std::uint16_t sn_counter) {
    const auto c = be<2>(sn_counter);
    return kdf(kgnb.expose(), 0x79, {c});
}

CkIkPrime ck_ik_prime(const SecretBytes& ck, const SecretBytes& ik, std::string_view access_network_identity,
                      ByteView sqn_xor_ak) {
    const SecretBytes key = ck_ik(ck, ik);
    const SecretBytes out = kdf(key.expose(), 0x20, {text(access_network_identity), sqn_xor_ak});
    return {SecretBytes::copy_of(out.expose().first(16)), SecretBytes::copy_of(out.expose().last(16))};
}

std::uint32_t nas_count(std::uint16_t overflow, std::uint8_t sqn) {
    return (static_cast<std::uint32_t>(overflow) << 8) | sqn;
}

} // namespace ksim::crypto::keys5g
