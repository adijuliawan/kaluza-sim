// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "crypto/as_security.hpp"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <cstdlib>
#include <vector>

#include "ocudu/security/s3g.h"  // third_party/ocudu-security: the SNOW 3G kernel and f9

namespace ksim::crypto {

namespace {

constexpr std::size_t kKey = 16;

Error bad(const char* what) {
    return make_error(Errc::invalid_argument, 0, what);
}
Error zuc_gap() {
    return make_error(Errc::unsupported, 0, "128-NEA3/NIA3 (ZUC): declared gap, row KS-SEC-G1");
}

/// BEARER (5 bits) || DIRECTION (1 bit) || 00 (TS 33.401 B.1.3, B.2.3).
std::uint8_t bearer_direction(SecInput in) {
    return static_cast<std::uint8_t>((unsigned{in.bearer} << 3) | ((unsigned{in.direction} & 1U) << 2));
}

/// The octets past `bits` zeroed, as the bit-string forms leave them.
void clear_tail(std::span<std::uint8_t> data, std::size_t bits) {
    const std::size_t used = (bits + 7) / 8;
    for (std::size_t i = used; i < data.size(); ++i) {
        data[i] = 0;
    }
    if (bits % 8 != 0 && used > 0) {
        data[used - 1] &= static_cast<std::uint8_t>(0xFF00U >> (bits % 8));
    }
}

void load_key_words(ByteView b, std::uint32_t k[4]) {
    // SAGE Document 1 §3.4: K3 = CK[0..31] (the first four octets) ... K0 = CK[96..127].
    for (std::size_t i = 0; i < 4; ++i) {
        k[3 - i] = (std::uint32_t{b[4 * i]} << 24) | (std::uint32_t{b[4 * i + 1]} << 16) |
                   (std::uint32_t{b[4 * i + 2]} << 8) | std::uint32_t{b[4 * i + 3]};
    }
}

} // namespace

// ---- ciphering ----------------------------------------------------------------------------

struct NeaContext::Impl {
    EVP_CIPHER_CTX* ctr = nullptr;   // NEA2: AES-128-CTR with the key set
    std::vector<std::uint32_t> ks;   // NEA1: the keystream, reused
    ~Impl() {
        EVP_CIPHER_CTX_free(ctr);
        if (!ks.empty()) {
            OPENSSL_cleanse(ks.data(), ks.size() * sizeof(std::uint32_t));
        }
    }
};

NeaContext::NeaContext(Nea alg, SecretBytes key) : alg_(alg), key_(std::move(key)), impl_(std::make_unique<Impl>()) {}
NeaContext::NeaContext(NeaContext&&) noexcept = default;
NeaContext& NeaContext::operator=(NeaContext&&) noexcept = default;
NeaContext::~NeaContext() = default;

Result<NeaContext> NeaContext::make(Nea alg, const SecretBytes& key) {
    switch (alg) {
    case Nea::nea0:
        return NeaContext(alg, SecretBytes{});
    case Nea::nea1:
    case Nea::nea2:
        break;
    case Nea::nea3:
        return zuc_gap();
    default:
        return bad("NEA: unknown algorithm");
    }
    if (key.size() != kKey) {
        return bad("NEA: the key is 16 octets");
    }
    if (alg == Nea::nea1) {
        return NeaContext(alg, key.clone());
    }
    NeaContext c(alg, SecretBytes{});
    c.impl_->ctr = EVP_CIPHER_CTX_new();
    if (c.impl_->ctr == nullptr ||
        EVP_EncryptInit_ex(c.impl_->ctr, EVP_aes_128_ctr(), nullptr, key.expose().data(), nullptr) != 1) {
        std::abort();   // a 16-octet key with AES-128-CTR: only an exhausted process gets here
    }
    return c;
}

Result<void> NeaContext::apply(SecInput in, std::span<std::uint8_t> data, std::size_t bits) {
    if (bits > data.size() * 8) {
        return bad("NEA: bit length exceeds the data");
    }
    if (in.bearer > 31) {
        return bad("NEA: BEARER is five bits");
    }
    const std::size_t n = (bits + 7) / 8;
    switch (alg_) {
    case Nea::nea0:
        break;
    case Nea::nea1: {
        // 128-EEA1: UEA2's f8 with COUNT-C = COUNT (TS 33.401 B.1.2; SAGE Document 1 §3).
        std::uint32_t k[4];
        load_key_words(key_.expose(), k);
        const std::uint32_t bd = (std::uint32_t{in.bearer} << 27) | (std::uint32_t{in.direction & 1U} << 26);
        std::uint32_t iv[4] = {bd, in.count, bd, in.count};   // IV0 .. IV3 (§3.4)
        const std::size_t words = (bits + 31) / 32;
        impl_->ks.resize(words);
        ocudu::security::S3G_STATE st{};
        ocudu::security::s3g_initialize(&st, k, iv);
        ocudu::security::s3g_generate_keystream(&st, static_cast<std::uint32_t>(words), impl_->ks.data());
        OPENSSL_cleanse(st.lfsr, 16 * sizeof(std::uint32_t));   // key-dependent; the kernel frees without wiping
        OPENSSL_cleanse(st.fsm, 3 * sizeof(std::uint32_t));
        ocudu::security::s3g_deinitialize(&st);
        OPENSSL_cleanse(k, sizeof k);
        for (std::size_t j = 0; j < n; ++j) {
            data[j] ^= static_cast<std::uint8_t>(impl_->ks[j / 4] >> (24 - 8 * (j % 4)));
        }
        break;
    }
    case Nea::nea2: {
        // 128-EEA2: AES-128-CTR from T1 = COUNT || BEARER || DIRECTION || 0^90 (B.1.3).
        const std::uint8_t t1[16] = {static_cast<std::uint8_t>(in.count >> 24), static_cast<std::uint8_t>(in.count >> 16),
                                     static_cast<std::uint8_t>(in.count >> 8), static_cast<std::uint8_t>(in.count),
                                     bearer_direction(in)};
        int out = 0;
        if (EVP_EncryptInit_ex(impl_->ctr, nullptr, nullptr, nullptr, t1) != 1 ||
            (n > 0 && EVP_EncryptUpdate(impl_->ctr, data.data(), &out, data.data(), static_cast<int>(n)) != 1)) {
            std::abort();
        }
        break;
    }
    case Nea::nea3:
        return zuc_gap();
    }
    if (bits % 8 != 0) {
        clear_tail(data.first(n), bits);
    }
    return {};
}

// ---- integrity ----------------------------------------------------------------------------

struct NiaContext::Impl {
    EVP_MAC* mac = nullptr;          // NIA2: CMAC over AES-128-CBC, keyed once
    EVP_MAC_CTX* ctx = nullptr;
    Bytes joined;                    // NIA1: f9 reads one contiguous, padded message
    ~Impl() {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        if (!joined.empty()) {
            OPENSSL_cleanse(joined.data(), joined.size());
        }
    }
};

NiaContext::NiaContext(Nia alg, SecretBytes key) : alg_(alg), key_(std::move(key)), impl_(std::make_unique<Impl>()) {}
NiaContext::NiaContext(NiaContext&&) noexcept = default;
NiaContext& NiaContext::operator=(NiaContext&&) noexcept = default;
NiaContext::~NiaContext() = default;

Result<NiaContext> NiaContext::make(Nia alg, const SecretBytes& key) {
    switch (alg) {
    case Nia::nia0:
        return NiaContext(alg, SecretBytes{});
    case Nia::nia1:
    case Nia::nia2:
        break;
    case Nia::nia3:
        return zuc_gap();
    default:
        return bad("NIA: unknown algorithm");
    }
    if (key.size() != kKey) {
        return bad("NIA: the key is 16 octets");
    }
    if (alg == Nia::nia1) {
        return NiaContext(alg, key.clone());
    }
    NiaContext c(alg, SecretBytes{});
    char cipher[] = "AES-128-CBC";
    OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, cipher, 0), OSSL_PARAM_construct_end()};
    c.impl_->mac = EVP_MAC_fetch(nullptr, "CMAC", nullptr);
    c.impl_->ctx = c.impl_->mac != nullptr ? EVP_MAC_CTX_new(c.impl_->mac) : nullptr;
    if (c.impl_->ctx == nullptr || EVP_MAC_init(c.impl_->ctx, key.expose().data(), kKey, params) != 1) {
        std::abort();   // OpenSSL 3's default provider always has CMAC
    }
    return c;
}

Result<Mac> NiaContext::mac(SecInput in, std::initializer_list<ByteView> parts) {
    if (in.bearer > 31) {
        return bad("NIA: BEARER is five bits");
    }
    switch (alg_) {
    case Nia::nia0:
        return Mac{};
    case Nia::nia1: {
        // 128-EIA1: UIA2's f9 with COUNT-I = COUNT, FRESH = BEARER || 0^27 (B.2.2), over the
        // joined message, zero-padded to whole 64-bit words as f9 reads them.
        auto& m = impl_->joined;
        m.clear();
        for (const auto& p : parts) {
            m.insert(m.end(), p.begin(), p.end());
        }
        const std::size_t bits = m.size() * 8;
        if (bits == 0) {
            return bad("NIA1: the message is at least one bit");   // KS-SEC-D1
        }
        m.resize((m.size() + 7) / 8 * 8 + 8, 0);
        ocudu::security::sec_mac out{};
        ocudu::security::s3g_f9(out, key_.expose().data(), in.count, std::uint32_t{in.bearer} << 27,
                                in.direction & 1U, m.data(), bits);
        return Mac{out[0], out[1], out[2], out[3]};
    }
    case Nia::nia2: {
        // 128-EIA2: AES-CMAC over COUNT || BEARER || DIRECTION || 0^26 || MESSAGE, 32 MSBs (B.2.3).
        const std::uint8_t head[8] = {static_cast<std::uint8_t>(in.count >> 24), static_cast<std::uint8_t>(in.count >> 16),
                                      static_cast<std::uint8_t>(in.count >> 8), static_cast<std::uint8_t>(in.count),
                                      bearer_direction(in), 0, 0, 0};
        std::uint8_t tag[16];
        std::size_t len = 0;
        bool ok = EVP_MAC_init(impl_->ctx, nullptr, 0, nullptr) == 1 && EVP_MAC_update(impl_->ctx, head, sizeof head) == 1;
        for (const auto& p : parts) {
            ok = ok && (p.empty() || EVP_MAC_update(impl_->ctx, p.data(), p.size()) == 1);
        }
        if (!ok || EVP_MAC_final(impl_->ctx, tag, &len, sizeof tag) != 1 || len != sizeof tag) {
            std::abort();
        }
        const Mac out{tag[0], tag[1], tag[2], tag[3]};
        OPENSSL_cleanse(tag, sizeof tag);
        return out;
    }
    case Nia::nia3:
        return zuc_gap();
    }
    return bad("NIA: unknown algorithm");
}

} // namespace ksim::crypto
