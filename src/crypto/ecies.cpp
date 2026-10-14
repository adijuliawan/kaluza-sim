// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "crypto/ecies.hpp"

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <memory>

#include "crypto/aes.hpp"
#include "crypto/kdf.hpp"

namespace ksim::crypto::ecies {

namespace {

constexpr std::size_t kMacLen = 8;

Error bad(const char* what) {
    return make_error(Errc::invalid_argument, 0, what);
}

struct BnFree {
    void operator()(BIGNUM* p) const { BN_clear_free(p); }
};
struct GroupFree {
    void operator()(EC_GROUP* p) const { EC_GROUP_free(p); }
};
struct PointFree {
    void operator()(EC_POINT* p) const { EC_POINT_clear_free(p); }
};
struct PkeyFree {
    void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
struct PctxFree {
    void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); }
};
using Bn = std::unique_ptr<BIGNUM, BnFree>;
using Group = std::unique_ptr<EC_GROUP, GroupFree>;
using Point = std::unique_ptr<EC_POINT, PointFree>;
using Pkey = std::unique_ptr<EVP_PKEY, PkeyFree>;
using Pctx = std::unique_ptr<EVP_PKEY_CTX, PctxFree>;

Group p256() {
    return Group(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
}

/// A P-256 scalar from 32 octets, checked to lie in [1, n - 1].
Result<Bn> p256_scalar(const EC_GROUP* g, const SecretBytes& priv) {
    if (priv.size() != 32) {
        return bad("ECIES B: private key is 32 octets");
    }
    Bn d(BN_bin2bn(priv.expose().data(), 32, BN_secure_new()));
    if (!d || BN_is_zero(d.get()) || BN_cmp(d.get(), EC_GROUP_get0_order(g)) >= 0) {
        return bad("ECIES B: private key out of range");
    }
    BN_set_flags(d.get(), BN_FLG_CONSTTIME);
    return d;
}

Result<Bytes> p256_point_bytes(const EC_GROUP* g, const EC_POINT* p) {
    Bytes out(33);
    if (EC_POINT_point2oct(g, p, POINT_CONVERSION_COMPRESSED, out.data(), out.size(), nullptr) != 33) {
        return make_error(Errc::internal, 0, "ECIES B: point encoding");
    }
    return out;
}

/// Z for Profile B: the x-coordinate of d * Q (cofactor 1).
Result<SecretBytes> p256_shared(const SecretBytes& priv, ByteView peer) {
    Group g = p256();
    auto d = p256_scalar(g.get(), priv);
    if (!d) {
        return d.error();
    }
    Point q(EC_POINT_new(g.get()));
    if (!q || EC_POINT_oct2point(g.get(), q.get(), peer.data(), peer.size(), nullptr) != 1 ||
        EC_POINT_is_on_curve(g.get(), q.get(), nullptr) != 1) {
        return bad("ECIES B: peer key is not a P-256 point");
    }
    Point z(EC_POINT_new(g.get()));
    Bn x(BN_secure_new());
    if (!z || !x || EC_POINT_mul(g.get(), z.get(), nullptr, q.get(), d->get(), nullptr) != 1 ||
        EC_POINT_is_at_infinity(g.get(), z.get()) == 1 ||
        EC_POINT_get_affine_coordinates(g.get(), z.get(), x.get(), nullptr, nullptr) != 1) {
        return make_error(Errc::internal, 0, "ECIES B: ECDH");
    }
    SecretBytes out(32);
    if (BN_bn2binpad(x.get(), out.expose_mut().data(), 32) != 32) {
        return make_error(Errc::internal, 0, "ECIES B: ECDH");
    }
    return out;
}

Result<Bytes> p256_public(const SecretBytes& priv) {
    Group g = p256();
    auto d = p256_scalar(g.get(), priv);
    if (!d) {
        return d.error();
    }
    Point p(EC_POINT_new(g.get()));
    if (!p || EC_POINT_mul(g.get(), p.get(), d->get(), nullptr, nullptr, nullptr) != 1) {
        return make_error(Errc::internal, 0, "ECIES B: public key");
    }
    return p256_point_bytes(g.get(), p.get());
}

Result<Pkey> x25519_private(const SecretBytes& priv) {
    if (priv.size() != 32) {
        return bad("ECIES A: private key is 32 octets");
    }
    Pkey k(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv.expose().data(), 32));
    if (!k) {
        return make_error(Errc::internal, 0, "ECIES A: private key");
    }
    return k;
}

Result<Bytes> x25519_public(const SecretBytes& priv) {
    auto k = x25519_private(priv);
    if (!k) {
        return k.error();
    }
    Bytes out(32);
    std::size_t n = out.size();
    if (EVP_PKEY_get_raw_public_key(k->get(), out.data(), &n) != 1 || n != 32) {
        return make_error(Errc::internal, 0, "ECIES A: public key");
    }
    return out;
}

Result<SecretBytes> x25519_shared(const SecretBytes& priv, ByteView peer) {
    if (peer.size() != 32) {
        return bad("ECIES A: peer key is 32 octets");
    }
    auto k = x25519_private(priv);
    if (!k) {
        return k.error();
    }
    Pkey q(EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer.data(), peer.size()));
    Pctx ctx(EVP_PKEY_CTX_new(k->get(), nullptr));
    SecretBytes out(32);
    std::size_t n = 32;
    if (!q || !ctx || EVP_PKEY_derive_init(ctx.get()) != 1 || EVP_PKEY_derive_set_peer(ctx.get(), q.get()) != 1 ||
        EVP_PKEY_derive(ctx.get(), out.expose_mut().data(), &n) != 1 || n != 32) {
        return bad("ECIES A: X25519 failed (a low-order peer key?)");
    }
    return out;
}

Result<SecretBytes> shared(Scheme s, const SecretBytes& priv, ByteView peer) {
    return s == Scheme::profile_a ? x25519_shared(priv, peer) : p256_shared(priv, peer);
}

/// ANSI X9.63 KDF with SHA-256: Hash(Z || counter || SharedInfo1), counter from 1.
SecretBytes x963(const SecretBytes& z, ByteView shared_info, std::size_t len) {
    SecretBytes out(len);
    auto dst = out.expose_mut();
    std::size_t done = 0;
    for (std::uint32_t counter = 1; done < len; ++counter) {
        Bytes in(z.expose().begin(), z.expose().end());
        in.push_back(static_cast<std::uint8_t>(counter >> 24));
        in.push_back(static_cast<std::uint8_t>(counter >> 16));
        in.push_back(static_cast<std::uint8_t>(counter >> 8));
        in.push_back(static_cast<std::uint8_t>(counter));
        in.insert(in.end(), shared_info.begin(), shared_info.end());
        Bytes h = sha256(in);
        for (std::size_t i = 0; i < h.size() && done < len; ++i) {
            dst[done++] = h[i];
        }
        OPENSSL_cleanse(in.data(), in.size());
        OPENSSL_cleanse(h.data(), h.size());
    }
    return out;
}

/// AES-128-CTR whose counter is the low 32 bits of the block (C.3.4.0).
Bytes ctr32(ByteView ek, ByteView icb, ByteView in) {
    const Aes128 aes(ek);
    Block ctr{};
    std::copy(icb.begin(), icb.end(), ctr.begin());
    Bytes out(in.begin(), in.end());
    for (std::size_t off = 0; off < out.size(); off += 16) {
        Block ks = aes.encrypt(ctr);
        for (std::size_t i = 0; i < 16 && off + i < out.size(); ++i) {
            out[off + i] ^= ks[i];
        }
        OPENSSL_cleanse(ks.data(), ks.size());
        for (int i = 15; i >= 12; --i) {  // increment mod 2^32
            if (++ctr[static_cast<std::size_t>(i)] != 0) {
                break;
            }
        }
    }
    return out;
}

Bytes tag(ByteView mk, ByteView ciphertext) {
    const SecretBytes h = hmac_sha256(mk, ciphertext);
    return Bytes(h.expose().begin(), h.expose().begin() + kMacLen);
}

std::size_t pub_len(Scheme s) {
    return s == Scheme::profile_a ? 32 : 33;
}

} // namespace

Result<Bytes> msin_bcd(std::string_view msin) {
    if (msin.empty() || msin.size() > 10) {
        return bad("MSIN: 1 to 10 digits");
    }
    Bytes out((msin.size() + 1) / 2, 0);
    for (std::size_t i = 0; i < msin.size(); ++i) {
        const char c = msin[i];
        if (c < '0' || c > '9') {
            return bad("MSIN: decimal digits only");
        }
        const auto d = static_cast<std::uint8_t>(c - '0');
        out[i / 2] |= static_cast<std::uint8_t>(i % 2 == 0 ? d : d << 4);
    }
    if (msin.size() % 2 != 0) {
        out.back() |= 0xF0;
    }
    return out;
}

Result<Bytes> public_key(Scheme scheme, const SecretBytes& private_key) {
    switch (scheme) {
    case Scheme::profile_a:
        return x25519_public(private_key);
    case Scheme::profile_b:
        return p256_public(private_key);
    case Scheme::null:
        break;
    }
    return bad("ECIES: no key for the null scheme");
}

Result<Bytes> conceal(Scheme scheme, ByteView hn_public_key, ByteView scheme_input,
                      const SecretBytes* ephemeral_private_key) {
    if (scheme == Scheme::null) {
        return Bytes(scheme_input.begin(), scheme_input.end());
    }
    if (hn_public_key.size() != pub_len(scheme)) {
        return bad("ECIES: home network public key length");
    }
    SecretBytes fresh;
    if (ephemeral_private_key == nullptr) {
        fresh = SecretBytes(32);
        if (scheme == Scheme::profile_b) {
            Group g = p256();
            Bn d(BN_secure_new());
            if (!d || BN_priv_rand_range(d.get(), EC_GROUP_get0_order(g.get())) != 1 || BN_is_zero(d.get()) ||
                BN_bn2binpad(d.get(), fresh.expose_mut().data(), 32) != 32) {
                return make_error(Errc::internal, 0, "ECIES: ephemeral key");
            }
        } else if (RAND_priv_bytes(fresh.expose_mut().data(), 32) != 1) {
            return make_error(Errc::internal, 0, "ECIES: ephemeral key");
        }
        ephemeral_private_key = &fresh;
    }
    auto eph_pub = public_key(scheme, *ephemeral_private_key);
    if (!eph_pub) {
        return eph_pub.error();
    }
    auto z = shared(scheme, *ephemeral_private_key, hn_public_key);
    if (!z) {
        return z.error();
    }
    const SecretBytes k = x963(*z, *eph_pub, 64);
    const ByteView kv = k.expose();
    Bytes ct = ctr32(kv.first(16), kv.subspan(16, 16), scheme_input);
    Bytes out = std::move(*eph_pub);
    const Bytes t = tag(kv.subspan(32, 32), ct);
    out.insert(out.end(), ct.begin(), ct.end());
    out.insert(out.end(), t.begin(), t.end());
    return out;
}

Result<Bytes> deconceal(Scheme scheme, const SecretBytes& hn_private_key, ByteView scheme_output) {
    if (scheme == Scheme::null) {
        return Bytes(scheme_output.begin(), scheme_output.end());
    }
    const std::size_t pl = pub_len(scheme);
    if (scheme_output.size() < pl + kMacLen) {
        return make_error(Errc::truncated, 0, "ECIES: scheme output too short");
    }
    const ByteView eph_pub = scheme_output.first(pl);
    const ByteView ct = scheme_output.subspan(pl, scheme_output.size() - pl - kMacLen);
    const ByteView got = scheme_output.last(kMacLen);
    auto z = shared(scheme, hn_private_key, eph_pub);
    if (!z) {
        return z.error();
    }
    const SecretBytes k = x963(*z, eph_pub, 64);
    const ByteView kv = k.expose();
    const Bytes want = tag(kv.subspan(32, 32), ct);
    if (CRYPTO_memcmp(want.data(), got.data(), kMacLen) != 0) {
        return make_error(Errc::malformed, static_cast<std::uint32_t>(pl + ct.size()), "ECIES: MAC tag mismatch");
    }
    return ctr32(kv.first(16), kv.subspan(16, 16), ct);
}

} // namespace ksim::crypto::ecies
