// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Known-answer tests: every set of every spec/kat file (plan M9). The set
// counts are asserted too, so a short extraction cannot pass by testing less.

#include <gtest/gtest.h>

#include <algorithm>

#include "crypto/aes.hpp"
#include "crypto/eap_aka_prime.hpp"
#include "crypto/ecies.hpp"
#include "crypto/keccak.hpp"
#include "crypto/keys5g.hpp"
#include "crypto/milenage.hpp"
#include "crypto/milenage256.hpp"
#include "crypto/nea.hpp"
#include "crypto/rijndael256.hpp"
#include "crypto/tuak.hpp"
#include "kat_file.hpp"

namespace ksim::crypto {
namespace {

using kat::hx;

std::string mac_hex(const Mac& m) {
    return to_hex(ByteView(m));
}

TEST(Kat, Rijndael35208) {
    const auto sets = kat::load("rijndael");
    ASSERT_EQ(sets.size(), 20U);
    for (const auto& [name, s] : sets) {
        const Bytes key = s.bytes("Key");
        const Aes128 aes(key);
        Block in{};
        const Bytes p = s.bytes("Plaintext");
        std::copy(p.begin(), p.end(), in.begin());
        const Block out = aes.encrypt(in);
        EXPECT_EQ(to_hex(ByteView(out)), s.hex("Ciphertext")) << "set " << name;
    }
}

TEST(Kat, Milenage35208) {
    const auto sets = kat::load("milenage");
    ASSERT_EQ(sets.size(), 20U);
    for (const auto& [name, s] : sets) {
        const SecretBytes k = s.secret("K");
        auto opc = milenage::opc(k, s.secret("OP"));
        ASSERT_TRUE(opc) << name;
        EXPECT_EQ(hx(*opc), s.hex("OPC")) << "set " << name;
        auto o = milenage::compute(k, *opc, s.bytes("RAND"), s.bytes("SQN"), s.bytes("AMF"));
        ASSERT_TRUE(o) << name;
        EXPECT_EQ(to_hex(o->mac_a), s.hex("f1")) << "set " << name;
        EXPECT_EQ(to_hex(o->mac_s), s.hex("f1*")) << "set " << name;
        EXPECT_EQ(hx(o->res), s.hex("f2")) << "set " << name;
        EXPECT_EQ(hx(o->ck), s.hex("f3")) << "set " << name;
        EXPECT_EQ(hx(o->ik), s.hex("f4")) << "set " << name;
        EXPECT_EQ(hx(o->ak), s.hex("f5")) << "set " << name;
        EXPECT_EQ(hx(o->ak_star), s.hex("f5*")) << "set " << name;
    }
}

TEST(Kat, Keccak35233) {
    const auto sets = kat::load("keccak");
    ASSERT_EQ(sets.size(), 6U);
    for (const auto& [name, s] : sets) {
        const Bytes in = s.bytes("IN");
        ASSERT_EQ(in.size(), 200U);
        KeccakState st{};
        std::copy(in.begin(), in.end(), st.begin());
        keccak_f1600(st);
        EXPECT_EQ(to_hex(ByteView(st)), s.hex("OUT")) << "set " << name;
    }
}

TEST(Kat, Tuak35233) {
    const auto sets = kat::load("tuak");
    ASSERT_EQ(sets.size(), 6U);
    for (const auto& [name, s] : sets) {
        tuak::Sizes sz;
        sz.k = s.num("Klength") / 8;
        sz.mac = s.num("MAClength") / 8;
        sz.res = s.num("RESLength") / 8;
        sz.ck = s.num("CKlength") / 8;
        sz.ik = s.num("IKlength") / 8;
        sz.iterations = static_cast<unsigned>(s.num("KeccakIterations"));
        const SecretBytes k = s.secret("K");
        auto topc = tuak::topc(k, s.secret("TOP"), sz);
        ASSERT_TRUE(topc) << name << ": " << topc.error().what;
        EXPECT_EQ(hx(*topc), s.hex("TOPc")) << "set " << name;
        auto o = tuak::compute(k, *topc, s.bytes("RAND"), s.bytes("SQN"), s.bytes("AMF"), sz);
        ASSERT_TRUE(o) << name;
        EXPECT_EQ(to_hex(o->mac_a), s.hex("f1")) << "set " << name;
        EXPECT_EQ(to_hex(o->mac_s), s.hex("f1*")) << "set " << name;
        EXPECT_EQ(hx(o->res), s.hex("f2")) << "set " << name;
        EXPECT_EQ(hx(o->ck), s.hex("f3")) << "set " << name;
        EXPECT_EQ(hx(o->ik), s.hex("f4")) << "set " << name;
        EXPECT_EQ(hx(o->ak), s.hex("f5")) << "set " << name;
        EXPECT_EQ(hx(o->ak_star), s.hex("f5*")) << "set " << name;
    }
}

Block32 block32(const Bytes& b) {
    Block32 x{};
    std::copy(b.begin(), b.end(), x.begin());
    return x;
}

TEST(Kat, Milenage256Kernel35236) {
    // The debug intermediates of cases 1a..5a are PRF input/output pairs.
    const auto sets = kat::load("milenage256");
    int pairs = 0;
    for (const auto& [name, s] : sets) {
        const Rijndael256 prf(s.bytes("KEY"));
        EXPECT_EQ(to_hex(ByteView(prf.encrypt(block32(s.bytes("OP"))))), s.hex("PRF_K(OP)")) << name;
        EXPECT_EQ(to_hex(ByteView(prf.encrypt(block32(s.bytes("PRF_in2"))))), s.hex("PRF_out2")) << name;
        pairs += 2;
        for (int i = 0; i < 8; ++i) {
            const std::string p = "idx" + std::to_string(i) + ".";
            if (!s.has(p + "PRF_in1")) {
                continue;
            }
            for (const char* n : {"1", "2"}) {
                const Block32 y = prf.encrypt(block32(s.bytes(p + "PRF_in" + n)));
                EXPECT_EQ(to_hex(ByteView(y)), s.hex(p + "PRF_out" + n)) << name << " " << p << n;
                ++pairs;
            }
        }
    }
    EXPECT_EQ(pairs, 25 * 2 + 5 * 8 * 2);
}

TEST(Kat, Milenage256_35236) {
    const auto sets = kat::load("milenage256");
    ASSERT_EQ(sets.size(), 25U);
    for (const auto& [name, s] : sets) {
        milenage256::Sizes sz;
        sz.k = s.num("KEY_sz");
        sz.rand = s.num("RAND_sz");
        sz.sqn = s.num("SQN_sz");
        sz.res = s.num("RES_sz");
        sz.ck = s.num("CK_sz");
        sz.ik = s.num("IK_sz");
        sz.mac = s.num("MAC_sz");
        sz.ak = s.num("AK_sz");
        milenage256::Constants c{};
        for (std::size_t i = 0; i < 8; ++i) {
            const Bytes ci = s.bytes("c" + std::to_string(i));
            ASSERT_EQ(ci.size(), 16U) << name;
            std::copy(ci.begin(), ci.end(), c[i].begin());
        }
        const SecretBytes k = s.secret("KEY");
        auto opc = milenage256::opc(k, s.secret("OP"));
        ASSERT_TRUE(opc) << name;
        EXPECT_EQ(hx(*opc), s.hex("OPc")) << "set " << name;
        auto o = milenage256::compute(k, *opc, s.bytes("RAND"), s.bytes("SQN"), s.bytes("AMF"), sz, c);
        ASSERT_TRUE(o) << name;
        EXPECT_EQ(to_hex(o->mac_s), s.hex("f1*:MAC_S")) << "set " << name;
        EXPECT_EQ(to_hex(o->mac_a), s.hex("f1:MAC_A")) << "set " << name;
        EXPECT_EQ(hx(o->res), s.hex("f2:RES")) << "set " << name;
        EXPECT_EQ(hx(o->ck), s.hex("f3:CK")) << "set " << name;
        EXPECT_EQ(hx(o->ik), s.hex("f4:IK")) << "set " << name;
        EXPECT_EQ(hx(o->ak), s.hex("f5:AK")) << "set " << name;
        EXPECT_EQ(hx(o->ak_star), s.hex("f5*:AK*")) << "set " << name;
        EXPECT_EQ(hx(o->ak_star_star), s.hex("f5**:AK*")) << "set " << name;
        auto ss = milenage256::f5_star_star(k, *opc, s.bytes("RAND"), o->mac_s, sz, c);
        ASSERT_TRUE(ss) << name;
        EXPECT_TRUE(ct_equal(*ss, o->ak_star_star)) << name;
    }
}

TEST(Kat, Milenage256DefaultConstants) {
    const auto c = milenage256::default_constants();
    EXPECT_EQ(c[0], (std::array<std::uint8_t, 16>{}));
    EXPECT_EQ(c[1][15], 0x01);
    EXPECT_EQ(c[7][15], 0x40);
    EXPECT_EQ(std::count(c[3].begin(), c[3].end(), 0), 15);
}

TEST(Kat, Eea2_33401) {
    const auto sets = kat::load("eea2");
    ASSERT_EQ(sets.size(), 6U);
    for (const auto& [name, s] : sets) {
        const std::size_t bits = s.num("Length");
        const SecInput in{static_cast<std::uint32_t>(s.num("Count")), static_cast<std::uint8_t>(s.num("Bearer")),
                          static_cast<std::uint8_t>(s.num("Direction"))};
        auto c = nea(Nea::nea2, s.secret("Key"), in, s.bytes("Plaintext"), bits);
        ASSERT_TRUE(c) << name;
        EXPECT_EQ(to_hex(*c), to_hex(kat::first_bits(s.bytes("Ciphertext"), bits))) << "set " << name;
        auto p = nea(Nea::nea2, s.secret("Key"), in, *c, bits);  // decryption is the same operation
        ASSERT_TRUE(p) << name;
        EXPECT_EQ(to_hex(*p), to_hex(kat::first_bits(s.bytes("Plaintext"), bits))) << "set " << name;
    }
}

TEST(Kat, Eea1FromUea2Sage) {
    // 128-EEA1 is UEA2 (33.401 B.1.2, C.3): the SAGE Document 3 sets.
    const auto sets = kat::load("uea2");
    ASSERT_EQ(sets.size(), 5U);
    for (const auto& [name, s] : sets) {
        const std::size_t bits = s.num("Length");
        const SecInput in{static_cast<std::uint32_t>(s.num("Count-C")), static_cast<std::uint8_t>(s.num("Bearer")),
                          static_cast<std::uint8_t>(s.num("Direction"))};
        auto c = nea(Nea::nea1, s.secret("CK"), in, s.bytes("Plaintext"), bits);
        ASSERT_TRUE(c) << name;
        EXPECT_EQ(to_hex(*c), to_hex(kat::first_bits(s.bytes("Ciphertext"), bits))) << "set " << name;
    }
}

TEST(Kat, Eia2_33401) {
    const auto sets = kat::load("eia2");
    ASSERT_EQ(sets.size(), 8U);
    for (const auto& [name, s] : sets) {
        const SecInput in{static_cast<std::uint32_t>(s.num("Count-I")), static_cast<std::uint8_t>(s.num("Bearer")),
                          static_cast<std::uint8_t>(s.num("Direction"))};
        auto m = nia(Nia::nia2, s.secret("IK"), in, s.bytes("Message"), s.num("Length"));
        ASSERT_TRUE(m) << name;
        EXPECT_EQ(mac_hex(*m), s.hex("MACT")) << "set " << name;
    }
}

TEST(Kat, Eia1_33401) {
    const auto sets = kat::load("eia1");
    ASSERT_EQ(sets.size(), 7U);
    for (const auto& [name, s] : sets) {
        const SecInput in{static_cast<std::uint32_t>(s.num("Count-I")), static_cast<std::uint8_t>(s.num("Bearer")),
                          static_cast<std::uint8_t>(s.num("Direction"))};
        auto m = nia(Nia::nia1, s.secret("IK"), in, s.bytes("Message"), s.num("Length"));
        ASSERT_TRUE(m) << name;
        EXPECT_EQ(mac_hex(*m), s.hex("MACT")) << "set " << name;
    }
}

TEST(Kat, Uia2Sage) {
    const auto sets = kat::load("uia2");
    ASSERT_EQ(sets.size(), 6U);
    for (const auto& [name, s] : sets) {
        const Mac m = uia2_f9(s.secret("IK"), static_cast<std::uint32_t>(s.num("COUNT-I")),
                              static_cast<std::uint32_t>(s.num("FRESH")), static_cast<std::uint8_t>(s.num("DIRECTION")),
                              s.bytes("MESSAGE"), s.num("LENGTH"));
        EXPECT_EQ(mac_hex(m), s.hex("MAC-I")) << "set " << name;
    }
}

TEST(Kat, NullAlgorithmsAndZucGap) {
    const SecretBytes key(16);
    const Bytes data = {0xde, 0xad, 0xbe, 0xef};
    auto c = nea(Nea::nea0, key, {}, data);
    ASSERT_TRUE(c);
    EXPECT_EQ(*c, data);
    auto m = nia(Nia::nia0, key, {}, data);
    ASSERT_TRUE(m);
    EXPECT_EQ(*m, (Mac{0, 0, 0, 0}));
    auto z = nea(Nea::nea3, key, {}, data);
    ASSERT_FALSE(z);
    EXPECT_EQ(z.error().code, Errc::unsupported);
    auto zi = nia(Nia::nia3, key, {}, data);
    ASSERT_FALSE(zi);
    EXPECT_EQ(zi.error().code, Errc::unsupported);
}

TEST(Kat, EciesNullScheme33501) {
    const auto sets = kat::load("ecies");
    ASSERT_EQ(sets.size(), 6U);
    const auto& s = sets[0].second;  // C.4.2.1, MSIN 001002086
    ASSERT_EQ(sets[0].first, "C.4.2.1");
    auto bcd = ecies::msin_bcd("001002086");
    ASSERT_TRUE(bcd);
    EXPECT_EQ(to_hex(*bcd), s.hex("Scheme Input"));
    auto out = ecies::conceal(ecies::Scheme::null, {}, *bcd);
    ASSERT_TRUE(out);
    EXPECT_EQ(to_hex(*out), s.hex("Scheme Output"));
}

TEST(Kat, EciesProfiles33501) {
    const auto sets = kat::load("ecies");
    int checked = 0;
    for (const auto& [name, s] : sets) {
        const bool a = name.starts_with("C.4.3");
        const bool b = name.starts_with("C.4.4");
        if (!a && !b) {
            continue;
        }
        const auto scheme = a ? ecies::Scheme::profile_a : ecies::Scheme::profile_b;
        const std::string hn_pub = a ? "Home Network Public Key" : "Home Network Public Key (compressed)";
        const std::string eph_pub = a ? "Eph. Public Key" : "Eph. Public Key (compressed)";
        const std::string plain = a ? "Plaintext block" : "Scheme-input corresponding to the plaintext-block";
        const SecretBytes hn_priv = s.secret("Home Network Private Key");
        const SecretBytes eph_priv = s.secret("Eph. Private Key");

        auto hp = ecies::public_key(scheme, hn_priv);
        ASSERT_TRUE(hp) << name;
        EXPECT_EQ(to_hex(*hp), s.hex(hn_pub)) << name;
        auto ep = ecies::public_key(scheme, eph_priv);
        ASSERT_TRUE(ep) << name;
        EXPECT_EQ(to_hex(*ep), s.hex(eph_pub)) << name;

        auto out = ecies::conceal(scheme, s.bytes(hn_pub), s.bytes(plain), &eph_priv);
        ASSERT_TRUE(out) << name;
        EXPECT_EQ(to_hex(*out), s.hex(eph_pub) + s.hex("Cipher-text vaue") + s.hex("MAC-tag value")) << name;
        if (!s.hex("Scheme Output").empty()) {
            EXPECT_EQ(to_hex(*out), s.hex("Scheme Output")) << name;
        }
        auto back = ecies::deconceal(scheme, hn_priv, *out);
        ASSERT_TRUE(back) << name;
        EXPECT_EQ(to_hex(*back), s.hex(plain)) << name;

        Bytes bad = *out;
        ASSERT_GT(bad.size(), 8U) << name;
        bad[bad.size() - 1] = static_cast<std::uint8_t>(bad[bad.size() - 1] ^ 0x01);  // the tag's last bit
        auto rej = ecies::deconceal(scheme, hn_priv, bad);
        ASSERT_FALSE(rej) << name;
        EXPECT_EQ(rej.error().code, Errc::malformed) << name;

        auto fresh = ecies::conceal(scheme, s.bytes(hn_pub), s.bytes(plain));  // a fresh ephemeral key
        ASSERT_TRUE(fresh) << name;
        EXPECT_NE(to_hex(*fresh), to_hex(*out)) << name;
        auto fb = ecies::deconceal(scheme, hn_priv, *fresh);
        ASSERT_TRUE(fb) << name;
        EXPECT_EQ(to_hex(*fb), s.hex(plain)) << name;
        ++checked;
    }
    EXPECT_EQ(checked, 4);
}

TEST(Kat, EapAkaPrimeRfc9048) {
    const auto sets = kat::load("eap_aka_prime");
    ASSERT_EQ(sets.size(), 4U);
    for (const auto& [name, s] : sets) {
        const Bytes autn = s.bytes("AUTN");
        const auto p = keys5g::ck_ik_prime(s.secret("CK"), s.secret("IK"), s.text("Network name"),
                                           ByteView(autn).first(6));  // SQN xor AK
        EXPECT_EQ(hx(p.ck_prime), s.hex("CK'")) << "case " << name;
        EXPECT_EQ(hx(p.ik_prime), s.hex("IK'")) << "case " << name;
        const auto k = eap_aka_prime::derive(p.ck_prime, p.ik_prime, s.text("Identity"));
        EXPECT_EQ(hx(k.k_encr), s.hex("K_encr")) << "case " << name;
        EXPECT_EQ(hx(k.k_aut), s.hex("K_aut")) << "case " << name;
        EXPECT_EQ(hx(k.k_re), s.hex("K_re")) << "case " << name;
        EXPECT_EQ(hx(k.msk), s.hex("MSK")) << "case " << name;
        EXPECT_EQ(hx(k.emsk), s.hex("EMSK")) << "case " << name;
        EXPECT_EQ(hx(eap_aka_prime::kausf(k)), s.hex("EMSK").substr(0, 64)) << "case " << name;
    }
}

} // namespace
} // namespace ksim::crypto
