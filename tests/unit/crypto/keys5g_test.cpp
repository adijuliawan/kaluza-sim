// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The 5G key hierarchy (TS 33.501 Annex A). The specification has no vectors
// for it (row KS-SEC-T2), so the checks are:
//  - the key traps (plan M9): each written as the KDF input string S spelled
//    out octet by octet from the clause, so a wrong encoding cannot agree;
//  - OCUDU's unit-test vectors for the gNB-side derivations (an independent
//    implementation, BSD-3-Clause-Open-MPI, OCUDU 489ed15c5c,
//    tests/unittests/security/security_test.cpp);
//  - the independent Python oracle over 10k random inputs (keychain-oracle).

#include <gtest/gtest.h>

#include "crypto/ecies.hpp"
#include "crypto/kdf.hpp"
#include "crypto/keys5g.hpp"
#include "kat_file.hpp"

namespace ksim::crypto {
namespace {

using kat::hx;

SecretBytes sec(std::string_view h) {
    auto r = SecretBytes::from_hex(h);
    EXPECT_TRUE(r);
    return r ? std::move(*r) : SecretBytes{};
}

Bytes bytes_of(std::string_view s) {
    return Bytes(s.begin(), s.end());
}

TEST(Keys5g, ServingNetworkName) {
    EXPECT_EQ(*keys5g::serving_network_name("001", "01"), "5G:mnc001.mcc001.3gppnetwork.org");
    EXPECT_EQ(*keys5g::serving_network_name("999", "70"), "5G:mnc070.mcc999.3gppnetwork.org");
    EXPECT_EQ(*keys5g::serving_network_name("310", "410"), "5G:mnc410.mcc310.3gppnetwork.org");
    EXPECT_FALSE(keys5g::serving_network_name("01", "01"));
    EXPECT_FALSE(keys5g::serving_network_name("001", "1"));
    EXPECT_FALSE(keys5g::serving_network_name("00a", "01"));
}

// Trap 1: K_AMF takes the IMSI as a character string of digits (A.7.0 and
// TS 33.220 B.2.1.2), never BCD and never the "imsi-" URI form.
TEST(Keys5g, KamfTakesTheImsiDigitString) {
    const SecretBytes kseaf = sec("a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00");
    const Bytes abba = {0x00, 0x00};
    auto kamf = keys5g::kamf(kseaf, "001010000000001", abba);
    ASSERT_TRUE(kamf);

    Bytes s = {0x6D};                               // FC
    const Bytes p0 = bytes_of("001010000000001");   // P0: 15 characters
    s.insert(s.end(), p0.begin(), p0.end());
    s.insert(s.end(), {0x00, 0x0F});                // L0
    s.insert(s.end(), {0x00, 0x00});                // P1: ABBA
    s.insert(s.end(), {0x00, 0x02});                // L1
    EXPECT_EQ(hx(*kamf), hx(hmac_sha256(kseaf.expose(), s)));

    const Bytes bcd = {0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10};  // the wrong reading
    Bytes wrong = {0x6D};
    wrong.insert(wrong.end(), bcd.begin(), bcd.end());
    wrong.insert(wrong.end(), {0x00, 0x08, 0x00, 0x00, 0x00, 0x02});
    EXPECT_NE(hx(*kamf), hx(hmac_sha256(kseaf.expose(), wrong)));

    auto uri = keys5g::kamf(kseaf, "imsi-001010000000001", abba);
    ASSERT_FALSE(uri);
    EXPECT_EQ(uri.error().code, Errc::invalid_argument);
}

// Trap 2: the null-scheme SUCI is the MSIN itself in BCD, low nibble first,
// 0xF filler for an odd digit count (TS 33.501 C.3.1, 24.501 9.11.3.4).
TEST(Keys5g, NullSchemeSuciIsTheMsin) {
    auto even = ecies::msin_bcd("0000000001");
    ASSERT_TRUE(even);
    EXPECT_EQ(to_hex(*even), "0000000010");
    auto odd = ecies::msin_bcd("123456789");
    ASSERT_TRUE(odd);
    EXPECT_EQ(to_hex(*odd), "21436587f9");
    auto out = ecies::conceal(ecies::Scheme::null, {}, *odd);
    ASSERT_TRUE(out);
    EXPECT_EQ(*out, *odd);
    EXPECT_FALSE(ecies::msin_bcd("12345678901"));
    EXPECT_FALSE(ecies::msin_bcd("12a4"));
}

// Trap 3: K_gNB takes the uplink NAS COUNT as four octets (A.9), the 24-bit
// COUNT (overflow << 8 | SQN) right-aligned (TS 33.220 B.2.1.3 example: 259 is
// 00 00 01 03).
TEST(Keys5g, KgnbTakesFourOctetUplinkCount) {
    const SecretBytes kamf = sec("00112233445566778899aabbccddeeff0123456789abcdef0123456789abcdef");
    EXPECT_EQ(keys5g::nas_count(1, 3), 259U);
    const SecretBytes kgnb = keys5g::kgnb(kamf, keys5g::nas_count(1, 3));
    const Bytes s = {0x6E, 0x00, 0x00, 0x01, 0x03, 0x00, 0x04, 0x01, 0x00, 0x01};
    EXPECT_EQ(hx(kgnb), hx(hmac_sha256(kamf.expose(), s)));
    EXPECT_NE(hx(kgnb), hx(keys5g::kgnb(kamf, 0)));
    const SecretBytes kn3iwf = keys5g::kgnb(kamf, 259, keys5g::AccessType::non_3gpp);
    const Bytes s2 = {0x6E, 0x00, 0x00, 0x01, 0x03, 0x00, 0x04, 0x02, 0x00, 0x01};
    EXPECT_EQ(hx(kn3iwf), hx(hmac_sha256(kamf.expose(), s2)));
}

TEST(Keys5g, ResStarAndHxresStarAreTheLeastSignificantHalves) {
    const SecretBytes ck = sec("000102030405060708090a0b0c0d0e0f");
    const SecretBytes ik = sec("101112131415161718191a1b1c1d1e1f");
    const SecretBytes res = sec("2021222324252627");
    const Bytes rand = *from_hex("303132333435363738393a3b3c3d3e3f");
    const std::string snn = "5G:mnc001.mcc001.3gppnetwork.org";
    const SecretBytes rs = keys5g::res_star(ck, ik, snn, rand, res);
    Bytes s = {0x6B};
    const Bytes p0 = bytes_of(snn);
    s.insert(s.end(), p0.begin(), p0.end());
    s.insert(s.end(), {0x00, static_cast<std::uint8_t>(p0.size())});
    s.insert(s.end(), rand.begin(), rand.end());
    s.insert(s.end(), {0x00, 0x10});
    s.insert(s.end(), res.expose().begin(), res.expose().end());
    s.insert(s.end(), {0x00, 0x08});
    const Bytes key = *from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    EXPECT_EQ(hx(rs), hx(hmac_sha256(key, s)).substr(32));
    Bytes h = rand;
    h.insert(h.end(), rs.expose().begin(), rs.expose().end());
    EXPECT_EQ(to_hex(keys5g::hres_star(rand, rs)), to_hex(sha256(h)).substr(32));
}

TEST(Keys5g, AlgorithmKeyRejectsWideIdentity) {
    const SecretBytes k(32);
    EXPECT_FALSE(keys5g::algorithm_key(k, keys5g::AlgType::nas_enc, 16));
    auto ok = keys5g::algorithm_key(k, keys5g::AlgType::nas_enc, 2);
    ASSERT_TRUE(ok);
    EXPECT_EQ(ok->size(), 16U);
}

// OCUDU security_test.cpp: security_gen_k_ng_ran_star/testset1 (PCI 32, ARFCN 561).
// OCUDU writes an ARFCN below 2^16 in two octets; A.11 fixes L1 = 0x00 0x03, so
// its vector is the two-octet reading and ours differs (row KS-SEC-T4). Both
// readings are spelled out here, and ours must be the three-octet one.
TEST(Keys5g, KngRanStarArfcnIsThreeOctets) {
    const SecretBytes kgnb = sec("c4c7bc798ab94e3d354cd6608e79aa92f5569df46519507850051e36f018ca5f");
    const Bytes ocudu_s = {0x70, 0x00, 0x20, 0x00, 0x02, 0x02, 0x31, 0x00, 0x02};
    EXPECT_EQ(hx(hmac_sha256(kgnb.expose(), ocudu_s)),
              "82fe5b109099321225a953633c4fec579051652b77f472b33840127bdfa7a655");  // OCUDU's vector
    const Bytes spec_s = {0x70, 0x00, 0x20, 0x00, 0x02, 0x00, 0x02, 0x31, 0x00, 0x03};
    EXPECT_EQ(hx(keys5g::kng_ran_star(kgnb, 32, 561)), hx(hmac_sha256(kgnb.expose(), spec_s)));
    // A realistic SSB ARFCN (n78, 3.5 GHz) needs three octets either way, where the two agree.
    const Bytes n78_s = {0x70, 0x00, 0x20, 0x00, 0x02, 0x09, 0xA5, 0xB5, 0x00, 0x03};
    EXPECT_EQ(hx(keys5g::kng_ran_star(kgnb, 32, 632245)), hx(hmac_sha256(kgnb.expose(), n78_s)));
}

// OCUDU security_test.cpp: security_gen_k_rrc/testset1 and security_gen_k_up/testset1
// (NEA2, NIA0). OCUDU keeps the whole 256-bit output; the key is its low 128 bits.
TEST(Keys5g, OcuduRrcAndUpKeys) {
    const SecretBytes kgnb = sec("45cbc3f8a81193fd5c5229300d59edf812e998a115ec4e0ce903ba89367e2628");
    using keys5g::AlgType;
    EXPECT_EQ(hx(*keys5g::algorithm_key(kgnb, AlgType::rrc_enc, 2)), "66a09e992386c8d1df7892964c6fb522");
    EXPECT_EQ(hx(*keys5g::algorithm_key(kgnb, AlgType::rrc_int, 0)), "5c2cc2fda0f318a1e0ce35b9db5e80a5");
    EXPECT_EQ(hx(*keys5g::algorithm_key(kgnb, AlgType::up_enc, 2)), "152052d3dfbc3f05869b7f920095be68");
    EXPECT_EQ(hx(*keys5g::algorithm_key(kgnb, AlgType::up_int, 0)), "d0deb4584095599e5806eae4f67656d8");
}

} // namespace
} // namespace ksim::crypto
