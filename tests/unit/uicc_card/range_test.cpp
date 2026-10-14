// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The sim ranges' cards (P1 N8; sim-uicc.md §8): identities from the IMSI,
// secrets from the range master, K_FPR, and key files created owner-only.

#include <gtest/gtest.h>

#include <sys/stat.h>
#include <unistd.h>

#include <cstdlib>
#include <filesystem>
#include <string>

#include "fixture.hpp"
#include "platform/yaml.hpp"
#include "uicc/image/image.hpp"
#include "uicc/secrets/secrets.hpp"

namespace ksim::uicc {
namespace {

std::string temp_dir() {
    std::string t = (std::filesystem::temp_directory_path() / "ksim-range-XXXXXX").string();
    char* d = ::mkdtemp(t.data());
    EXPECT_NE(d, nullptr);
    return t;
}

SecretBytes master() { return test::sb("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"); }

TEST(Range, TheIdentitiesFollowTheImsi) {
    auto s = image::range_subscriber("001010000300001");
    ASSERT_TRUE(s);
    EXPECT_EQ(s->iccid, "8988211000000300001");   // the card fixture's, so both stay one rule
    EXPECT_EQ(s->msisdn, "99900300001");
    EXPECT_EQ(s->mnc_digits, 2u);
    EXPECT_TRUE(image::range_subscriber("999700000300999"));
    EXPECT_FALSE(image::range_subscriber("001010000000121"));   // the core's own seed, not a sim range
    EXPECT_FALSE(image::range_subscriber("00101000030000"));
    EXPECT_FALSE(image::range_subscriber("0010100003000x1"));
}

TEST(Range, CardSecretsAreDeterministicAndDistinct) {
    const auto a = secrets::card_secrets(master(), "001010000300001");
    const auto again = secrets::card_secrets(master(), "001010000300001");
    const auto b = secrets::card_secrets(master(), "001010000300002");
    for (const char* name : {"k", "opc", "pin1", "puk1", "pin2", "puk2", "adm1"}) {
        ASSERT_NE(a.get(name), nullptr) << name;
        EXPECT_TRUE(ct_equal(*a.get(name), *again.get(name))) << name;
    }
    EXPECT_FALSE(ct_equal(*a.get("k"), *b.get("k")));
    EXPECT_FALSE(ct_equal(*a.get("k"), *a.get("opc")));
    EXPECT_TRUE(ct_equal(*a.get("k"), secrets::derive(master(), "K", "001010000300001")));
    EXPECT_EQ(a.get("pin1")->size(), 4u);
    EXPECT_EQ(a.get("adm1")->size(), 8u);
    for (std::uint8_t c : a.get("adm1")->expose()) {
        EXPECT_TRUE(c >= '0' && c <= '9');
    }
}

TEST(Range, ADerivedCardLoadsAndReadsItsImsi) {
    const auto s = secrets::card_secrets(master(), "001010000300007");
    auto card = image::load(Yaml::load_file(test::template_path()), s);
    auto sub = image::range_subscriber("001010000300007");
    ASSERT_TRUE(sub);
    ASSERT_TRUE(image::personalise(*card, *sub));
    // SELECT ADF.USIM, then READ BINARY of EF.IMSI: 08 09 10 10 00 00 03 00 70.
    test::apdu(*card, "00A4040C07A0000000871002");
    test::apdu(*card, "00A4000C026F07");
    EXPECT_EQ(test::apdu(*card, "00B0000009"), "0809101000000300709000");
}

TEST(Range, TheFingerprintHidesKAndDependsOnTheSalt) {
    const auto k = secrets::derive(master(), "K", "001010000300001");
    const Bytes salt1(16, 1);
    const Bytes salt2(16, 2);
    const std::string f1 = secrets::key_fingerprint(salt1, k);
    EXPECT_EQ(f1.size(), 8u);
    EXPECT_EQ(f1, secrets::key_fingerprint(salt1, k));
    EXPECT_NE(f1, secrets::key_fingerprint(salt2, k));
    EXPECT_EQ(to_hex(k.expose()).find(f1), std::string::npos);
}

TEST(Range, AKeyFileIsCreatedOwnerOnlyAndNeverOverwritten) {
    const std::string dir = temp_dir();
    const std::string f = dir + "/master.key";
    ASSERT_TRUE(secrets::create_key_file(f));
    struct stat st {};
    ASSERT_EQ(::stat(f.c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 0777, 0600u);
    EXPECT_EQ(st.st_size, 32);
    auto k = secrets::load_kek(f);
    ASSERT_TRUE(k);
    EXPECT_FALSE(secrets::create_key_file(f));   // exists: refused, the key is kept
    auto again = secrets::load_kek(f);
    ASSERT_TRUE(again);
    EXPECT_TRUE(ct_equal(*k, *again));
    std::filesystem::remove_all(dir);
}

} // namespace
} // namespace ksim::uicc
