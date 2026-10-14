// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Card images and sealed secrets (P1 N3; sim-uicc.md §7, §8; TS 31.102
// §4.2.2, §4.2.15, §4.2.26; TS 102 221 §13.2).

#include <gtest/gtest.h>

#include <sys/stat.h>

#include <cstdio>
#include <fstream>

#include "fixture.hpp"

namespace ksim::uicc::test {
namespace {

TEST(Image, EncodesImsiIccidAccAndMsisdn) {
    EXPECT_EQ(to_hex(*image::encode_imsi("001010000300001")), "080910100000030010");   // odd: type and parity '9'
    EXPECT_EQ(to_hex(*image::encode_imsi("00101000030000")), "0801101000000300f0");    // even: '1', 'F' at the end
    EXPECT_FALSE(image::encode_imsi("0010100003000011"));
    EXPECT_EQ(to_hex(*image::encode_iccid("8988211000000300001")), "988812010000300000f1");
    EXPECT_EQ(to_hex(image::encode_acc("001010000300001")), "0002");    // class 1
    EXPECT_EQ(to_hex(image::encode_acc("001010000300009")), "0200");    // class 9
    EXPECT_EQ(to_hex(*image::encode_msisdn_record("99900300001", 14)), "07919909300000f1ffffffffffff");
}

TEST(Image, TheTemplatePersonalises) {
    auto card = make_card();
    os::File& adf = usim(*card);
    EXPECT_EQ(to_hex(at(adf, 0x6F07).data), "080910100000030010");
    EXPECT_EQ(to_hex(at(card->mf(), 0x2FE2).data), "988812010000300000f1");
    EXPECT_EQ(to_hex(at(adf, 0x6F78).data), "0002");
    EXPECT_EQ(at(adf, 0x6FAD).data.at(3) & 0x0F, 2);
    EXPECT_TRUE(at(adf, 0xAF20).secret);
    EXPECT_EQ(at(adf, 0xAF20).secret_data.size(), 33u);
    EXPECT_TRUE(os::is_df(at(adf, 0x5FC0).kind));
}

TEST(Image, SaveAndLoadRoundTripWithoutSecretsInTheYaml) {
    const auto k = sb("a1603571e5d6234082bade59243a6179");
    const auto opc = sb("1bd3144979f3d42bb52eb5228b061020");
    auto card = make_card(test_secrets(k, opc));
    // Session keys in DF.5GS: they must go to the sealed map, not the YAML.
    os::File& nsc = at(at(usim(*card), 0x5FC0), 0x4F05);
    ASSERT_GE(nsc.data.size(), 18u);
    std::fill(nsc.data.begin() + 2, nsc.data.begin() + 18, 0x5A);
    secrets::SecretMap sealed;
    const std::string text = image::save(*card, sealed);
    EXPECT_EQ(text.find("a1603571e5d6234082bade59243a6179"), std::string::npos);
    EXPECT_EQ(text.find("A1603571E5D6234082BADE59243A6179"), std::string::npos);
    EXPECT_EQ(text.find("1BD3144979F3D42BB52EB5228B061020"), std::string::npos);
    EXPECT_EQ(text.find("5A5A5A5A"), std::string::npos);
    ASSERT_NE(sealed.get("ef.AF20"), nullptr);
    ASSERT_NE(sealed.get("ef.4F05"), nullptr);
    ASSERT_NE(sealed.get("ef.4F03"), nullptr);
    // Load again from the YAML, the sealed EFs and the PINs: the same image.
    auto s2 = test_secrets(SecretBytes(16), SecretBytes(16));
    for (const auto& n : sealed.names()) {
        s2.set(n, sealed.get(n)->clone());
    }
    auto again = image::load(Yaml::parse(text, "saved.yaml"), s2);
    secrets::SecretMap sealed2;
    EXPECT_EQ(image::save(*again, sealed2), text);
    EXPECT_TRUE(ct_equal(*sealed2.get("ef.AF20"), *sealed.get("ef.AF20")));
    EXPECT_EQ(at(at(usim(*again), 0x5FC0), 0x4F05).data, nsc.data);
}

TEST(Image, AMisspeltKeyIsAnErrorThatSaysWhere) {
    const std::string bad = "mf:\n  fid: 0x3F00\n  type: mf\n  files:\n    - fid: 0x2FE2\n      typ: transparent\n";
    try {
        (void)image::load(Yaml::parse(bad, "bad.yaml"), secrets::SecretMap{});
        FAIL() << "a misspelt key must be refused";
    } catch (const YamlError& e) {
        EXPECT_EQ(e.path(), "mf.files[0].typ");
        EXPECT_EQ(e.where(), "bad.yaml:6:7");
    }
}

TEST(Secrets, RangeKeysAreHmacSha256OfTheMasterAndTheImsi) {
    Bytes m(32);
    for (std::size_t i = 0; i < m.size(); ++i) {
        m[i] = static_cast<std::uint8_t>(i);
    }
    const SecretBytes master = SecretBytes::copy_of(m);
    // Expected values computed with Python's hmac module, not with this code.
    EXPECT_EQ(to_hex(secrets::derive(master, "K", "001010000300001").expose()), "a1603571e5d6234082bade59243a6179");
    EXPECT_EQ(to_hex(secrets::derive(master, "OPc", "001010000300001").expose()), "1bd3144979f3d42bb52eb5228b061020");
}

TEST(Secrets, ASealedFileOpensOnlyUnderItsKek) {
    secrets::SecretMap m;
    m.set("k", sb("465b5ce8b199b49faa5f0a2ee238a6bc"));
    m.set("adm1", digits("11111111"));
    const SecretBytes kek = SecretBytes::copy_of(Bytes(32, 0x42));
    auto sealed = secrets::seal(kek, m);
    ASSERT_TRUE(sealed);
    EXPECT_EQ(to_hex(ByteView(*sealed).first(8)), "4b53494d53454331");   // "KSIMSEC1"
    EXPECT_EQ(to_hex(*sealed).find("465b5ce8b199b49faa5f0a2ee238a6bc"), std::string::npos);
    auto back = secrets::open(kek, *sealed);
    ASSERT_TRUE(back);
    EXPECT_EQ(back->size(), 2u);
    EXPECT_TRUE(ct_equal(*back->get("k"), *m.get("k")));
    const SecretBytes other = SecretBytes::copy_of(Bytes(32, 0x43));
    EXPECT_EQ(secrets::open(other, *sealed).error().code, Errc::malformed);
    Bytes tampered = *sealed;
    ASSERT_FALSE(tampered.empty());
    tampered[tampered.size() - 1] ^= 1;
    EXPECT_EQ(secrets::open(kek, tampered).error().code, Errc::malformed);
    // Two seals of the same secrets differ (a fresh nonce each time).
    EXPECT_NE(*secrets::seal(kek, m), *sealed);
}

TEST(Secrets, TheKekFileMustBeTheOwnersAlone) {
    const std::string path = ::testing::TempDir() + "/ksim-kek-test";
    {
        std::ofstream f(path, std::ios::binary);
        const Bytes kek(32, 7);
        f.write(reinterpret_cast<const char*>(kek.data()), static_cast<std::streamsize>(kek.size()));
    }
    ::chmod(path.c_str(), 0644);
    EXPECT_EQ(secrets::load_kek(path).error().code, Errc::invalid_argument);
    ::chmod(path.c_str(), 0600);
    auto k = secrets::load_kek(path);
    ASSERT_TRUE(k);
    EXPECT_EQ(k->size(), 32u);
    std::remove(path.c_str());
    EXPECT_EQ(secrets::load_kek(path).error().code, Errc::io);
}

TEST(Secrets, APinBlockIsAsciiDigitsPaddedWithFf) {
    EXPECT_EQ(to_hex(secrets::pin_block(digits("1234"))->expose()), "31323334ffffffff");
    EXPECT_FALSE(secrets::pin_block(digits("12a4")));
    EXPECT_FALSE(secrets::pin_block(digits("123")));
}

} // namespace
} // namespace ksim::uicc::test
