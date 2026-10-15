// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// ksim-sim burn (P2 Q1; decision D3) against our soft card dressed as a
// sysmoISIM-SJA5: it writes AF20 and the EFs from the range master, checks the
// card with one AUTHENTICATE, stops before any VERIFY when ADM1 has fewer than
// 3 tries left, and sends a wrong ADM1 once only.

#include <gtest/gtest.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

#include "burn.hpp"
#include "card.hpp"
#include "uicc/secrets/secrets.hpp"

namespace ksim::sim {
namespace {

namespace secrets = uicc::secrets;

class BurnTest : public ::testing::Test {
protected:
    void SetUp() override {
        char tmpl[] = "/tmp/ksim-burn-XXXXXX";
        ASSERT_NE(::mkdtemp(tmpl), nullptr);
        dir_ = tmpl;
        ASSERT_TRUE(secrets::create_key_file(dir_ + "/master.key"));
        ASSERT_TRUE(secrets::create_key_file(dir_ + "/kek.key"));
        CardSource src;
        src.tmpl = std::string(KSIM_SOURCE_DIR) + "/cards/usim-5g.yaml";
        src.imsi = "001010000300100";
        src.test_keys = true;   // ADM1 11111111 and the TS 35.208 K before the burn
        src.personality = "sysmoISIM-SJA5";
        std::string why;
        card_ = make_card(src, why);
        ASSERT_TRUE(card_) << why;
        opts_.reader = "soft";
        opts_.imsi = src.imsi;
        opts_.master = dir_ + "/master.key";
        opts_.kek = dir_ + "/kek.key";
        opts_.adm1 = dir_ + "/adm1.sealed";
        opts_.tmpl = src.tmpl;
    }
    void TearDown() override { std::filesystem::remove_all(dir_); }

    void seal_adm1(const char* digits) {
        auto kek = secrets::load_kek(opts_.kek);
        ASSERT_TRUE(kek);
        secrets::SecretMap m;
        m.set("adm1", SecretBytes::copy_of(ByteView(reinterpret_cast<const std::uint8_t*>(digits), std::char_traits<char>::length(digits))));   // NOLINT
        auto sealed = secrets::seal(*kek, m);
        ASSERT_TRUE(sealed);
        std::ofstream(opts_.adm1, std::ios::binary).write(reinterpret_cast<const char*>(sealed->data()),   // NOLINT
                                                           static_cast<std::streamsize>(sealed->size()));
    }
    Xfer xfer() {
        return [this](ByteView c) -> Result<Bytes> {
            if (c.size() > 4 && c[1] == 0x20 && c[3] == 0x0A) {
                ++adm1_verifies_;
            }
            return card_->process(c);
        };
    }

    std::string dir_;
    std::unique_ptr<uicc::os::Card> card_;
    BurnOptions opts_;
    int adm1_verifies_ = 0;
};

TEST_F(BurnTest, WritesTheCardAndProvesItsKeys) {
    seal_adm1("11111111");
    EXPECT_EQ(burn(opts_, xfer()), 0);
    EXPECT_EQ(adm1_verifies_, 1);
}

TEST_F(BurnTest, AWrongAdm1IsSentOnceAndStopsIt) {
    seal_adm1("22222222");
    EXPECT_EQ(burn(opts_, xfer()), 1);
    EXPECT_EQ(adm1_verifies_, 1);
}

TEST_F(BurnTest, FewerThanThreeTriesLeftStopsBeforeAnyVerify) {
    // Wrong VERIFYs of our own until the card's ADM1 has fewer than 3 tries left.
    const Bytes wrong = *from_hex("0020000A083232323232323232");
    const Bytes status = *from_hex("0020000A");
    for (int i = 0; i < 20; ++i) {
        const Bytes st = card_->process(status);
        if (st.size() == 2 && st[0] == 0x63 && (st[1] & 0xF0) == 0xC0 && (st[1] & 0x0F) < 3) {
            break;
        }
        (void)card_->process(wrong);
    }
    seal_adm1("11111111");
    EXPECT_EQ(burn(opts_, xfer()), 3);
    EXPECT_EQ(adm1_verifies_, 0);
}

TEST_F(BurnTest, ADryRunWritesNothing) {
    opts_.dry_run = true;
    EXPECT_EQ(burn(opts_, xfer()), 0);
    EXPECT_EQ(adm1_verifies_, 0);
}

} // namespace
} // namespace ksim::sim
