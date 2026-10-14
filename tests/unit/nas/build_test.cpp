// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Building NAS messages (P1 N5; codec/nas/build.hpp): the header IEs set by
// make(), IEs set by their table names in any order and encoded in table
// order with the half-octet pairs intact.

#include <gtest/gtest.h>

#include "codec/nas/build.hpp"

namespace ksim::nas {
namespace {

TEST(NasBuild, AMessageGetsItsHeaderAndItsIesInTableOrder) {
    auto m = make(Epd::mm, 0x41);   // REGISTRATION REQUEST
    ASSERT_TRUE(m);
    EXPECT_EQ(missing_mandatory(*m),
              (std::vector<std::string_view>{"5GS registration type", "ngKSI", "5GS mobile identity"}));
    // Set out of order: the UE security capability (2E) first, the type 1 IEs last.
    ASSERT_TRUE(set(*m, "UE security capability", *from_hex("80e0e0e0")));
    ASSERT_TRUE(set(*m, "5GS mobile identity", *from_hex("0100f110000000000000000001")));
    ASSERT_TRUE(set(*m, "ngKSI", {0x07}));
    ASSERT_TRUE(set(*m, "5GS registration type", {0x09}));
    EXPECT_TRUE(missing_mandatory(*m).empty());
    auto wire = encode(*m);
    ASSERT_TRUE(wire);
    EXPECT_EQ(to_hex(*wire), "7e004179000d0100f110000000000000000001" "2e0480e0e0e0");
    // The same octets decode to the same message.
    auto back = decode(*wire);
    ASSERT_TRUE(back);
    EXPECT_EQ(to_hex(*get(*back, "UE security capability")), "80e0e0e0");
}

TEST(NasBuild, ASetReplacesAndUnsetRemoves) {
    auto m = make(Epd::mm, 0x64);   // 5GMM STATUS
    ASSERT_TRUE(m);
    ASSERT_TRUE(set(*m, "5GMM cause", {0x60}));
    ASSERT_TRUE(set(*m, "5GMM cause", {0x61}));
    EXPECT_EQ(to_hex(*encode(*m)), "7e006461");
    unset(*m, "5GMM cause");
    EXPECT_EQ(get(*m, "5GMM cause"), nullptr);
    EXPECT_FALSE(set(*m, "No such IE", {0x00}));
    EXPECT_FALSE(make(Epd::mm, 0xFF));
}

TEST(NasBuild, A5gsmMessageGetsItsSessionHeader) {
    auto m = make(Epd::sm, 0xD6);   // 5GSM STATUS
    ASSERT_TRUE(m);
    ASSERT_TRUE(set(*m, "5GSM cause", {0x6F}));
    EXPECT_EQ(to_hex(*encode(*m)), "2e0000d66f");
}

} // namespace
} // namespace ksim::nas
