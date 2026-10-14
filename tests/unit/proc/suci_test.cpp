// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The subscription read from the USIM and the null-scheme SUCI (P1 N5; TS
// 31.102 4.2.2, 4.2.18, 4.4.11.11; TS 24.501 9.11.3.4; TS 33.501 6.12.2).

#include <gtest/gtest.h>

#include "proc/ue/nas_mm/suci.hpp"

namespace ksim::proc::ue {
namespace {

Bytes h(const char* s) { return *from_hex(s); }

TEST(Suci, TheImsiAndTheMncLengthComeFromEfImsiAndEfAd) {
    auto s = read_subscription(h("080910100000030010"), h("00000002"));
    ASSERT_TRUE(s);
    EXPECT_EQ(s->imsi, "001010000300001");
    EXPECT_EQ(s->home.mcc, "001");
    EXPECT_EQ(s->home.mnc, "01");
    EXPECT_EQ(s->msin, "0000300001");
    // A three-digit MNC (EF.AD octet 4 = 3) moves a digit from the MSIN.
    auto t = read_subscription(h("080910100000030010"), h("00000003"));
    ASSERT_TRUE(t);
    EXPECT_EQ(t->home.mnc, "010");
    EXPECT_EQ(t->msin, "000300001");
    // An even number of digits ends in the filler.
    auto e = read_subscription(h("0801103254769810f0"), h("00000002"));
    ASSERT_TRUE(e);
    EXPECT_EQ(e->imsi, "00123456789010");   // 14 digits
}

TEST(Suci, ABadEfImsiIsRefused) {
    EXPECT_FALSE(read_subscription(h("00"), h("00000002")));                  // no length
    EXPECT_FALSE(read_subscription(h("0809101000"), h("00000002")));          // shorter than its length
    EXPECT_FALSE(read_subscription(h("08081010000003001f"), h("00000002")));  // type 0 is not an IMSI
    EXPECT_FALSE(read_subscription(h("0809101000000300a0"), h("00000002")));  // a digit A
    EXPECT_FALSE(read_subscription(h("0801103254769810"), h("00000002")));    // even, no filler octet
}

TEST(Suci, TheRoutingIndicatorIsItsDigitsOrZero) {
    EXPECT_EQ(read_routing_indicator(h("0000ffff")), "0000");
    EXPECT_EQ(read_routing_indicator(h("21f3ffff")), "123");
    EXPECT_EQ(read_routing_indicator(h("ffffffff")), "0");
    EXPECT_EQ(read_routing_indicator({}), "0");
}

TEST(Suci, TheNullSchemeOutputIsTheMsin) {
    auto s = read_subscription(h("080910100000030010"), h("00000002"));
    ASSERT_TRUE(s);
    const auto id = null_suci(*s, "0000");
    auto wire = id.encode();
    ASSERT_TRUE(wire);
    // SUCI (type 1, IMSI format), 001/01, routing indicator 0000, scheme 0, key 0, MSIN 0000300001.
    EXPECT_EQ(to_hex(*wire), "0100f11000000000" "0000030010");
    EXPECT_EQ(id.null_scheme_msin(), "0000300001");
}

} // namespace
} // namespace ksim::proc::ue
