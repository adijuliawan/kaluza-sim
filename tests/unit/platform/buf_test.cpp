// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include <gtest/gtest.h>

#include <cstdint>

#include "platform/buf.hpp"

using namespace ksim;

TEST(ByteReader, ReadsNetworkOrderAndStopsAtTheEnd) {
    const Bytes in = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a};
    ByteReader r(in);
    EXPECT_EQ(*r.u8(), 0x01);
    EXPECT_EQ(*r.u16(), 0x0203);
    EXPECT_EQ(*r.u24(), 0x040506U);
    EXPECT_EQ(*r.u32(), 0x0708090aU);
    EXPECT_TRUE(r.empty());
    auto past = r.u8();
    ASSERT_FALSE(past);
    EXPECT_EQ(past.error().code, Errc::truncated);
    EXPECT_EQ(past.error().offset, 10U);
}

TEST(ByteReader, TakeIsAViewAndRespectsBounds) {
    const Bytes in = {0xaa, 0xbb, 0xcc};
    ByteReader r(in);
    auto v = r.take(2);
    ASSERT_TRUE(v);
    EXPECT_EQ(v->size(), 2U);
    EXPECT_EQ(v->data(), in.data());
    EXPECT_FALSE(r.take(2));
    EXPECT_EQ(r.offset(), 2U);  // a failed read does not move the cursor
    EXPECT_EQ(*r.peek(), 0xcc);
    EXPECT_EQ(r.rest().size(), 1U);
}

TEST(ByteWriter, WritesAndPatchesLengths) {
    ByteWriter w;
    w.u8(0x7e);
    const std::size_t len_at = w.size();
    w.u16(0);
    w.u24(0x112233);
    w.u32(0x44556677);
    w.u64(0x8899aabbccddeeffULL);
    ASSERT_TRUE(w.patch_u16(len_at, static_cast<std::uint16_t>(w.size() - len_at - 2)));
    EXPECT_EQ(to_hex(w.data()), "7e000f1122334455667788" "99aabbccddeeff");
    EXPECT_FALSE(w.patch_u16(w.size() - 1, 0));
}

TEST(BitBuffers, RoundTripMsbFirst) {
    BitWriter w;
    ASSERT_TRUE(w.bits(0b101, 3));
    w.bit(true);
    ASSERT_TRUE(w.bits(0x3f, 6));
    ASSERT_TRUE(w.bits(0xdeadbeefcafeULL, 48));
    w.align();
    EXPECT_EQ(w.bit_size(), 64U);

    BitReader r(w.data());
    EXPECT_EQ(*r.bits(3), 0b101U);
    EXPECT_TRUE(*r.bit());
    EXPECT_EQ(*r.bits(6), 0x3fU);
    EXPECT_EQ(*r.bits(48), 0xdeadbeefcafeULL);
    EXPECT_EQ(r.bits_left(), 6U);
    EXPECT_FALSE(r.bits(7));
}

TEST(BitBuffers, RejectsValuesWiderThanTheField) {
    BitWriter w;
    auto r = w.bits(0x10, 4);
    ASSERT_FALSE(r);
    EXPECT_EQ(r.error().code, Errc::out_of_range);
}

TEST(Hex, RoundTripAndErrors) {
    auto b = from_hex("DE:ad be_EF\n00");
    ASSERT_TRUE(b);
    EXPECT_EQ(to_hex(*b), "deadbeef00");
    EXPECT_EQ(from_hex("abc").error().code, Errc::malformed);
    EXPECT_EQ(from_hex("zz").error().code, Errc::malformed);
    EXPECT_TRUE(from_hex("")->empty());
}
