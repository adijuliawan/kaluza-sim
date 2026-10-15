// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// IPv4 and ICMP echo (P1 N10): the RFC 1071 checksum, an echo request built
// and read back, and the malformed inputs refused.

#include <gtest/gtest.h>

#include "codec/ip/ipv4.hpp"

namespace ksim::ip {
namespace {

Bytes hex(std::string_view h) {
    Bytes out;
    for (std::size_t i = 0; i + 1 < h.size(); i += 2) {
        out.push_back(static_cast<std::uint8_t>(std::stoi(std::string(h.substr(i, 2)), nullptr, 16)));
    }
    return out;
}

TEST(Ipv4, Rfc1071_TheChecksumOfTheRfcExample) {
    // RFC 1071 4.1: 0001 f203 f4f5 f6f7 sums to ddf2 (one's complement 220d).
    EXPECT_EQ(checksum(hex("0001f203f4f5f6f7")), 0x220D);
    // An odd length pads with a zero octet.
    EXPECT_EQ(checksum(hex("01")), static_cast<std::uint16_t>(~0x0100 & 0xFFFF));
}

TEST(Ipv4, Rfc791_AHeaderWithItsChecksumVerifiesToZero) {
    // The classic example header (Wikipedia's IPv4 header checksum worked example): b861.
    const Bytes h = hex("450000730000400040110000c0a80001c0a800c7");
    Bytes with = h;
    const std::uint16_t c = checksum(h);
    EXPECT_EQ(c, 0xB861);
    with[10] = static_cast<std::uint8_t>(c >> 8);
    with[11] = static_cast<std::uint8_t>(c & 0xFF);
    EXPECT_EQ(checksum(with), 0);
}

TEST(Ipv4, APingIsBuiltAndReadBack) {
    const Bytes p = ping({10, 60, 0, 2}, {10, 60, 0, 1}, 7, 3, 56);
    ASSERT_EQ(p.size(), 20u + 8u + 56u);
    auto d = decode(p);
    ASSERT_TRUE(d) << d.error().what;
    EXPECT_EQ(d->protocol, kIcmp);
    EXPECT_EQ(d->src, (Addr{10, 60, 0, 2}));
    EXPECT_EQ(d->dst, (Addr{10, 60, 0, 1}));
    EXPECT_TRUE(d->dont_fragment);
    auto e = decode_icmp(d->payload);
    ASSERT_TRUE(e && *e);
    EXPECT_FALSE((*e)->reply);
    EXPECT_EQ((*e)->id, 7);
    EXPECT_EQ((*e)->seq, 3);
    EXPECT_EQ((*e)->data.size(), 56u);
    EXPECT_EQ((*e)->data[55], 55);
}

TEST(Ipv4, AnEchoReplyKeepsIdSeqAndData) {
    Echo e{true, 0x1234, 9, Bytes{1, 2, 3}};
    auto back = decode_icmp(encode_icmp(e));
    ASSERT_TRUE(back && *back);
    EXPECT_TRUE((*back)->reply);
    EXPECT_EQ((*back)->id, 0x1234);
    EXPECT_EQ((*back)->seq, 9);
    EXPECT_EQ((*back)->data, (Bytes{1, 2, 3}));
}

TEST(Ipv4, MalformedPacketsAreRefused) {
    Bytes p = ping({1, 1, 1, 1}, {2, 2, 2, 2}, 1, 1, 8);
    EXPECT_EQ(decode(ByteView(p).first(19)).error().code, Errc::truncated);
    Bytes v6 = ping({1, 1, 1, 1}, {2, 2, 2, 2}, 1, 1, 8);
    v6[0] = 0x65;
    EXPECT_EQ(decode(v6).error().code, Errc::malformed);
    Bytes bad_sum = ping({1, 1, 1, 1}, {2, 2, 2, 2}, 1, 1, 8);
    bad_sum[10] ^= 0xFF;
    EXPECT_EQ(decode(bad_sum).error().code, Errc::malformed);
    Bytes long_total = ping({1, 1, 1, 1}, {2, 2, 2, 2}, 1, 1, 8);
    long_total[3] = static_cast<std::uint8_t>(long_total[3] + 1);
    EXPECT_FALSE(decode(long_total));
    Bytes frag = ping({1, 1, 1, 1}, {2, 2, 2, 2}, 1, 1, 8);
    frag[6] = 0x20;   // more fragments
    frag[10] = 0;
    frag[11] = 0;
    const std::uint16_t c = checksum(ByteView(frag).first(20));
    frag[10] = static_cast<std::uint8_t>(c >> 8);
    frag[11] = static_cast<std::uint8_t>(c & 0xFF);
    EXPECT_EQ(decode(frag).error().code, Errc::unsupported);
    Bytes icmp = encode_icmp(Echo{false, 1, 1, {}});
    icmp[2] ^= 1;
    EXPECT_EQ(decode_icmp(icmp).error().code, Errc::malformed);
    // Another ICMP type (destination unreachable) is no echo.
    Bytes unreach{3, 1, 0, 0, 0, 0, 0, 0};
    const std::uint16_t uc = checksum(unreach);
    unreach[2] = static_cast<std::uint8_t>(uc >> 8);
    unreach[3] = static_cast<std::uint8_t>(uc & 0xFF);
    auto u = decode_icmp(unreach);
    ASSERT_TRUE(u);
    EXPECT_FALSE(u->has_value());
}

} // namespace
} // namespace ksim::ip
