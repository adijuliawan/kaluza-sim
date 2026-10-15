// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The rtnetlink builders against iproute2 6.19.0 (P1 N9): the goldens are the
// bytes `ip` sent for the same requests, taken with strace -e write= as an
// unprivileged user (the kernel refused them, after they were sent):
//   ip link add name ksim-n2 link lo netns /proc/self/ns/net type ipvlan mode l2   (fd 4, lo = 1)
//   ip addr add 172.30.30.30/24 dev lo
//   ip link set dev lo up
//   ip link del dev lo
// with sequence number 0x6ad006d5.

#include <gtest/gtest.h>

#include <cstring>

#include "net/netlink.hpp"

namespace ksim::net::nl {
namespace {

constexpr std::uint32_t kSeq = 0x6ad006d5;

TEST(Netlink, AnIpvlanInANamespaceIsWhatIproute2Sends) {
    auto m = new_ipvlan(kSeq, Ipvlan{"ksim-n2", 1, 4});
    ASSERT_TRUE(m);
    EXPECT_EQ(to_hex(*m),
              "6000000010000506d506d06a000000000000000000000000000000000000000008001c0004000000080005000100000"
              "00c0003006b73696d2d6e3200240012000b0001006970766c616e0000140002000600010000000000060002000000"
              "0000");
}

TEST(Netlink, AddressUpAndDeleteAreWhatIproute2Sends) {
    EXPECT_EQ(to_hex(new_addr_v4(kSeq, 1, {172, 30, 30, 30}, 24)),
              "2800000014000506d506d06a00000000021800000100000008000200ac1e1e1e08000100ac1e1e1e");
    EXPECT_EQ(to_hex(set_link_up(kSeq, 1)), "2000000010000500d506d06a0000000000000000010000000100000001000000");
    EXPECT_EQ(to_hex(del_link(kSeq, 1)), "2000000011000500d506d06a0000000000000000010000000000000000000000");
}

// P1 N10, the UE's namespaces; the same method, sequence number 0x6ad02004:
//   ip link set dev lo mtu 1400
//   ip route add default dev lo table 101       ip route add default dev lo
//   ip rule add from 10.45.0.2 table 101        ip rule del from 10.45.0.2 table 101
constexpr std::uint32_t kSeq2 = 0x6ad02004;

TEST(Netlink, MtuRoutesAndRulesAreWhatIproute2Sends) {
    EXPECT_EQ(to_hex(set_mtu(kSeq2, 1, 1400)), "28000000100005000420d06a00000000000000000100000000000000000000000800040078050000");
    auto r = new_default_route(kSeq2, 1, 101);
    ASSERT_TRUE(r);
    EXPECT_EQ(to_hex(*r), "24000000180005060420d06a00000000020000006503fd01000000000800040001000000");
    auto main = new_default_route(kSeq2, 1, 254);
    ASSERT_TRUE(main);
    EXPECT_EQ(to_hex(*main), "24000000180005060420d06a0000000002000000fe03fd01000000000800040001000000");
    auto add = new_rule_from(kSeq2, {10, 45, 0, 2}, 101);
    ASSERT_TRUE(add);
    EXPECT_EQ(to_hex(*add), "24000000200005060420d06a00000000020020006500000100000000080002000a2d0002");
    auto del = del_rule_from(kSeq2, {10, 45, 0, 2}, 101);
    ASSERT_TRUE(del);
    EXPECT_EQ(to_hex(*del), "24000000210005000420d06a00000000020020006500000000000000080002000a2d0002");
    EXPECT_FALSE(new_default_route(kSeq2, 0, 101));     // no link
    EXPECT_FALSE(new_default_route(kSeq2, 1, 256));     // a table beyond the header's octet
    EXPECT_FALSE(new_rule_from(kSeq2, {10, 45, 0, 2}, 0));
}

TEST(Netlink, BadIpvlanSpecsAreRefused) {
    EXPECT_FALSE(new_ipvlan(1, Ipvlan{"", 1, 4}));
    EXPECT_FALSE(new_ipvlan(1, Ipvlan{"a-name-too-long-for-ifnamsiz", 1, 4}));
    EXPECT_FALSE(new_ipvlan(1, Ipvlan{"ksim0", 0, 4}));
    EXPECT_FALSE(new_ipvlan(1, Ipvlan{"ksim0", 1, -1}));
}

Bytes error_msg(std::uint32_t seq, std::int32_t error) {
    // nlmsghdr (type NLMSG_ERROR = 2), then nlmsgerr: the error and the request's header.
    Bytes b(36, 0);
    const std::uint32_t len = 36;
    const std::uint16_t type = 2;
    std::memcpy(b.data(), &len, 4);
    std::memcpy(b.data() + 4, &type, 2);
    std::memcpy(b.data() + 8, &seq, 4);
    std::memcpy(b.data() + 16, &error, 4);
    return b;
}

TEST(Netlink, AcknowledgementsAreMatchedToTheirRequest) {
    EXPECT_EQ(*ack_of(error_msg(7, 0), 7), 0);
    EXPECT_EQ(*ack_of(error_msg(7, -1), 7), -1);   // EPERM
    EXPECT_FALSE(ack_of(error_msg(8, 0), 7));       // another request's
    EXPECT_FALSE(ack_of(Bytes(10, 0), 7));
}

} // namespace
} // namespace ksim::net::nl
