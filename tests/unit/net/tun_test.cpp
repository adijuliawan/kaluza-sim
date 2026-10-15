// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The TUN port without root (P1 N11): any packet-preserving descriptor works
// as a TUN's does, so a SOCK_SEQPACKET socketpair stands in for the device:
// packets in both directions on the reactor, boundaries kept, a full device
// counted as a drop.

#include <gtest/gtest.h>

#include <sys/socket.h>
#include <unistd.h>

#include "net/tun.hpp"
#include "platform/reactor.hpp"

namespace ksim::net {
namespace {

TEST(TunPort, CarriesPacketsBothWaysWithTheirBoundaries) {
    int sv[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv), 0);
    Fd kernel(sv[1]);
    Reactor reactor;
    auto port = TunPort::adopt(reactor, Fd(sv[0]));
    ASSERT_TRUE(port);
    std::vector<Bytes> got;
    (*port)->set_handler([&](ByteView p) { got.emplace_back(p.begin(), p.end()); });
    const Bytes a{0x45, 1, 2, 3};
    const Bytes b(1400, 0x45);
    ASSERT_EQ(::write(kernel.get(), a.data(), a.size()), 4);
    ASSERT_EQ(::write(kernel.get(), b.data(), b.size()), 1400);
    for (int i = 0; i < 10 && got.size() < 2; ++i) {
        ASSERT_TRUE(reactor.run_once(100));
    }
    ASSERT_EQ(got.size(), 2u);
    EXPECT_EQ(got[0], a);
    EXPECT_EQ(got[1].size(), 1400u);
    EXPECT_EQ((*port)->received(), 2u);
    ASSERT_TRUE((*port)->write(a));
    Bytes back(64);
    EXPECT_EQ(::read(kernel.get(), back.data(), back.size()), 4);
    EXPECT_EQ((*port)->dropped(), 0u);
}

TEST(TunPort, AFullDeviceDropsAndCountsInsteadOfBlocking) {
    int sv[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv), 0);
    Fd kernel(sv[1]);
    Reactor reactor;
    auto port = TunPort::adopt(reactor, Fd(sv[0]));
    ASSERT_TRUE(port);
    const Bytes p(1400, 0x45);
    for (int i = 0; i < 10'000 && (*port)->dropped() == 0; ++i) {
        ASSERT_TRUE((*port)->write(p));   // nobody reads the other side
    }
    EXPECT_GT((*port)->dropped(), 0u);
    EXPECT_FALSE(TunPort::adopt(reactor, Fd()));
}

} // namespace
} // namespace ksim::net
