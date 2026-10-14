// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Datagrams, streams and endpoints (P1 N2): memlink's network in virtual time,
// UDP and TCP over loopback, and Endpoint parsing.

#include <gtest/gtest.h>

#include <chrono>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "net/tcp.hpp"
#include "net/udp.hpp"
#include "platform/clock.hpp"
#include "platform/memlink.hpp"
#include "platform/shard.hpp"
#include "platform/sim_loop.hpp"

namespace ksim {
namespace {

void on_shard(Shard& s, const std::function<void()>& fn) {
    std::promise<void> p;
    auto f = p.get_future();
    ASSERT_TRUE(s.post([&] {
        fn();
        p.set_value();
    }));
    f.wait();
}

bool poll(const std::function<bool()>& pred) {
    const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (std::chrono::steady_clock::now() < end) {
        if (pred()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return pred();
}

TEST(Endpoint, ParsesAndPrintsBothFamilies) {
    const auto a = Endpoint::parse("172.30.30.30:38412");
    ASSERT_TRUE(a);
    EXPECT_EQ(a->to_string(), "172.30.30.30:38412");
    EXPECT_EQ(*a, Endpoint::v4(172, 30, 30, 30, 38412));
    const auto b = Endpoint::parse("[2001:db8::1]:2152");
    ASSERT_TRUE(b);
    EXPECT_EQ(b->family, Endpoint::Family::v6);
    EXPECT_EQ(b->to_string(), "[2001:db8::1]:2152");
    EXPECT_FALSE(Endpoint::parse("kaluza-uesim:22"));     // numeric only
    EXPECT_FALSE(Endpoint::parse("1.2.3.4:70000"));
    EXPECT_FALSE(Endpoint::parse("2001:db8::1:2152"));    // IPv6 needs brackets
    EXPECT_FALSE(Endpoint::parse("1.2.3.4"));
}

TEST(Endpoint, PrefixMembership) {
    const Endpoint lab = Endpoint::v4(172, 30, 0, 0, 0);
    EXPECT_TRUE(Endpoint::v4(172, 30, 30, 1, 38412).in(lab, 16));
    EXPECT_FALSE(Endpoint::v4(172, 31, 30, 1, 38412).in(lab, 16));
    EXPECT_TRUE(Endpoint::v4(127, 0, 0, 2, 1).in(Endpoint::v4(127, 0, 0, 0, 0), 8));
    EXPECT_FALSE(Endpoint::v4(172, 30, 30, 1, 1).in(*Endpoint::parse("::", 0), 0));   // other family
}

TEST(MemNet, DeliversAfterAHopInOrderAndDropsTheUnbound) {
    SimLoop loop(0);
    MemNet net(MemLinkConfig{1, 4, 11});
    auto a = net.bind(loop, Endpoint::v4(10, 0, 0, 1, 2152));
    auto b = net.bind(loop, Endpoint::v4(10, 0, 0, 2, 2152));
    ASSERT_TRUE(a && b);
    EXPECT_FALSE(net.bind(loop, Endpoint::v4(10, 0, 0, 1, 2152)));   // bound already
    std::vector<std::pair<Millis, std::uint8_t>> got;
    (*b)->set_handler([&](ByteView p, const Endpoint& from) {
        EXPECT_EQ(from, Endpoint::v4(10, 0, 0, 1, 2152));
        got.emplace_back(loop.now(), p[0]);
    });
    for (std::uint8_t i = 0; i < 20; ++i) {
        ASSERT_TRUE((*a)->send_to(Bytes{i}, Endpoint::v4(10, 0, 0, 2, 2152)));
    }
    ASSERT_TRUE((*a)->send_to(Bytes{1}, Endpoint::v4(10, 0, 0, 9, 2152)));
    loop.run_until(1000);
    ASSERT_EQ(got.size(), 20u);
    for (std::size_t i = 0; i < got.size(); ++i) {
        EXPECT_EQ(got[i].second, i);
        EXPECT_GE(got[i].first, 1);
        EXPECT_LE(got[i].first, 5);
    }
    EXPECT_EQ(net.dropped(), 1u);
    EXPECT_EQ((*a)->dropped(), 1u);
    // A destroyed socket frees its address, and what was in flight to it is dropped quietly.
    ASSERT_TRUE((*a)->send_to(Bytes{7}, Endpoint::v4(10, 0, 0, 2, 2152)));
    b->reset();
    loop.run_until(2000);
    EXPECT_TRUE(net.bind(loop, Endpoint::v4(10, 0, 0, 2, 2152)));
}

TEST(Udp, CarriesDatagramsOverLoopbackWithTheirSender) {
    MonotonicClock clock;
    Shard shard{5, 1024, clock};
    shard.start();
    std::unique_ptr<net::UdpSocket> a;
    std::unique_ptr<net::UdpSocket> b;
    std::mutex mu;
    std::vector<Bytes> got;
    Endpoint from_seen;
    on_shard(shard, [&] {
        auto ra = net::UdpSocket::bind(shard.reactor(), Endpoint::v4(127, 0, 0, 1, 0));
        auto rb = net::UdpSocket::bind(shard.reactor(), Endpoint::v4(127, 0, 0, 1, 0));
        ASSERT_TRUE(ra && rb);
        a = std::move(*ra);
        b = std::move(*rb);
        b->set_handler([&](ByteView p, const Endpoint& from) {
            const std::lock_guard lock(mu);
            got.emplace_back(p.begin(), p.end());
            from_seen = from;
        });
    });
    // Ten datagrams a millisecond, so the receiver (on the same shard) reads
    // between batches and its socket buffer never overflows.
    std::function<void(int)> batch = [&](int first) {
        for (int i = first; i < first + 10; ++i) {
            Bytes d(1400, static_cast<std::uint8_t>(i));
            ASSERT_TRUE(a->send_to(d, b->local()));
        }
        if (first + 10 < 200) {
            shard.start_timer(1, [&batch, first] { batch(first + 10); });
        }
    };
    on_shard(shard, [&] {
        batch(0);
        const auto bad = a->send_to(Bytes{1}, *Endpoint::parse("[::1]:2152"));
        ASSERT_FALSE(bad);
        EXPECT_EQ(bad.error().code, Errc::invalid_argument);
    });
    ASSERT_TRUE(poll([&] {
        const std::lock_guard lock(mu);
        return got.size() == 200;
    }));
    {
        const std::lock_guard lock(mu);
        for (std::size_t i = 0; i < got.size(); ++i) {
            EXPECT_EQ(got[i], Bytes(1400, static_cast<std::uint8_t>(i)));
        }
        EXPECT_EQ(from_seen, a->local());
    }
    on_shard(shard, [&] { EXPECT_EQ(a->dropped(), 0u); });
    on_shard(shard, [&] {
        a.reset();
        b.reset();
    });
    shard.stop();
    shard.join();
}

TEST(Tcp, EchoesAndReportsTheClose) {
    MonotonicClock clock;
    Shard shard{6, 1024, clock};
    shard.start();
    std::unique_ptr<net::TcpListener> listener;
    std::unique_ptr<IStream> server;
    std::unique_ptr<IStream> client;
    std::mutex mu;
    Bytes echoed;
    bool closed = false;
    on_shard(shard, [&] {
        auto l = net::TcpListener::listen(shard.reactor(), Endpoint::v4(127, 0, 0, 1, 0), [&](std::unique_ptr<IStream> s) {
            server = std::move(s);
            server->set_handlers([&](ByteView d) { (void)server->send(d); }, [] {});
        });
        ASSERT_TRUE(l);
        listener = std::move(*l);
        auto c = net::tcp_connect(shard.reactor(), listener->local());
        ASSERT_TRUE(c);
        client = std::move(*c);
        client->set_handlers(
            [&](ByteView d) {
                const std::lock_guard lock(mu);
                echoed.insert(echoed.end(), d.begin(), d.end());
            },
            [&] {
                const std::lock_guard lock(mu);
                closed = true;
            });
        Bytes big(50'000);
        for (std::size_t i = 0; i < big.size(); ++i) {
            big[i] = static_cast<std::uint8_t>(i);
        }
        ASSERT_TRUE(client->send(big));   // queued before the connect completes
    });
    ASSERT_TRUE(poll([&] {
        const std::lock_guard lock(mu);
        return echoed.size() == 50'000;
    }));
    for (std::size_t i = 0; i < echoed.size(); ++i) {
        ASSERT_EQ(echoed[i], static_cast<std::uint8_t>(i));
    }
    on_shard(shard, [&] { server->close(); });
    ASSERT_TRUE(poll([&] {
        const std::lock_guard lock(mu);
        return closed;
    }));
    on_shard(shard, [&] {
        EXPECT_FALSE(client->open());
        EXPECT_EQ(client->send(Bytes{1}).error().code, Errc::closed);
        client.reset();
        server.reset();
        listener.reset();
    });
    shard.stop();
    shard.join();
}

} // namespace
} // namespace ksim
