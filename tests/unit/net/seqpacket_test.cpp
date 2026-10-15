// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// UNIX SOCK_SEQPACKET behind IChannel (P2 Q2): message boundaries kept both
// ways, a burst larger than the socket buffer queued and delivered in order, a
// close seen by the peer, and nothing listening reported as closed.

#include <gtest/gtest.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <functional>
#include <future>
#include <memory>
#include <thread>
#include <vector>

#include "net/seqpacket.hpp"
#include "platform/clock.hpp"
#include "platform/shard.hpp"

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

class Seqpacket : public ::testing::Test {
protected:
    void SetUp() override {
        path_ = "/tmp/ksim-seqpacket-" + std::to_string(::getpid()) + ".sock";
        shard_ = std::make_unique<Shard>(0, 1U << 12, clock_);
        shard_->start();
    }
    void TearDown() override {
        on_shard(*shard_, [&] {
            client_.reset();
            server_.reset();
            listener_.reset();
        });
        shard_->stop();
        shard_->join();
        EXPECT_FALSE(std::filesystem::exists(path_));   // the listener took its file away
    }

    MonotonicClock clock_;
    std::unique_ptr<Shard> shard_;
    std::string path_;
    std::unique_ptr<net::SeqpacketListener> listener_;
    std::unique_ptr<IChannel> server_;
    std::unique_ptr<IChannel> client_;
};

TEST_F(Seqpacket, MessagesKeepTheirBoundariesBothWaysAndInOrder) {
    std::vector<Bytes> at_server;   // touched on the shard only
    std::vector<Bytes> at_client;
    std::atomic<std::size_t> n_server{0};
    std::atomic<std::size_t> n_client{0};
    on_shard(*shard_, [&] {
        auto l = net::SeqpacketListener::listen(shard_->reactor(), path_, [&](std::unique_ptr<IChannel> c) {
            server_ = std::move(c);
            server_->set_handlers(
                [&](ByteView m) {
                    at_server.emplace_back(m.begin(), m.end());
                    ++n_server;
                },
                [] {});
        });
        ASSERT_TRUE(l);
        listener_ = std::move(*l);
        auto c = net::seqpacket_connect(shard_->reactor(), path_);
        ASSERT_TRUE(c);
        client_ = std::move(*c);
        client_->set_handlers(
            [&](ByteView m) {
                at_client.emplace_back(m.begin(), m.end());
                ++n_client;
            },
            [] {});
        for (std::uint8_t i = 1; i <= 3; ++i) {
            ASSERT_TRUE(client_->send(Bytes(static_cast<std::size_t>(i) * 100U, i)));
        }
    });
    ASSERT_TRUE(poll([&] { return n_server == 3; }));
    on_shard(*shard_, [&] {
        for (std::size_t i = 0; i < 3; ++i) {
            EXPECT_EQ(at_server[i], Bytes((i + 1) * 100U, static_cast<std::uint8_t>(i + 1)));
        }
        ASSERT_TRUE(server_->send(Bytes{7, 7}));
    });
    ASSERT_TRUE(poll([&] { return n_client == 1; }));
    on_shard(*shard_, [&] { EXPECT_EQ(at_client[0], (Bytes{7, 7})); });
}

TEST_F(Seqpacket, ABurstBeyondTheSocketBufferIsQueuedAndArrivesWhole) {
    std::atomic<std::size_t> got{0};
    std::atomic<bool> in_order{true};
    on_shard(*shard_, [&] {
        auto l = net::SeqpacketListener::listen(shard_->reactor(), path_, [&](std::unique_ptr<IChannel> c) {
            server_ = std::move(c);
            server_->set_handlers(
                [&](ByteView m) {
                    const std::size_t n = got.load();
                    if (m.size() != 9000 || m[0] != static_cast<std::uint8_t>(n & 0xFF)) {
                        in_order = false;
                    }
                    got = n + 1;
                },
                [] {});
        });
        ASSERT_TRUE(l);
        listener_ = std::move(*l);
        auto c = net::seqpacket_connect(shard_->reactor(), path_);
        ASSERT_TRUE(c);
        client_ = std::move(*c);
        client_->set_handlers([](ByteView) {}, [] {});
        for (std::size_t i = 0; i < 2000; ++i) {   // 18 MB, far beyond the default buffer
            ASSERT_TRUE(client_->send(Bytes(9000, static_cast<std::uint8_t>(i & 0xFF))));
        }
    });
    ASSERT_TRUE(poll([&] { return got == 2000; }));
    EXPECT_TRUE(in_order);
}

TEST_F(Seqpacket, ACloseReachesThePeerAndNothingListeningIsClosed) {
    std::atomic<bool> closed{false};
    std::atomic<bool> accepted{false};
    on_shard(*shard_, [&] {
        auto none = net::seqpacket_connect(shard_->reactor(), path_);
        ASSERT_FALSE(none);
        EXPECT_EQ(none.error().code, Errc::closed);
        auto l = net::SeqpacketListener::listen(shard_->reactor(), path_, [&](std::unique_ptr<IChannel> c) {
            server_ = std::move(c);
            server_->set_handlers([](ByteView) {}, [&] { closed = true; });
            accepted = true;
        });
        ASSERT_TRUE(l);
        listener_ = std::move(*l);
        auto c = net::seqpacket_connect(shard_->reactor(), path_);
        ASSERT_TRUE(c);
        client_ = std::move(*c);
        client_->set_handlers([](ByteView) {}, [] {});
    });
    ASSERT_TRUE(poll([&] { return accepted.load(); }));
    on_shard(*shard_, [&] { client_->close(); });
    ASSERT_TRUE(poll([&] { return closed.load(); }));
    on_shard(*shard_, [&] { EXPECT_FALSE(client_->send(Bytes{1})); });
}

} // namespace
} // namespace ksim
