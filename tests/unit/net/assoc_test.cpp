// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The IAssoc contract (P1 N2, ADR 0009), on three implementations: memlink in
// virtual time, memlink between two real-time shards, and SCTP over loopback
// with the kernel's own API. Then what only a real SCTP client does: reconnect
// after the server restarts, and retry while refused (TS 38.412 §7; L11).

#include <gtest/gtest.h>

#include <netinet/in.h>
#include <sys/socket.h>

#include <chrono>
#include <condition_variable>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "net/sctp.hpp"
#include "platform/clock.hpp"
#include "platform/memlink.hpp"
#include "platform/shard.hpp"
#include "platform/sim_loop.hpp"

namespace ksim {
namespace {

struct Recorder {
    struct Msg {
        int side;
        Bytes bytes;
        SctpMeta meta;
    };

    void msg(int side, ByteView b, SctpMeta m) {
        const std::lock_guard lock(mu);
        msgs.push_back({side, Bytes(b.begin(), b.end()), m});
    }
    void event(int side, LinkEvent e) {
        const std::lock_guard lock(mu);
        events.emplace_back(side, e);
    }
    std::vector<Msg> msgs_of(int side) {
        const std::lock_guard lock(mu);
        std::vector<Msg> out;
        for (const auto& m : msgs) {
            if (m.side == side) {
                out.push_back(m);
            }
        }
        return out;
    }
    int count(int side, LinkEvent e) {
        const std::lock_guard lock(mu);
        int n = 0;
        for (const auto& [s, ev] : events) {
            n += s == side && ev == e ? 1 : 0;
        }
        return n;
    }

    std::mutex mu;
    std::vector<Msg> msgs;
    std::vector<std::pair<int, LinkEvent>> events;
};

void attach(IAssoc& a, Recorder& r, int side) {
    a.set_handlers([&r, side](ByteView b, SctpMeta m) { r.msg(side, b, m); },
                   [&r, side](LinkEvent e) { r.event(side, e); });
}

/// Runs `fn` on a shard's thread and waits for it.
void on_shard(Shard& s, const std::function<void()>& fn) {
    std::promise<void> p;
    auto f = p.get_future();
    ASSERT_TRUE(s.post([&] {
        fn();
        p.set_value();
    }));
    f.wait();
}

bool poll(const std::function<bool()>& pred, std::chrono::milliseconds limit = std::chrono::seconds(10)) {
    const auto end = std::chrono::steady_clock::now() + limit;
    while (std::chrono::steady_clock::now() < end) {
        if (pred()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return pred();
}

constexpr std::uint16_t kStreams = 4;

struct MemSimHarness {
    SimLoop loop{0};
    std::unique_ptr<MemAssocPair> pair;

    void setup(Recorder& r) {
        pair = std::make_unique<MemAssocPair>(loop, Endpoint::v4(10, 250, 0, 1, 38472), loop,
                                              Endpoint::v4(10, 250, 0, 2, 38472), kStreams,
                                              MemLinkConfig{1, 3, 7});
        attach(pair->a(), r, 0);
        attach(pair->b(), r, 1);
        pair->connect();
        ASSERT_TRUE(wait([&] { return r.count(0, LinkEvent::up) == 1 && r.count(1, LinkEvent::up) == 1; }));
    }
    void on_a(const std::function<void(IAssoc&)>& fn) { fn(pair->a()); }
    void on_b(const std::function<void(IAssoc&)>& fn) { fn(pair->b()); }
    bool wait(const std::function<bool()>& pred) { return loop.run_until(pred, loop.now() + 60'000); }
};

struct MemShardsHarness {
    MonotonicClock clock;
    Shard sa{1, 4096, clock};
    Shard sb{2, 4096, clock};
    std::unique_ptr<MemAssocPair> pair;

    MemShardsHarness() {
        sa.start();
        sb.start();
    }
    ~MemShardsHarness() {
        sa.stop();
        sb.stop();
        sa.join();
        sb.join();
    }
    void setup(Recorder& r) {
        pair = std::make_unique<MemAssocPair>(sa, Endpoint::v4(10, 250, 0, 1, 38462), sb,
                                              Endpoint::v4(10, 250, 0, 2, 38462), kStreams, MemLinkConfig{1, 2, 9});
        on_shard(sa, [&] { attach(pair->a(), r, 0); });
        on_shard(sb, [&] { attach(pair->b(), r, 1); });
        pair->connect();
        ASSERT_TRUE(wait([&] { return r.count(0, LinkEvent::up) == 1 && r.count(1, LinkEvent::up) == 1; }));
    }
    void on_a(const std::function<void(IAssoc&)>& fn) { on_shard(sa, [&] { fn(pair->a()); }); }
    void on_b(const std::function<void(IAssoc&)>& fn) { on_shard(sb, [&] { fn(pair->b()); }); }
    bool wait(const std::function<bool()>& pred) { return poll(pred); }
};

struct SctpHarness {
    MonotonicClock clock;
    Shard shard{3, 4096, clock};
    std::unique_ptr<net::SctpListener> listener;
    std::unique_ptr<net::SctpClient> client;
    std::unique_ptr<IAssoc> server;   // the accepted association
    Recorder* rec = nullptr;
    std::atomic<int> accepted{0};

    SctpHarness() { shard.start(); }
    ~SctpHarness() {
        on_shard(shard, [&] {
            client.reset();
            server.reset();
            listener.reset();
        });
        shard.stop();
        shard.join();
    }
    void listen(std::uint16_t port) {
        net::SctpOptions o;
        o.out_streams = kStreams;
        o.max_in_streams = kStreams;
        auto l = net::SctpListener::listen(shard.reactor(), {Endpoint::v4(127, 0, 0, 1, port)}, o,
                                           [this](std::unique_ptr<IAssoc> a) {
                                               attach(*a, *rec, 1);
                                               server = std::move(a);
                                               ++accepted;
                                           });
        ASSERT_TRUE(l.has_value()) << errc_name(l.error().code) << " " << l.error().offset;
        listener = std::move(*l);
    }
    void setup(Recorder& r) {
        rec = &r;
        on_shard(shard, [&] { listen(0); });
        const Endpoint at = listener->local();
        on_shard(shard, [&] {
            net::SctpOptions o;
            o.out_streams = kStreams;
            o.max_in_streams = kStreams;
            client = std::make_unique<net::SctpClient>(shard.reactor(), shard, std::vector<Endpoint>{},
                                                       std::vector<Endpoint>{at}, o, net::SctpBackoff{50, 400});
            attach(*client, r, 0);
            client->start();
        });
        ASSERT_TRUE(wait([&] { return r.count(0, LinkEvent::up) == 1 && accepted.load() == 1; }));
    }
    void on_a(const std::function<void(IAssoc&)>& fn) { on_shard(shard, [&] { fn(*client); }); }
    void on_b(const std::function<void(IAssoc&)>& fn) { on_shard(shard, [&] { fn(*server); }); }
    bool wait(const std::function<bool()>& pred) { return poll(pred); }
};

template <class H>
class AssocContract : public ::testing::Test {
protected:
    void SetUp() override { h.setup(rec); }
    Recorder rec;
    H h;
};

using Harnesses = ::testing::Types<MemSimHarness, MemShardsHarness, SctpHarness>;
TYPED_TEST_SUITE(AssocContract, Harnesses);

TYPED_TEST(AssocContract, BothEndsAreUpWithTheNegotiatedStreams) {
    for (int side = 0; side < 2; ++side) {
        auto check = [](IAssoc& a) {
            EXPECT_TRUE(a.up());
            EXPECT_EQ(a.out_streams(), kStreams);
            EXPECT_EQ(a.in_streams(), kStreams);
        };
        side == 0 ? this->h.on_a(check) : this->h.on_b(check);
    }
}

TYPED_TEST(AssocContract, MessagesArriveWholeWithTheirStreamAndPpidInOrder) {
    this->h.on_a([](IAssoc& a) {
        for (std::uint8_t i = 0; i < 40; ++i) {
            ASSERT_TRUE(a.send(Bytes{i, 0xAA, i}, SctpMeta{60, static_cast<std::uint16_t>(i % kStreams)}));
        }
    });
    this->h.on_b([](IAssoc& b) {
        for (std::uint8_t i = 0; i < 10; ++i) {
            ASSERT_TRUE(b.send(Bytes{0xBB, i}, SctpMeta{62, 1}));
        }
    });
    ASSERT_TRUE(this->h.wait([&] { return this->rec.msgs_of(1).size() == 40 && this->rec.msgs_of(0).size() == 10; }));
    // In order within each stream (SCTP orders per stream; memlink keeps all order).
    std::vector<int> last(kStreams, -1);
    for (const auto& m : this->rec.msgs_of(1)) {
        ASSERT_EQ(m.bytes.size(), 3u);
        EXPECT_EQ(m.meta.ppid, 60u);
        EXPECT_EQ(m.meta.stream, m.bytes[0] % kStreams);
        EXPECT_GT(static_cast<int>(m.bytes[0]), last[m.meta.stream]);
        last[m.meta.stream] = m.bytes[0];
    }
    int i = 0;
    for (const auto& m : this->rec.msgs_of(0)) {
        EXPECT_EQ(m.bytes, (Bytes{0xBB, static_cast<std::uint8_t>(i++)}));
        EXPECT_EQ(m.meta.ppid, 62u);
        EXPECT_EQ(m.meta.stream, 1);
    }
}

TYPED_TEST(AssocContract, ALargeMessageArrivesWhole) {
    Bytes big(std::size_t{100} * 1024);
    for (std::size_t i = 0; i < big.size(); ++i) {
        big[i] = static_cast<std::uint8_t>(i * 7 + i / 251);
    }
    this->h.on_a([&](IAssoc& a) { ASSERT_TRUE(a.send(big, SctpMeta{60, 2})); });
    ASSERT_TRUE(this->h.wait([&] { return this->rec.msgs_of(1).size() == 1; }));
    EXPECT_EQ(this->rec.msgs_of(1).front().bytes, big);
}

TYPED_TEST(AssocContract, AStreamBeyondTheNegotiatedCountIsRefused) {
    this->h.on_a([](IAssoc& a) {
        const auto r = a.send(Bytes{1}, SctpMeta{60, kStreams});
        ASSERT_FALSE(r);
        EXPECT_EQ(r.error().code, Errc::out_of_range);
        EXPECT_TRUE(a.send(Bytes{2}, SctpMeta{60, kStreams - 1}));
    });
    ASSERT_TRUE(this->h.wait([&] { return this->rec.msgs_of(1).size() == 1; }));
    EXPECT_EQ(this->rec.msgs_of(1).front().bytes, Bytes{2});
}

TYPED_TEST(AssocContract, AGracefulShutdownReachesThePeer) {
    this->h.on_a([](IAssoc& a) { a.shutdown(); });
    ASSERT_TRUE(this->h.wait([&] { return this->rec.count(1, LinkEvent::shutdown) == 1; }));
    this->h.on_b([](IAssoc& b) {
        EXPECT_FALSE(b.up());
        const auto r = b.send(Bytes{1}, SctpMeta{60, 0});
        ASSERT_FALSE(r);
        EXPECT_EQ(r.error().code, Errc::closed);
    });
    EXPECT_EQ(this->rec.count(1, LinkEvent::lost), 0);
}

TYPED_TEST(AssocContract, AnAbortReachesThePeerAsLost) {
    this->h.on_a([](IAssoc& a) {
        a.abort();
        EXPECT_FALSE(a.up());
    });
    ASSERT_TRUE(this->h.wait([&] { return this->rec.count(1, LinkEvent::lost) == 1; }));
    this->h.on_b([](IAssoc& b) { EXPECT_FALSE(b.up()); });
}

// ---- what only a real SCTP client does ---------------------------------------

TEST(SctpClient, ReconnectsAfterTheServerRestarts) {
    Recorder rec;
    SctpHarness h;
    h.setup(rec);
    const std::uint16_t port = h.listener->local().port;
    // The server goes away: its association aborted, its listener closed.
    on_shard(h.shard, [&] {
        h.server->abort();
        h.listener.reset();
    });
    ASSERT_TRUE(h.wait([&] { return rec.count(0, LinkEvent::lost) == 1; }));
    // It comes back on the same port; the client re-associates by itself.
    on_shard(h.shard, [&] {
        h.server.reset();
        h.listen(port);
    });
    ASSERT_TRUE(h.wait([&] { return rec.count(0, LinkEvent::up) == 2 && h.accepted.load() == 2; }));
    on_shard(h.shard, [&] { EXPECT_TRUE(h.client->send(Bytes{9, 9}, SctpMeta{60, 0})); });
    ASSERT_TRUE(h.wait([&] { return rec.msgs_of(1).size() == 1; }));
}

TEST(SctpClient, RetriesWhileRefused) {
    MonotonicClock clock;
    Shard shard{4, 1024, clock};
    shard.start();
    Recorder rec;
    // A port nothing listens on: bind one, learn it, close it.
    std::uint16_t port = 0;
    on_shard(shard, [&] {
        auto l = net::SctpListener::listen(shard.reactor(), {Endpoint::v4(127, 0, 0, 1, 0)}, {}, nullptr);
        ASSERT_TRUE(l.has_value());
        port = (*l)->local().port;
    });
    std::unique_ptr<net::SctpClient> c;
    on_shard(shard, [&] {
        c = std::make_unique<net::SctpClient>(shard.reactor(), shard, std::vector<Endpoint>{},
                                              std::vector<Endpoint>{Endpoint::v4(127, 0, 0, 1, port)}, net::SctpOptions{},
                                              net::SctpBackoff{20, 40});
        attach(*c, rec, 0);
        c->start();
    });
    EXPECT_TRUE(poll([&] { return rec.count(0, LinkEvent::refused) >= 3; }));
    on_shard(shard, [&] {
        EXPECT_GE(c->attempts(), 3u);
        EXPECT_FALSE(c->up());
        c.reset();
    });
    shard.stop();
    shard.join();
}

TEST(SctpClient, TakesItsSocketsFromASourceWhenGivenOne) {
    // ksim in the lab gets its NG-C sockets from ksim-netd (ADR 0009 point 4);
    // here a source that makes them itself, counted, the rest as usual.
    MonotonicClock clock;
    Shard shard{5, 1024, clock};
    shard.start();
    Recorder rec;
    std::unique_ptr<net::SctpListener> l;
    std::unique_ptr<IAssoc> server;
    std::unique_ptr<net::SctpClient> c;
    std::atomic<int> made{0};
    on_shard(shard, [&] {
        auto r = net::SctpListener::listen(shard.reactor(), {Endpoint::v4(127, 0, 0, 1, 0)}, {},
                                           [&](std::unique_ptr<IAssoc> a) { server = std::move(a); });
        ASSERT_TRUE(r.has_value());
        l = std::move(*r);
        net::SocketSource source = [&](int family) -> Result<Fd> {
            ++made;
            Fd fd(::socket(family, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_SCTP));   // blocking: the client fixes it
            if (!fd) {
                return make_error(Errc::io, 0, "test: socket");
            }
            return fd;
        };
        c = std::make_unique<net::SctpClient>(shard.reactor(), shard, std::vector<Endpoint>{Endpoint::v4(127, 0, 0, 1, 0)},
                                              std::vector<Endpoint>{l->local()}, net::SctpOptions{},
                                              net::SctpBackoff{20, 40}, source);
        attach(*c, rec, 0);
        c->start();
    });
    ASSERT_TRUE(poll([&] { return rec.count(0, LinkEvent::up) == 1; }));
    EXPECT_EQ(made.load(), 1);
    on_shard(shard, [&] {
        EXPECT_TRUE(c->send(Bytes{1, 2}, SctpMeta{60, 0}));
        c.reset();
        server.reset();
        l.reset();
    });
    shard.stop();
    shard.join();
}

TEST(SctpListener, TakesItsSocketFromASourceWhenGivenOne) {
    // P2 Q2: the CU-CP listens for F1-C and E1 inside its namespace, on a socket from ksim-netd.
    MonotonicClock clock;
    Shard shard{6, 1024, clock};
    shard.start();
    Recorder rec;
    std::unique_ptr<net::SctpListener> l;
    std::unique_ptr<IAssoc> server;
    std::unique_ptr<net::SctpClient> c;
    std::atomic<int> made{0};
    std::atomic<bool> accepted{false};
    on_shard(shard, [&] {
        net::SocketSource source = [&](int family) -> Result<Fd> {
            ++made;
            Fd fd(::socket(family, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_SCTP));   // blocking: the listener fixes it
            if (!fd) {
                return make_error(Errc::io, 0, "test: socket");
            }
            return fd;
        };
        auto r = net::SctpListener::listen(
            shard.reactor(), {Endpoint::v4(127, 0, 0, 1, 0)}, {},
            [&](std::unique_ptr<IAssoc> a) {
                server = std::move(a);
                accepted = true;
            },
            source);
        ASSERT_TRUE(r.has_value());
        l = std::move(*r);
        c = std::make_unique<net::SctpClient>(shard.reactor(), shard, std::vector<Endpoint>{Endpoint::v4(127, 0, 0, 1, 0)},
                                              std::vector<Endpoint>{l->local()}, net::SctpOptions{},
                                              net::SctpBackoff{20, 40});
        attach(*c, rec, 0);
        c->start();
    });
    ASSERT_TRUE(poll([&] { return rec.count(0, LinkEvent::up) == 1 && accepted.load(); }));
    EXPECT_EQ(made.load(), 1);
    on_shard(shard, [&] {
        c.reset();
        server.reset();
        l.reset();
    });
    shard.stop();
    shard.join();
}

} // namespace
} // namespace ksim
