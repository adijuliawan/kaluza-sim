// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The platform runtime (plan M13): the bounded MPSC inbox (with a multi-thread
// stress run, 10^8 messages under TSan for the milestone, KSIM_MPSC_STRESS),
// the reactor with its eventfd and timerfd, the shard, and the log façade.

#include <gtest/gtest.h>

#include <sys/epoll.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <string>
#include <thread>
#include <vector>

#include "platform/log.hpp"
#include "platform/mpsc.hpp"
#include "platform/reactor.hpp"
#include "platform/secret.hpp"
#include "platform/shard.hpp"

namespace ksim {
namespace {

static_assert(!fmt::is_formattable<SecretBytes>::value, "a key must not reach a log line");

TEST(Mpsc, FifoAndFull) {
    MpscQueue<int> q(4);
    EXPECT_EQ(q.capacity(), 4U);
    for (int i = 0; i < 4; ++i) {
        EXPECT_TRUE(q.try_push(i));
    }
    int extra = 99;
    EXPECT_FALSE(q.try_push(extra));
    EXPECT_EQ(extra, 99);   // left as it was
    for (int i = 0; i < 4; ++i) {
        EXPECT_EQ(*q.try_pop(), i);
    }
    EXPECT_FALSE(q.try_pop());
    EXPECT_TRUE(q.try_push(7));   // a lap later
    EXPECT_EQ(*q.try_pop(), 7);
}

TEST(Mpsc, MoveOnlyAndDestroyedOnce) {
    MpscQueue<std::unique_ptr<int>> q(8);
    q.try_push(std::make_unique<int>(5));
    q.try_push(std::make_unique<int>(6));
    auto first = q.try_pop();
    ASSERT_TRUE(first.has_value() && *first != nullptr);
    EXPECT_EQ(**first, 5);
    // the second is destroyed by the queue's destructor (ASan: no leak)
}

// Producers each send a numbered stream; the consumer sees every message once
// and each producer's in order.
TEST(Mpsc, ManyProducersOneConsumer) {
    const char* env = std::getenv("KSIM_MPSC_STRESS");
    const std::uint64_t total = env != nullptr ? std::strtoull(env, nullptr, 10) : 2'000'000;
    constexpr unsigned kProducers = 4;
    const std::uint64_t each = total / kProducers;
    MpscQueue<std::uint64_t> q(1024);
    std::vector<std::thread> producers;
    producers.reserve(kProducers);
    for (unsigned p = 0; p < kProducers; ++p) {
        producers.emplace_back([&q, p, each] {
            for (std::uint64_t i = 0; i < each; ++i) {
                std::uint64_t v = (std::uint64_t{p} << 56) | i;
                while (!q.try_push(v)) {
                    std::this_thread::yield();
                }
            }
        });
    }
    std::vector<std::uint64_t> next(kProducers, 0);
    std::uint64_t received = 0;
    bool in_order = true;
    while (received < each * kProducers) {
        auto v = q.try_pop();
        if (!v) {
            std::this_thread::yield();
            continue;
        }
        const auto p = static_cast<unsigned>(*v >> 56);
        const std::uint64_t i = *v & ((1ULL << 56) - 1);
        in_order = in_order && p < kProducers && i == next[p];
        ++next[p];
        ++received;
    }
    for (auto& t : producers) {
        t.join();
    }
    EXPECT_TRUE(in_order);
    EXPECT_FALSE(q.try_pop());
    RecordProperty("messages", std::to_string(received));
}

TEST(Reactor, EventFdAndSelfRemoval) {
    Reactor r;
    EventFd e;
    int calls = 0;
    ASSERT_TRUE(r.add(e.fd(), EPOLLIN, [&](std::uint32_t) {
        ++calls;
        EXPECT_EQ(e.drain(), 2U);
        (void)r.remove(e.fd());   // a handler may remove itself
    }));
    e.notify();
    e.notify();
    EXPECT_EQ(*r.run_once(1000), 1);
    EXPECT_EQ(calls, 1);
    EXPECT_EQ(r.size(), 0U);
    EXPECT_FALSE(r.remove(e.fd()));
}

TEST(Reactor, TimerFdAtAnAbsoluteTime) {
    Reactor r;
    TimerFd t;
    MonotonicClock clock;
    bool fired = false;
    ASSERT_TRUE(r.add(t.fd(), EPOLLIN, [&](std::uint32_t) {
        t.drain();
        fired = true;
    }));
    const Millis start = clock.now_ms();
    ASSERT_TRUE(t.arm_at(start + 20));
    while (!fired) {
        ASSERT_TRUE(r.run_once(1000));
    }
    EXPECT_GE(clock.now_ms(), start + 20);
    ASSERT_TRUE(t.arm_at(start + 5000));
    ASSERT_TRUE(t.disarm());
    EXPECT_EQ(*r.run_once(30), 0);
}

TEST(Shard, TasksRunOnItsThreadAndTimersFire) {
    MonotonicClock clock;
    Shard s(3, 64, clock);
    s.start();
    std::atomic<int> ran{0};
    std::atomic<bool> on_shard{true};
    std::atomic<Millis> fired_at{0};
    Millis scheduled_at = 0;
    std::atomic<bool> scheduled{false};
    for (int i = 0; i < 10; ++i) {
        while (!s.post([&] {
            on_shard = on_shard && Shard::current() == &s;
            ++ran;
        })) {
            std::this_thread::yield();
        }
    }
    ASSERT_TRUE(s.post([&] {
        scheduled_at = s.now();
        s.start_timer(30, [&] { fired_at = s.now(); });
        s.stop_timer(s.start_timer(10, [&] { fired_at = -1; }));
        scheduled = true;
    }));
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (fired_at.load() == 0 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    s.stop();
    s.join();
    EXPECT_EQ(ran.load(), 10);
    EXPECT_TRUE(on_shard.load());
    ASSERT_TRUE(scheduled.load());
    EXPECT_GE(fired_at.load(), scheduled_at + 30);   // not early, and the cancelled one never fired
    EXPECT_LT(fired_at.load(), scheduled_at + 1000);
    EXPECT_EQ(s.timers_fired(), 1U);
    EXPECT_EQ(Shard::current(), nullptr);
}

// A loop blocked in a syscall fires no late timer, so the watchdog's lag check never
// runs; the heartbeat's monitor names the syscall and the descriptor (LW1a, P2 Q7).
TEST(Shard, ALoopBlockedInASyscallIsReportedWithItsDescriptor) {
    MonotonicClock clock;
    Shard s(5, 64, clock);
    std::atomic<int> lags{0};
    s.set_watchdog(250, [&](Millis) { ++lags; }, 300);
    int p[2] = {-1, -1};
    ASSERT_EQ(::pipe(p), 0);
    testing::internal::CaptureStderr();
    s.start();
    ASSERT_TRUE(s.post([&] {
        char c = 0;
        (void)!::read(p[0], &c, 1);   // blocks until the test writes
    }));
    std::this_thread::sleep_for(std::chrono::milliseconds(1'500));
    const char c = 'x';
    ASSERT_EQ(::write(p[1], &c, 1), 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    s.stop();
    s.join();
    const std::string err = testing::internal::GetCapturedStderr();
    ::close(p[0]);
    ::close(p[1]);
    EXPECT_NE(err.find("KSIM_LOOP_STUCK shard=5 "), std::string::npos) << err;
    EXPECT_NE(err.find("syscall=\"0 "), std::string::npos) << err;   // read(2) on x86-64
    EXPECT_NE(err.find("fd1=pipe:["), std::string::npos) << err;
    EXPECT_EQ(err.find("KSIM_LOOP_STUCK", err.find("KSIM_LOOP_STUCK") + 1), std::string::npos);   // once
    EXPECT_GE(lags.load(), 1);   // and once unblocked, the late heartbeat is a lag
}

TEST(Shard, AFullInboxRefusesAndManyThreadsPost) {
    MonotonicClock clock;
    Shard s(0, 16, clock);
    // not started: the inbox fills
    int accepted = 0;
    for (int i = 0; i < 20; ++i) {
        accepted += s.post([] {}) ? 1 : 0;
    }
    EXPECT_EQ(accepted, 16);
    s.start();
    std::atomic<std::uint64_t> sum{0};
    std::vector<std::thread> posters;
    posters.reserve(4);
    for (int p = 0; p < 4; ++p) {
        posters.emplace_back([&s, &sum] {
            for (int i = 0; i < 20000; ++i) {
                while (!s.post([&sum] { sum.fetch_add(1, std::memory_order_relaxed); })) {
                    std::this_thread::yield();
                }
            }
        });
    }
    for (auto& t : posters) {
        t.join();
    }
    while (s.tasks_run() < 16 + 80000) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    s.stop();
    s.join();
    EXPECT_EQ(sum.load(), 80000U);
}

TEST(Log, LinesCarryLevelAreaAndShard) {
    std::vector<std::string> lines;
    log::set_sink([&](std::string_view l) { lines.emplace_back(l); });
    log::set_level(log::Level::info);
    log::info("test", "hello {}", 42);
    log::debug("test", "not shown {}", 1);
    MonotonicClock clock;
    Shard s(7, 8, clock);
    s.start();
    std::atomic<bool> done{false};
    ASSERT_TRUE(s.post([&] {
        log::warn("shard", "from the shard");
        done = true;
    }));
    while (!done) {
        std::this_thread::yield();
    }
    s.stop();
    s.join();
    log::set_sink(nullptr);
    ASSERT_EQ(lines.size(), 2U);
    EXPECT_NE(lines[0].find(" I test [-] hello 42\n"), std::string::npos) << lines[0];
    EXPECT_EQ(lines[0][10], 'T');
    EXPECT_NE(lines[1].find(" W shard [s7] from the shard"), std::string::npos) << lines[1];
}

} // namespace
} // namespace ksim
