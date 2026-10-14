// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Procedure coroutines (P1 N1): tasks, timers, mailboxes and cancellation in
// virtual time, with a property test that a cancel and an expiry never both
// win and no frame or timer is left behind.

#include <gtest/gtest.h>

#include <stdexcept>
#include <string>
#include <vector>

#include "platform/coro.hpp"
#include "platform/rng.hpp"
#include "platform/sim_loop.hpp"

namespace ksim::coro {
namespace {

Task<int> add_later(SimLoop& loop, int a, int b) {
    co_await sleep_for(loop, 50);
    co_return a + b;
}

Task<int> twice(SimLoop& loop, int a) {
    const int x = co_await add_later(loop, a, a);
    const int y = co_await add_later(loop, x, 0);
    co_return y;
}

Task<void> fails(SimLoop& loop) {
    co_await sleep_for(loop, 1);
    throw std::runtime_error("procedure failed");
}

TEST(Coro, NestedTasksReturnValuesInVirtualTime) {
    SimLoop loop(0);
    const auto frames = live_frames();
    int result = 0;
    Millis at = 0;
    spawn([](SimLoop& l, int& out, Millis& when) -> Task<void> {
        out = co_await twice(l, 21);
        when = l.now();
    }(loop, result, at));
    loop.run_until(10'000);
    EXPECT_EQ(result, 42);
    EXPECT_EQ(at, 100);
    EXPECT_EQ(live_frames(), frames);
}

TEST(Coro, AnExceptionReachesTheAwaiter) {
    SimLoop loop(0);
    std::string caught;
    spawn([](SimLoop& l, std::string& out) -> Task<void> {
        try {
            co_await fails(l);
        } catch (const std::runtime_error& e) {
            out = e.what();
        }
    }(loop, caught));
    loop.run_until(100);
    EXPECT_EQ(caught, "procedure failed");
}

TEST(Coro, CancelEndsASleepAtOnceAndStopsItsTimer) {
    SimLoop loop(0);
    CancelSource cancel;
    Wake wake = Wake::done;
    Millis at = -1;
    spawn([](SimLoop& l, CancelToken tok, Wake& w, Millis& when) -> Task<void> {
        w = co_await sleep_for(l, 60'000, tok);
        when = l.now();
    }(loop, cancel.token(), wake, at));
    loop.run_until(1000);
    EXPECT_EQ(loop.pending_timers(), 1u);
    cancel.cancel();
    EXPECT_EQ(wake, Wake::cancelled);
    EXPECT_EQ(at, 1000);
    EXPECT_EQ(loop.pending_timers(), 0u);
    // A wait on a cancelled token ends without suspending.
    Wake again = Wake::done;
    spawn([](SimLoop& l, CancelToken tok, Wake& w) -> Task<void> { w = co_await sleep_for(l, 5, tok); }(
        loop, cancel.token(), again));
    EXPECT_EQ(again, Wake::cancelled);
}

TEST(Coro, AMailboxDeliversQueuedAndLaterMessagesAndTimesOut) {
    SimLoop loop(0);
    Mailbox<std::string> mb(loop);
    std::vector<std::string> log;
    mb.push("early");
    spawn([](SimLoop& l, Mailbox<std::string>& m, std::vector<std::string>& out) -> Task<void> {
        auto a = co_await m.receive(1000);
        out.push_back(*a.value);                 // queued before the wait
        auto b = co_await m.receive(1000);
        out.push_back(*b.value + "@" + std::to_string(l.now()));
        auto c = co_await m.receive(300);
        out.push_back(c.wake == Wake::timeout && !c.value ? "timeout@" + std::to_string(l.now()) : "?");
    }(loop, mb, log));
    loop.run_until(200);
    EXPECT_TRUE(mb.waiting());
    mb.push("response");                         // resumes the waiter before push returns
    EXPECT_EQ(log.size(), 2u);
    loop.run_until(10'000);
    EXPECT_EQ(log, (std::vector<std::string>{"early", "response@200", "timeout@500"}));
    EXPECT_EQ(loop.pending_timers(), 0u);
}

TEST(Coro, AMailboxWaitEndsOnCancel) {
    SimLoop loop(0);
    Mailbox<int> mb(loop);
    CancelSource cancel;
    Wake wake = Wake::done;
    spawn([](Mailbox<int>& m, CancelToken tok, Wake& w) -> Task<void> {
        auto r = co_await m.receive(-1, tok);   // no time limit
        w = r.wake;
    }(mb, cancel.token(), wake));
    loop.run_until(100);
    EXPECT_TRUE(mb.waiting());
    cancel.cancel();
    EXPECT_EQ(wake, Wake::cancelled);
    EXPECT_FALSE(mb.waiting());
    mb.push(1);   // nobody waits now: it queues
    EXPECT_EQ(mb.queued(), 1u);
}

// Property: N procedures sleep random (even) durations and their source is
// cancelled at a random (odd) time. Each ends exactly once, done exactly when
// its sleep was shorter, cancelled otherwise; afterwards no timer is pending
// and no frame is alive.
TEST(Coro, ACancelAndAnExpiryNeverBothWin) {
    for (std::uint64_t seed = 1; seed <= 200; ++seed) {
        Rng rng(seed, {Rng::label("coro-cancel")});
        SimLoop loop(0);
        const auto frames = live_frames();
        CancelSource cancel;
        const int n = static_cast<int>(rng.uniform(1, 12));
        std::vector<int> ends(static_cast<std::size_t>(n), 0);
        std::vector<Wake> wakes(static_cast<std::size_t>(n), Wake::timeout);
        std::vector<Millis> sleeps;
        for (int i = 0; i < n; ++i) {
            sleeps.push_back(2 * rng.uniform(1, 500));
            spawn([](SimLoop& l, Millis d, CancelToken tok, int& end, Wake& w) -> Task<void> {
                w = co_await sleep_for(l, d, tok);
                ++end;
            }(loop, sleeps.back(), cancel.token(), ends[static_cast<std::size_t>(i)], wakes[static_cast<std::size_t>(i)]));
        }
        const Millis cancel_at = 2 * rng.uniform(0, 500) + 1;
        loop.start_timer(cancel_at, [&] { cancel.cancel(); });
        loop.run_until(10'000);
        for (int i = 0; i < n; ++i) {
            const auto k = static_cast<std::size_t>(i);
            ASSERT_EQ(ends[k], 1) << "seed " << seed;
            ASSERT_EQ(wakes[k], sleeps[k] < cancel_at ? Wake::done : Wake::cancelled) << "seed " << seed;
        }
        ASSERT_EQ(loop.pending_timers(), 0u) << "seed " << seed;
        ASSERT_EQ(live_frames(), frames) << "seed " << seed;
    }
}

} // namespace
} // namespace ksim::coro
