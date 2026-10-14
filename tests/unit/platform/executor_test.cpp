// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The Executor contract (P1 N1, ADR 0009 point 5), run on both implementations:
// the real-time Shard and the virtual-time SimLoop. A procedure written against
// Executor must behave alike on both, so the same cases run on each.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <vector>

#include "platform/clock.hpp"
#include "platform/executor.hpp"
#include "platform/shard.hpp"
#include "platform/sim_loop.hpp"

namespace ksim {
namespace {

using Body = std::function<void(Executor& ex, const std::function<void()>& done)>;

struct SimHarness {
    SimLoop loop{1000};
    /// Runs `body` on the loop until it calls done() (virtual time, bounded).
    bool run(const Body& body) {
        bool finished = false;
        loop.post([&] { body(loop, [&] { finished = true; }); });
        return loop.run_until([&] { return finished; }, loop.now() + 60'000);
    }
};

struct ShardHarness {
    MonotonicClock clock;
    Shard shard{0, 1024, clock};
    ShardHarness() { shard.start(); }
    ~ShardHarness() {
        shard.stop();
        shard.join();
    }
    bool run(const Body& body) {
        auto p = std::make_shared<std::promise<void>>();
        auto f = p->get_future();
        const bool posted = shard.post([this, body, p] { body(shard, [p] { p->set_value(); }); });
        return posted && f.wait_for(std::chrono::seconds(10)) == std::future_status::ready;
    }
};

template <class H>
class ExecutorContract : public ::testing::Test {
protected:
    H h;
};

using Harnesses = ::testing::Types<SimHarness, ShardHarness>;
TYPED_TEST_SUITE(ExecutorContract, Harnesses);

TYPED_TEST(ExecutorContract, PostedTasksRunInPostingOrder) {
    std::vector<int> order;
    ASSERT_TRUE(this->h.run([&](Executor& ex, const std::function<void()>& done) {
        for (int i = 0; i < 5; ++i) {
            ex.post([&order, i] { order.push_back(i); });
        }
        ex.post(done);
    }));
    EXPECT_EQ(order, (std::vector<int>{0, 1, 2, 3, 4}));
}

TYPED_TEST(ExecutorContract, TimersFireInDeadlineOrderAndTiesInStartOrder) {
    std::vector<int> order;
    ASSERT_TRUE(this->h.run([&](Executor& ex, const std::function<void()>& done) {
        ex.start_timer(30, [&order] { order.push_back(3); });
        ex.start_timer(10, [&order] { order.push_back(1); });
        ex.start_timer(20, [&order] { order.push_back(2); });
        ex.start_timer(20, [&order] { order.push_back(22); });
        ex.start_timer(40, done);
    }));
    EXPECT_EQ(order, (std::vector<int>{1, 2, 22, 3}));
}

TYPED_TEST(ExecutorContract, ATimerNeverFiresEarly) {
    std::vector<Millis> early;
    ASSERT_TRUE(this->h.run([&](Executor& ex, const std::function<void()>& done) {
        for (Millis d : {1, 5, 17, 25}) {
            const Millis due = ex.now() + d;
            ex.start_timer(d, [&ex, &early, due] {
                if (ex.now() < due) {
                    early.push_back(due - ex.now());
                }
            });
        }
        ex.start_timer(30, done);
    }));
    EXPECT_TRUE(early.empty());
}

TYPED_TEST(ExecutorContract, AStoppedTimerDoesNotFireAndAStaleIdIsRefused) {
    bool fired = false;
    bool first_stop = false;
    bool second_stop = true;
    bool stop_after_fire = true;
    ASSERT_TRUE(this->h.run([&](Executor& ex, const std::function<void()>& done) {
        const TimerId t = ex.start_timer(10, [&fired] { fired = true; });
        first_stop = ex.stop_timer(t);
        second_stop = ex.stop_timer(t);
        const auto quick = std::make_shared<TimerId>();
        *quick = ex.start_timer(1, [] {});
        ex.start_timer(20, [&ex, &stop_after_fire, quick, done] {
            stop_after_fire = ex.stop_timer(*quick);
            done();
        });
    }));
    EXPECT_FALSE(fired);
    EXPECT_TRUE(first_stop);
    EXPECT_FALSE(second_stop);
    EXPECT_FALSE(stop_after_fire);
}

TYPED_TEST(ExecutorContract, WorkStartedFromCallbacksRuns) {
    std::vector<int> order;
    ASSERT_TRUE(this->h.run([&](Executor& ex, const std::function<void()>& done) {
        ex.start_timer(5, [&ex, &order, done] {
            order.push_back(1);
            ex.post([&ex, &order, done] {
                order.push_back(2);
                ex.start_timer(5, [&order, done] {
                    order.push_back(3);
                    done();
                });
            });
        });
    }));
    EXPECT_EQ(order, (std::vector<int>{1, 2, 3}));
}

TYPED_TEST(ExecutorContract, AZeroOrNegativeDelayFiresAfterTheCurrentTask) {
    std::vector<int> order;
    ASSERT_TRUE(this->h.run([&](Executor& ex, const std::function<void()>& done) {
        ex.start_timer(0, [&order] { order.push_back(2); });
        ex.start_timer(-5, [&order] { order.push_back(3); });
        order.push_back(1);
        ex.start_timer(2, done);
    }));
    EXPECT_EQ(order, (std::vector<int>{1, 2, 3}));
}

} // namespace
} // namespace ksim
