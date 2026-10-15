// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The blocking pool (P2 Q1): jobs run off the caller's thread, one thread keeps
// their order, and the destructor finishes what was queued before it joins.

#include <gtest/gtest.h>

#include <atomic>
#include <mutex>
#include <thread>
#include <vector>

#include "platform/blocking.hpp"

namespace ksim {
namespace {

TEST(BlockingPool, JobsRunOffTheCallersThread) {
    std::atomic<int> ran{0};
    std::atomic<bool> other{true};
    const auto me = std::this_thread::get_id();
    {
        BlockingPool pool(2);
        EXPECT_EQ(pool.threads(), 2u);
        for (int i = 0; i < 100; ++i) {
            ASSERT_TRUE(pool.run([&] {
                if (std::this_thread::get_id() == me) {
                    other = false;
                }
                ++ran;
            }));
        }
    }   // the destructor drains the queue
    EXPECT_EQ(ran.load(), 100);
    EXPECT_TRUE(other.load());
}

TEST(BlockingPool, OneThreadKeepsTheOrder) {
    std::vector<int> seen;
    std::mutex mu;
    {
        BlockingPool pool(1);
        for (int i = 0; i < 50; ++i) {
            pool.run([&, i] {
                const std::lock_guard<std::mutex> lock(mu);
                seen.push_back(i);
            });
        }
    }
    ASSERT_EQ(seen.size(), 50u);
    for (int i = 0; i < 50; ++i) {
        EXPECT_EQ(seen[static_cast<std::size_t>(i)], i);
    }
}

TEST(BlockingPool, ZeroThreadsMeansOne) {
    BlockingPool pool(0);
    EXPECT_EQ(pool.threads(), 1u);
}

} // namespace
} // namespace ksim
