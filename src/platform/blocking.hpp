// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The blocking pool (P2 Q1; architecture.md §5): a few threads for the calls
// that block and have no non-blocking form, PC/SC first. An actor never waits
// on one: it hands the job over and gets the result back as a task posted to
// its own executor, so its single-threaded rule (R6) holds. Jobs run in the
// order given on whichever thread is free; a caller that needs order keeps one
// job in flight.

#pragma once

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>

namespace ksim {

class BlockingPool {
public:
    using Job = std::function<void()>;

    explicit BlockingPool(std::size_t threads = 2);
    /// Finishes the jobs already queued, then joins.
    ~BlockingPool();
    BlockingPool(const BlockingPool&) = delete;
    BlockingPool& operator=(const BlockingPool&) = delete;

    /// Any thread. False once the pool is stopping.
    bool run(Job job);
    std::size_t threads() const noexcept { return workers_.size(); }

private:
    void work();

    std::mutex mu_;
    std::condition_variable cv_;
    std::deque<Job> jobs_;
    bool stopping_ = false;
    std::vector<std::thread> workers_;
};

} // namespace ksim
