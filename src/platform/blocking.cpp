// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "platform/blocking.hpp"

#include <utility>

namespace ksim {

BlockingPool::BlockingPool(std::size_t threads) {
    workers_.reserve(threads == 0 ? 1 : threads);
    for (std::size_t i = 0; i < (threads == 0 ? 1 : threads); ++i) {
        workers_.emplace_back([this] { work(); });
    }
}

BlockingPool::~BlockingPool() {
    {
        const std::lock_guard<std::mutex> lock(mu_);
        stopping_ = true;
    }
    cv_.notify_all();
    for (auto& t : workers_) {
        t.join();
    }
}

bool BlockingPool::run(Job job) {
    {
        const std::lock_guard<std::mutex> lock(mu_);
        if (stopping_) {
            return false;
        }
        jobs_.push_back(std::move(job));
    }
    cv_.notify_one();
    return true;
}

void BlockingPool::work() {
    for (;;) {
        Job job;
        {
            std::unique_lock<std::mutex> lock(mu_);
            cv_.wait(lock, [this] { return stopping_ || !jobs_.empty(); });
            if (jobs_.empty()) {
                return;   // stopping, and nothing is left
            }
            job = std::move(jobs_.front());
            jobs_.pop_front();
        }
        job();
    }
}

} // namespace ksim
