// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "platform/shard.hpp"

#include "platform/mutation.hpp"

#include <sys/epoll.h>

#include <algorithm>

namespace ksim {

namespace {
thread_local Shard* t_current = nullptr;
} // namespace

Shard::Shard(unsigned id, std::size_t inbox_capacity, const Clock& clock)
    : id_(id), clock_(clock), inbox_(inbox_capacity), wheel_(clock.now_ms()) {
    (void)reactor_.add(wake_.fd(), EPOLLIN, [this](std::uint32_t) {
        wake_.drain();
        run_inbox();
    });
    (void)reactor_.add(timer_.fd(), EPOLLIN, [this](std::uint32_t) {
        timer_.drain();
        run_timers();
    });
}

Shard::~Shard() {
    stop();
    join();
}

Shard* Shard::current() noexcept {
    return t_current;
}

void Shard::start() {
    thread_ = std::thread([this] { loop(); });
}

void Shard::stop() noexcept {
    stopping_.store(true, std::memory_order_seq_cst);
    wake_.notify();
}

void Shard::join() {
    if (thread_.joinable()) {
        thread_.join();
    }
}

bool Shard::post(Task t) {
    if (!inbox_.try_push(t)) {
        return false;
    }
    // Wake the loop once per batch: only the post that finds no wake pending
    // writes the eventfd. The loop clears the flag before it drains, so a post
    // racing the drain either is drained or wakes it again.
    if (!wake_pending_.exchange(true, std::memory_order_seq_cst)) {
        wake_.notify();
    }
    return true;
}

void Shard::run_inbox() {
    wake_pending_.store(false, std::memory_order_seq_cst);
    run_timers();   // the wheel catches up with the clock before any task runs
    // A bounded batch, so timers and descriptors are not starved by a flood;
    // what is left keeps the wake flag set and comes on the next turn.
    for (std::size_t n = 0; n < inbox_.capacity(); ++n) {
        auto t = inbox_.try_pop();
        if (!t) {
            return;
        }
        (*t)();
        tasks_run_.fetch_add(1, std::memory_order_relaxed);
    }
    wake_pending_.store(true, std::memory_order_seq_cst);
    wake_.notify();
}

void Shard::set_watchdog(Millis threshold, std::function<void(Millis)> on_lag) {
    watchdog_ms_ = threshold;
    on_lag_ = std::move(on_lag);
}

void Shard::run_timers() {
    const Millis now = clock_.now_ms();
    if (auto due = wheel_.next_deadline(); due && *due <= now) {
        const Millis lag = now - *due;
        if (lag > max_lag_.load(std::memory_order_relaxed)) {
            max_lag_.store(lag, std::memory_order_relaxed);
        }
        // P2 Q7: a timer this late means the loop was blocked; told once a second at most.
        if (watchdog_ms_ > 0 && lag > watchdog_ms_ && on_lag_ && !KSIM_MUTANT("watchdog_silent") &&
            (!lag_reported_ || now - last_lag_report_ >= 1'000)) {
            lag_reported_ = true;
            last_lag_report_ = now;
            on_lag_(lag);
        }
    }
    timers_fired_.fetch_add(wheel_.advance(now), std::memory_order_relaxed);
}

void Shard::rearm() {
    if (auto next = wheel_.next_deadline(); next) {
        (void)timer_.arm_at(std::max(*next, wheel_.now() + 1));
    } else {
        (void)timer_.disarm();
    }
}

void Shard::loop() {
    t_current = this;
    while (!stopping_.load(std::memory_order_seq_cst)) {
        run_timers();   // tasks may have scheduled timers that are already due
        rearm();
        (void)reactor_.run_once(-1);
    }
    run_inbox();   // what was posted before stop()
    t_current = nullptr;
}

} // namespace ksim
