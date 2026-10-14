// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "platform/sim_loop.hpp"

#include <utility>

namespace ksim {

SimLoop::SimLoop(Millis start) : clock_(start), wheel_(start) {}

bool SimLoop::post(Task t) {
    ready_.push_back(std::move(t));
    return true;
}

TimerId SimLoop::start_timer(Millis delay, Callback cb) {
    return wheel_.schedule_at(clock_.now_ms() + (delay > 0 ? delay : 0), std::move(cb));
}

bool SimLoop::step() {
    if (!ready_.empty()) {
        Task t = std::move(ready_.front());
        ready_.pop_front();
        ++steps_;
        t();
        return true;
    }
    const std::size_t fired = wheel_.advance(clock_.now_ms());
    steps_ += fired;
    return fired > 0;
}

std::size_t SimLoop::run_ready() {
    const std::uint64_t before = steps_;
    while (step()) {
    }
    return static_cast<std::size_t>(steps_ - before);
}

std::size_t SimLoop::run_until(Millis until) {
    const std::uint64_t before = steps_;
    for (;;) {
        run_ready();
        const auto next = wheel_.next_deadline();
        if (!next || *next > until) {
            break;
        }
        clock_.set(*next > clock_.now_ms() ? *next : clock_.now_ms());
    }
    if (until > clock_.now_ms()) {
        clock_.set(until);
        wheel_.advance(until);   // nothing is due before `until`: only moves the wheel's time
    }
    return static_cast<std::size_t>(steps_ - before);
}

bool SimLoop::run_until(const std::function<bool()>& done, Millis until) {
    for (;;) {
        if (done()) {
            return true;
        }
        if (step()) {
            continue;
        }
        const auto next = wheel_.next_deadline();
        if (!next || *next > until) {
            return done();
        }
        clock_.set(*next > clock_.now_ms() ? *next : clock_.now_ms());
    }
}

} // namespace ksim
