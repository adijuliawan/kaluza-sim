// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// What an actor runs on (P1 N1, ADR 0009 point 5): post work, start and stop
// timers, read the time. The real-time Shard implements it, and SimLoop is its
// single-threaded virtual-time twin for procedure tests, so a procedure runs
// unchanged under both. Entities see only the TimerService half (rule R4).

#pragma once

#include <functional>

#include "platform/clock.hpp"
#include "platform/timer_wheel.hpp"

namespace ksim {

class TimerService {
public:
    using Callback = TimerWheel::Callback;

    virtual ~TimerService() = default;

    /// A timer `delay` ms from now (a negative delay counts as 0). It never
    /// fires early, and its callback runs on the executor's thread.
    virtual TimerId start_timer(Millis delay, Callback cb) = 0;
    /// A timer at `deadline` on the executor's clock (a past one fires at
    /// once). Timers with the same deadline fire in the order they were
    /// started, so a sequence of non-decreasing deadlines keeps its order.
    virtual TimerId start_timer_at(Millis deadline, Callback cb) = 0;
    /// False when the timer has fired or was stopped already (a stale id).
    virtual bool stop_timer(TimerId id) noexcept = 0;
    virtual Millis now() const noexcept = 0;
};

class Executor : public TimerService {
public:
    using Task = std::function<void()>;

    /// Queue a task to run after the current one, in posting order. A Shard
    /// takes posts from any thread and returns false when its inbox is full;
    /// a SimLoop is single-threaded and never refuses.
    virtual bool post(Task t) = 0;
};

} // namespace ksim
