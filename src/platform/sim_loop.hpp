// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// A single-threaded discrete-event executor in virtual time (P1 N1, ADR 0009
// point 5). Posted tasks run in posting order at the current time. When none is
// left, the clock jumps to the timer wheel's next deadline and the timers due
// there fire, ordered by (deadline, scheduling order) as on a Shard. Hours of
// protocol timers therefore take milliseconds, and a run is a pure function of
// its inputs and seeds.

#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>

#include "platform/clock.hpp"
#include "platform/executor.hpp"
#include "platform/timer_wheel.hpp"

namespace ksim {

class SimLoop final : public Executor {
public:
    explicit SimLoop(Millis start = 0);

    bool post(Task t) override;
    TimerId start_timer(Millis delay, Callback cb) override;
    bool stop_timer(TimerId id) noexcept override { return wheel_.cancel(id); }
    Millis now() const noexcept override { return clock_.now_ms(); }

    /// The loop's clock, for components that take a Clock.
    const Clock& clock() const noexcept { return clock_; }

    /// Run every posted task and every timer due at the current time, without
    /// moving time. Returns the number of tasks and timers run.
    std::size_t run_ready();
    /// Run, jumping time from deadline to deadline, until nothing is left at
    /// or before `until`; time then stands at `until`. Returns the steps run.
    std::size_t run_until(Millis until);
    std::size_t run_for(Millis duration) { return run_until(now() + duration); }
    /// Run until `done()` holds (checked after each task and each timer tick)
    /// or time would pass `until`. True when `done()` held.
    bool run_until(const std::function<bool()>& done, Millis until);

    std::size_t pending_tasks() const noexcept { return ready_.size(); }
    std::size_t pending_timers() const noexcept { return wheel_.size(); }
    bool idle() const noexcept { return ready_.empty() && wheel_.size() == 0; }
    std::uint64_t steps() const noexcept { return steps_; }

private:
    /// One step at the current time: a posted task, else the timers due now.
    /// False when there is nothing to do at the current time.
    bool step();

    ManualClock clock_;
    TimerWheel wheel_;
    std::deque<Task> ready_;
    std::uint64_t steps_ = 0;
};

} // namespace ksim
