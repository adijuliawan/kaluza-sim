// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// A shard (plan M13, architecture §5): one thread with an epoll reactor, an
// eventfd-woken bounded MPSC inbox and a timer wheel driven by a timerfd that
// is armed only for the wheel's next deadline (no tick). Actors live on one
// shard for life; other threads reach a shard only by post().

#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <thread>

#include "platform/clock.hpp"
#include "platform/executor.hpp"
#include "platform/mpsc.hpp"
#include "platform/reactor.hpp"
#include "platform/timer_wheel.hpp"

namespace ksim {

class Shard final : public Executor {
public:

    /// `clock` must outlive the shard (MonotonicClock in real time).
    Shard(unsigned id, std::size_t inbox_capacity, const Clock& clock);
    ~Shard() override;   // stops and joins

    Shard(const Shard&) = delete;
    Shard& operator=(const Shard&) = delete;

    unsigned id() const noexcept { return id_; }

    void start();
    /// Any thread: ask the loop to finish; tasks already posted still run.
    void stop() noexcept;
    void join();

    /// Any thread: queue a task for the shard's thread. False when the inbox is
    /// full; the task is then not queued (the caller holds the backpressure).
    bool post(Task t) override;

    // The shard's own thread only.
    /// A timer `delay` ms from now by the shard's clock (never early: the
    /// wheel's own time may trail the clock by the work done since it last
    /// advanced, so TimerWheel::schedule_in is not used for this).
    TimerId start_timer(Millis delay, TimerWheel::Callback cb) override {
        return wheel_.schedule_at(clock_.now_ms() + (delay > 0 ? delay : 0), std::move(cb));
    }
    TimerId start_timer_at(Millis deadline, TimerWheel::Callback cb) override {
        return wheel_.schedule_at(deadline, std::move(cb));
    }
    bool stop_timer(TimerId id) noexcept override { return wheel_.cancel(id); }
    TimerWheel& timers() noexcept { return wheel_; }
    Reactor& reactor() noexcept { return reactor_; }
    Millis now() const noexcept override { return clock_.now_ms(); }
    /// The shard running on the calling thread, or nullptr.
    static Shard* current() noexcept;

    // Counters, readable from any thread.
    std::uint64_t tasks_run() const noexcept { return tasks_run_.load(std::memory_order_relaxed); }
    std::uint64_t timers_fired() const noexcept { return timers_fired_.load(std::memory_order_relaxed); }
    /// The largest delay between a timer's deadline and its firing (loop lag), ms.
    Millis max_lag_ms() const noexcept { return max_lag_.load(std::memory_order_relaxed); }
    /// P2 Q7, the watchdog: `on_lag(lag_ms)` runs on the shard when a timer fires more
    /// than `threshold` ms late, at most once a second. Set before the shard runs work.
    /// With it the shard also beats once a second, and a monitor thread reports a loop
    /// that missed its beat for kStuckMs (a blocked loop fires no late timer to tell):
    /// one KSIM_LOOP_STUCK line on stderr with the thread's syscall, kernel wait and,
    /// for a descriptor, what it is, then the thread's backtrace (LW1a, 2026-10-16).
    static constexpr Millis kStuckMs = 8'000;
    void set_watchdog(Millis threshold, std::function<void(Millis)> on_lag, Millis stuck_after = kStuckMs);

private:
    void loop();
    void run_inbox();
    void run_timers();
    void rearm();

    unsigned id_;
    const Clock& clock_;
    Reactor reactor_;
    EventFd wake_;
    TimerFd timer_;
    MpscQueue<Task> inbox_;
    TimerWheel wheel_;
    std::atomic<bool> wake_pending_{false};
    std::atomic<bool> stopping_{false};
    std::atomic<std::uint64_t> tasks_run_{0};
    std::atomic<std::uint64_t> timers_fired_{0};
    std::atomic<Millis> max_lag_{0};
    Millis watchdog_ms_ = 0;                 // 0: off
    std::function<void(Millis)> on_lag_;
    Millis last_lag_report_ = 0;
    bool lag_reported_ = false;
    Millis stuck_after_ = kStuckMs;
    std::atomic<Millis> beat_{0};            // the heartbeat's last run, by the clock
    std::atomic<int> tid_{0};                // the loop thread's kernel id, for /proc
    std::atomic<bool> monitor_stop_{false};
    std::function<void()> heartbeat_;
    void heartbeat();
    void monitor();
    void report_stuck(Millis for_ms) const;
    std::thread thread_;
    std::thread monitor_;
};

} // namespace ksim
