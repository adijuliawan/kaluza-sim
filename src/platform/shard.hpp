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
#include "platform/mpsc.hpp"
#include "platform/reactor.hpp"
#include "platform/timer_wheel.hpp"

namespace ksim {

class Shard {
public:
    using Task = std::function<void()>;

    /// `clock` must outlive the shard (MonotonicClock in real time).
    Shard(unsigned id, std::size_t inbox_capacity, const Clock& clock);
    ~Shard();   // stops and joins

    Shard(const Shard&) = delete;
    Shard& operator=(const Shard&) = delete;

    unsigned id() const noexcept { return id_; }

    void start();
    /// Any thread: ask the loop to finish; tasks already posted still run.
    void stop() noexcept;
    void join();

    /// Any thread: queue a task for the shard's thread. False when the inbox is
    /// full; the task is then not queued (the caller holds the backpressure).
    bool post(Task t);

    // The shard's own thread only.
    /// A timer `delay` ms from now by the shard's clock (never early: the
    /// wheel's own time may trail the clock by the work done since it last
    /// advanced, so TimerWheel::schedule_in is not used for this).
    TimerId start_timer(Millis delay, TimerWheel::Callback cb) {
        return wheel_.schedule_at(clock_.now_ms() + (delay > 0 ? delay : 0), std::move(cb));
    }
    bool stop_timer(TimerId id) noexcept { return wheel_.cancel(id); }
    TimerWheel& timers() noexcept { return wheel_; }
    Reactor& reactor() noexcept { return reactor_; }
    Millis now() const noexcept { return clock_.now_ms(); }
    /// The shard running on the calling thread, or nullptr.
    static Shard* current() noexcept;

    // Counters, readable from any thread.
    std::uint64_t tasks_run() const noexcept { return tasks_run_.load(std::memory_order_relaxed); }
    std::uint64_t timers_fired() const noexcept { return timers_fired_.load(std::memory_order_relaxed); }
    /// The largest delay between a timer's deadline and its firing (loop lag), ms.
    Millis max_lag_ms() const noexcept { return max_lag_.load(std::memory_order_relaxed); }

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
    std::thread thread_;
};

} // namespace ksim
