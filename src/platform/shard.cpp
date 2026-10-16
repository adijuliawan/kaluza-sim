// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "platform/shard.hpp"

#include "platform/mutation.hpp"

#include <execinfo.h>
#include <pthread.h>
#include <signal.h>
#include <sys/epoll.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>

namespace ksim {

namespace {
thread_local Shard* t_current = nullptr;

// The stuck loop's backtrace: the monitor signals the loop's thread, which writes its
// own stack to stderr. backtrace() is called once before, so the handler loads nothing.
const int kStackSignal = SIGRTMIN + 3;
void stack_handler(int /*sig*/) {
    void* frames[64];
    const int n = ::backtrace(frames, 64);
    ::backtrace_symbols_fd(frames, n, STDERR_FILENO);
}
void install_stack_handler() {
    static std::once_flag once;
    std::call_once(once, [] {
        void* warm[1];
        (void)::backtrace(warm, 1);
        struct sigaction sa{};
        sa.sa_handler = stack_handler;
        sa.sa_flags = SA_RESTART;
        ::sigemptyset(&sa.sa_mask);
        (void)::sigaction(kStackSignal, &sa, nullptr);
    });
}
std::string slurp(const std::string& path) {
    std::ifstream in(path);
    std::stringstream s;
    s << in.rdbuf();
    std::string v = s.str();
    while (!v.empty() && (v.back() == '\n' || v.back() == ' ')) {
        v.pop_back();
    }
    return v;
}
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
    if (watchdog_ms_ > 0) {
        install_stack_handler();
        monitor_ = std::thread([this] { monitor(); });
    }
}

void Shard::stop() noexcept {
    stopping_.store(true, std::memory_order_seq_cst);
    monitor_stop_.store(true, std::memory_order_seq_cst);
    wake_.notify();
}

void Shard::join() {
    if (thread_.joinable()) {
        thread_.join();
    }
    if (monitor_.joinable()) {
        monitor_.join();
    }
}

void Shard::heartbeat() {
    beat_.store(clock_.now_ms(), std::memory_order_relaxed);
    (void)start_timer(1'000, heartbeat_);
}

void Shard::monitor() {
    bool reported = false;
    while (!monitor_stop_.load(std::memory_order_seq_cst)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        const Millis beat = beat_.load(std::memory_order_relaxed);
        const Millis late = clock_.now_ms() - beat;
        if (beat > 0 && late > stuck_after_ && !stopping_.load(std::memory_order_seq_cst)) {
            if (!reported) {
                report_stuck(late);
                reported = true;
            }
        } else {
            reported = false;
        }
    }
}

void Shard::report_stuck(Millis for_ms) const {
    const int tid = tid_.load(std::memory_order_relaxed);
    const std::string task = "/proc/self/task/" + std::to_string(tid);
    const std::string sc = slurp(task + "/syscall");   // "<nr> <arg1> …", or "running"
    std::string fd_is;
    unsigned long nr = 0;
    unsigned long arg1 = 0;
    if (std::sscanf(sc.c_str(), "%lu 0x%lx", &nr, &arg1) == 2 && arg1 < 65'536) {
        char buf[256] = {};
        const std::string link = "/proc/self/fd/" + std::to_string(arg1);
        if (const ssize_t k = ::readlink(link.c_str(), buf, sizeof(buf) - 1); k > 0) {
            fd_is = std::string(buf, static_cast<std::size_t>(k));
        }
    }
    std::fprintf(stderr, "KSIM_LOOP_STUCK shard=%u for_ms=%lld tid=%d syscall=\"%s\" wchan=%s fd1=%s\n", id_,
                 static_cast<long long>(for_ms), tid, sc.c_str(), slurp(task + "/wchan").c_str(),
                 fd_is.empty() ? "-" : fd_is.c_str());
    std::fflush(stderr);
#if defined(__SANITIZE_THREAD__)
    const bool stack = false;   // TSan holds the handler's unwinding signal-unsafe
#elif defined(__has_feature)
#if __has_feature(thread_sanitizer)
    const bool stack = false;
#else
    const bool stack = true;
#endif
#else
    const bool stack = true;
#endif
    if (stack && thread_.joinable()) {
        (void)::pthread_kill(const_cast<std::thread&>(thread_).native_handle(), kStackSignal);   // NOLINT(cppcoreguidelines-pro-type-const-cast): native_handle is not const
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

void Shard::set_watchdog(Millis threshold, std::function<void(Millis)> on_lag, Millis stuck_after) {
    watchdog_ms_ = threshold;
    on_lag_ = std::move(on_lag);
    stuck_after_ = stuck_after;
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
    tid_.store(static_cast<int>(::gettid()), std::memory_order_relaxed);
    if (watchdog_ms_ > 0) {
        heartbeat_ = [this] { heartbeat(); };
        heartbeat();
    }
    while (!stopping_.load(std::memory_order_seq_cst)) {
        run_timers();   // tasks may have scheduled timers that are already due
        rearm();
        (void)reactor_.run_once(-1);
    }
    run_inbox();   // what was posted before stop()
    t_current = nullptr;
}

} // namespace ksim
