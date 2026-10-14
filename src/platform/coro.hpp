// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Coroutines for procedures (P1 N1, architecture §5: RAN orchestration as C++20
// coroutines owned by the UE context). A procedure is a Task that awaits
// timers and messages on its actor's TimerService:
//
//     Task<void> setup(…) {
//         send_request();
//         auto r = co_await mailbox.receive(timeouts.ue_ctx_setup, cancel.token());
//         if (r.wake != Wake::done) co_return;   // timed out or cancelled
//         …
//     }
//     spawn(setup(…));
//
// Everything is single-threaded and resumes inline on the actor's thread. A
// timer's expiry resumes its waiter from the executor's loop. Mailbox::push and
// CancelSource::cancel resume a waiter before they return. So an actor that
// owns a CancelSource and cancels it in its destructor ends its procedures
// before its state goes: a waiter woken with Wake::cancelled must co_return
// without touching that state.

#pragma once

#include <atomic>
#include <coroutine>
#include <cstdint>
#include <deque>
#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include "platform/executor.hpp"

namespace ksim::coro {

enum class Wake : std::uint8_t { done, timeout, cancelled };

namespace detail {

inline std::atomic<std::int64_t>& frame_count() noexcept {
    static std::atomic<std::int64_t> n{0};
    return n;
}

struct FrameCount {
    FrameCount() noexcept { frame_count().fetch_add(1, std::memory_order_relaxed); }
    ~FrameCount() { frame_count().fetch_sub(1, std::memory_order_relaxed); }
    FrameCount(const FrameCount&) = delete;
    FrameCount& operator=(const FrameCount&) = delete;
};

struct CancelState {
    bool cancelled = false;
    std::uint64_t next_id = 1;
    std::vector<std::pair<std::uint64_t, std::function<void()>>> callbacks;
};

} // namespace detail

/// Coroutine frames alive in the process (a leak check for tests).
inline std::int64_t live_frames() noexcept { return detail::frame_count().load(std::memory_order_relaxed); }

class CancelToken {
public:
    CancelToken() = default;   // never cancelled

    bool cancelled() const noexcept { return s_ && s_->cancelled; }
    bool can_cancel() const noexcept { return s_ != nullptr; }
    /// Calls `cb` when the source is cancelled. Returns 0, registering nothing,
    /// when there is no source or it is cancelled already (check that first).
    std::uint64_t on_cancel(std::function<void()> cb) const {
        if (!s_ || s_->cancelled) {
            return 0;
        }
        const std::uint64_t id = s_->next_id++;
        s_->callbacks.emplace_back(id, std::move(cb));
        return id;
    }
    void forget(std::uint64_t id) const noexcept {
        if (!s_ || id == 0) {
            return;
        }
        auto& v = s_->callbacks;
        for (auto it = v.begin(); it != v.end(); ++it) {
            if (it->first == id) {
                v.erase(it);
                return;
            }
        }
    }

private:
    friend class CancelSource;
    explicit CancelToken(std::shared_ptr<detail::CancelState> s) : s_(std::move(s)) {}
    std::shared_ptr<detail::CancelState> s_;
};

class CancelSource {
public:
    CancelSource() : s_(std::make_shared<detail::CancelState>()) {}

    CancelToken token() const { return CancelToken(s_); }
    bool cancelled() const noexcept { return s_->cancelled; }
    /// Every waiter registered on a token of this source resumes now, on this
    /// thread, with Wake::cancelled. Later waits on its tokens end at once.
    void cancel() {
        if (s_->cancelled) {
            return;
        }
        s_->cancelled = true;
        auto callbacks = std::move(s_->callbacks);
        s_->callbacks.clear();
        for (auto& entry : callbacks) {
            entry.second();
        }
    }

private:
    std::shared_ptr<detail::CancelState> s_;
};

template <class T = void>
class Task;

namespace detail {

struct PromiseBase {
    std::coroutine_handle<> continuation;
    std::exception_ptr error;
    FrameCount count;

    std::suspend_always initial_suspend() const noexcept { return {}; }
    struct Final {
        bool await_ready() const noexcept { return false; }
        template <class P>
        std::coroutine_handle<> await_suspend(std::coroutine_handle<P> h) const noexcept {
            const auto c = h.promise().continuation;
            return c ? c : std::noop_coroutine();
        }
        void await_resume() const noexcept {}
    };
    Final final_suspend() const noexcept { return {}; }
    void unhandled_exception() noexcept { error = std::current_exception(); }
};

} // namespace detail

/// A lazily started coroutine: it runs when awaited (or spawned) and resumes
/// its awaiter when it ends. An exception it throws is rethrown at the await.
template <class T>
class [[nodiscard]] Task {
public:
    struct promise_type : detail::PromiseBase {
        std::optional<T> value;
        Task get_return_object() noexcept { return Task(std::coroutine_handle<promise_type>::from_promise(*this)); }
        template <class U>
        void return_value(U&& v) {
            value.emplace(std::forward<U>(v));
        }
    };

    Task(Task&& o) noexcept : h_(std::exchange(o.h_, {})) {}
    Task& operator=(Task&& o) noexcept {
        if (this != &o) {
            if (h_) {
                h_.destroy();
            }
            h_ = std::exchange(o.h_, {});
        }
        return *this;
    }
    Task(const Task&) = delete;
    Task& operator=(const Task&) = delete;
    ~Task() {
        if (h_) {
            h_.destroy();
        }
    }

    bool await_ready() const noexcept { return false; }
    std::coroutine_handle<> await_suspend(std::coroutine_handle<> awaiting) noexcept {
        h_.promise().continuation = awaiting;
        return h_;
    }
    T await_resume() {
        auto& p = h_.promise();
        if (p.error) {
            std::rethrow_exception(p.error);
        }
        if (!p.value.has_value()) {
            std::terminate();   // a Task<T> that ended without co_return
        }
        return std::move(p.value).value();
    }

private:
    explicit Task(std::coroutine_handle<promise_type> h) noexcept : h_(h) {}
    std::coroutine_handle<promise_type> h_;
};

template <>
class [[nodiscard]] Task<void> {
public:
    struct promise_type : detail::PromiseBase {
        Task get_return_object() noexcept { return Task(std::coroutine_handle<promise_type>::from_promise(*this)); }
        void return_void() const noexcept {}
    };

    Task(Task&& o) noexcept : h_(std::exchange(o.h_, {})) {}
    Task& operator=(Task&& o) noexcept {
        if (this != &o) {
            if (h_) {
                h_.destroy();
            }
            h_ = std::exchange(o.h_, {});
        }
        return *this;
    }
    Task(const Task&) = delete;
    Task& operator=(const Task&) = delete;
    ~Task() {
        if (h_) {
            h_.destroy();
        }
    }

    bool await_ready() const noexcept { return false; }
    std::coroutine_handle<> await_suspend(std::coroutine_handle<> awaiting) noexcept {
        h_.promise().continuation = awaiting;
        return h_;
    }
    void await_resume() {
        if (h_.promise().error) {
            std::rethrow_exception(h_.promise().error);
        }
    }

private:
    explicit Task(std::coroutine_handle<promise_type> h) noexcept : h_(h) {}
    std::coroutine_handle<promise_type> h_;
};

namespace detail {

struct Detached {
    struct promise_type {
        FrameCount count;
        Detached get_return_object() const noexcept { return {}; }
        std::suspend_never initial_suspend() const noexcept { return {}; }
        std::suspend_never final_suspend() const noexcept { return {}; }
        void return_void() const noexcept {}
        [[noreturn]] void unhandled_exception() const noexcept { std::terminate(); }
    };
};

inline Detached run_detached(Task<void> t) {
    co_await std::move(t);
}

} // namespace detail

/// Starts `t` now: it runs to its first suspension, then on its own, and frees
/// its frame when it ends. An exception escaping it ends the process.
inline void spawn(Task<void> t) {
    detail::run_detached(std::move(t));
}

/// `co_await sleep_for(timers, ms, token)`: Wake::done after `ms`, or
/// Wake::cancelled as soon as the token's source is cancelled.
class [[nodiscard]] Sleep {
public:
    Sleep(TimerService& timers, Millis delay, CancelToken token)
        : timers_(timers), delay_(delay), token_(std::move(token)) {}

    bool await_ready() noexcept {
        if (token_.cancelled()) {
            wake_ = Wake::cancelled;
            return true;
        }
        return false;
    }
    void await_suspend(std::coroutine_handle<> h) {
        h_ = h;
        timer_ = timers_.start_timer(delay_, [this] {
            token_.forget(reg_);
            wake_ = Wake::done;
            h_.resume();
        });
        reg_ = token_.on_cancel([this] {
            timers_.stop_timer(timer_);
            wake_ = Wake::cancelled;
            h_.resume();
        });
    }
    Wake await_resume() const noexcept { return wake_; }

private:
    TimerService& timers_;
    Millis delay_;
    CancelToken token_;
    TimerId timer_{};
    std::uint64_t reg_ = 0;
    Wake wake_ = Wake::done;
    std::coroutine_handle<> h_;
};

inline Sleep sleep_for(TimerService& timers, Millis delay, CancelToken token = {}) {
    return Sleep(timers, delay, std::move(token));
}

/// Messages for one waiting coroutine at a time: what a procedure awaits (the
/// response to its request) while its actor's handlers push what arrives.
template <class T>
class Mailbox {
public:
    struct Received {
        Wake wake = Wake::done;
        std::optional<T> value;
    };

    explicit Mailbox(TimerService& timers) : timers_(timers) {}
    Mailbox(const Mailbox&) = delete;
    Mailbox& operator=(const Mailbox&) = delete;
    /// Its waiter, if any, must have been cancelled before (see the file note).
    ~Mailbox() = default;

    /// Delivers `v`: a waiting receiver resumes now, before push returns; with
    /// none waiting, `v` is queued for the next receive.
    void push(T v) {
        if (waiter_ != nullptr) {
            Awaiter* w = std::exchange(waiter_, nullptr);
            w->deliver(std::move(v));
            return;
        }
        queue_.push_back(std::move(v));
    }
    std::size_t queued() const noexcept { return queue_.size(); }
    bool waiting() const noexcept { return waiter_ != nullptr; }

    class [[nodiscard]] Awaiter {
    public:
        Awaiter(Mailbox& mb, Millis timeout, CancelToken token)
            : mb_(mb), timeout_(timeout), token_(std::move(token)) {}

        bool await_ready() {
            if (token_.cancelled()) {
                out_.wake = Wake::cancelled;
                return true;
            }
            if (!mb_.queue_.empty()) {
                out_.value.emplace(std::move(mb_.queue_.front()));
                mb_.queue_.pop_front();
                return true;
            }
            return false;
        }
        void await_suspend(std::coroutine_handle<> h) {
            if (mb_.waiter_ != nullptr) {
                std::terminate();   // one receiver at a time
            }
            h_ = h;
            mb_.waiter_ = this;
            if (timeout_ >= 0) {
                timer_ = mb_.timers_.start_timer(timeout_, [this] {
                    mb_.waiter_ = nullptr;
                    token_.forget(reg_);
                    out_.wake = Wake::timeout;
                    h_.resume();
                });
            }
            reg_ = token_.on_cancel([this] {
                mb_.waiter_ = nullptr;
                if (timer_.valid()) {
                    mb_.timers_.stop_timer(timer_);
                }
                out_.wake = Wake::cancelled;
                h_.resume();
            });
        }
        Received await_resume() { return std::move(out_); }

    private:
        friend class Mailbox;
        void deliver(T v) {
            if (timer_.valid()) {
                mb_.timers_.stop_timer(timer_);
            }
            token_.forget(reg_);
            out_.value.emplace(std::move(v));
            out_.wake = Wake::done;
            h_.resume();
        }

        Mailbox& mb_;
        Millis timeout_;
        CancelToken token_;
        TimerId timer_{};
        std::uint64_t reg_ = 0;
        Received out_;
        std::coroutine_handle<> h_;
    };

    /// `co_await mb.receive(ms, token)`: the next message (Wake::done), or
    /// Wake::timeout after `ms` (a negative `ms` waits without limit), or
    /// Wake::cancelled.
    Awaiter receive(Millis timeout, CancelToken token = {}) { return Awaiter(*this, timeout, std::move(token)); }

private:
    TimerService& timers_;
    std::deque<T> queue_;
    Awaiter* waiter_ = nullptr;
};

} // namespace ksim::coro
