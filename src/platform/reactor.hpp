// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The event loop of a shard (plan M13, architecture §5): epoll, an eventfd to
// wake it, and a timerfd armed at an absolute CLOCK_MONOTONIC time, so the
// timer wheel sleeps until its next deadline instead of ticking. Rule R7: the
// epoll calls of the whole tree live here.

#pragma once

#include <cstdint>
#include <functional>
#include <unordered_map>

#include "platform/clock.hpp"
#include "platform/result.hpp"

namespace ksim {

/// An owned file descriptor.
class Fd {
public:
    Fd() noexcept = default;
    explicit Fd(int fd) noexcept : fd_(fd) {}
    Fd(Fd&& o) noexcept : fd_(o.release()) {}
    Fd& operator=(Fd&& o) noexcept;
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    ~Fd();

    int get() const noexcept { return fd_; }
    int release() noexcept {
        const int f = fd_;
        fd_ = -1;
        return f;
    }
    explicit operator bool() const noexcept { return fd_ >= 0; }

private:
    int fd_ = -1;
};

class Reactor {
public:
    using Handler = std::function<void(std::uint32_t events)>;

    Reactor();   // epoll_create1(EPOLL_CLOEXEC); throws std::system_error on failure

    /// events: EPOLLIN, EPOLLOUT, ... (level-triggered unless EPOLLET is given).
    Result<void> add(int fd, std::uint32_t events, Handler h);
    Result<void> modify(int fd, std::uint32_t events);
    Result<void> remove(int fd);

    /// Wait up to timeout_ms (-1: until an event) and run the handlers of the
    /// ready descriptors. A handler may add or remove descriptors, itself too.
    Result<int> run_once(int timeout_ms);

    std::size_t size() const noexcept { return handlers_.size(); }

private:
    Fd ep_;
    std::unordered_map<int, Handler> handlers_;
};

/// eventfd(EFD_NONBLOCK | EFD_CLOEXEC): any thread may notify.
class EventFd {
public:
    EventFd();
    int fd() const noexcept { return fd_.get(); }
    void notify() noexcept;
    std::uint64_t drain() noexcept;

private:
    Fd fd_;
};

/// timerfd on CLOCK_MONOTONIC, armed at an absolute time.
class TimerFd {
public:
    TimerFd();
    int fd() const noexcept { return fd_.get(); }
    Result<void> arm_at(Millis monotonic_ms);
    Result<void> disarm();
    std::uint64_t drain() noexcept;

private:
    Fd fd_;
};

} // namespace ksim
