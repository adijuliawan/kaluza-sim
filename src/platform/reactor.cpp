// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "platform/reactor.hpp"

#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <system_error>

namespace ksim {

namespace {
Error os_error(const char* what) {
    return make_error(Errc::internal, static_cast<std::uint32_t>(errno), what);
}
} // namespace

Fd& Fd::operator=(Fd&& o) noexcept {
    if (this != &o) {
        if (fd_ >= 0) {
            ::close(fd_);
        }
        fd_ = o.release();
    }
    return *this;
}

Fd::~Fd() {
    if (fd_ >= 0) {
        ::close(fd_);
    }
}

Reactor::Reactor() : ep_(::epoll_create1(EPOLL_CLOEXEC)) {
    if (!ep_) {
        throw std::system_error(errno, std::generic_category(), "epoll_create1");
    }
}

Result<void> Reactor::add(int fd, std::uint32_t events, Handler h) {
    epoll_event ev{};
    ev.events = events;
    ev.data.fd = fd;
    if (::epoll_ctl(ep_.get(), EPOLL_CTL_ADD, fd, &ev) != 0) {
        return os_error("epoll_ctl ADD (offset: errno)");
    }
    handlers_[fd] = std::move(h);
    return {};
}

Result<void> Reactor::modify(int fd, std::uint32_t events) {
    epoll_event ev{};
    ev.events = events;
    ev.data.fd = fd;
    if (::epoll_ctl(ep_.get(), EPOLL_CTL_MOD, fd, &ev) != 0) {
        return os_error("epoll_ctl MOD (offset: errno)");
    }
    return {};
}

Result<void> Reactor::remove(int fd) {
    if (::epoll_ctl(ep_.get(), EPOLL_CTL_DEL, fd, nullptr) != 0) {
        return os_error("epoll_ctl DEL (offset: errno)");
    }
    handlers_.erase(fd);
    return {};
}

Result<int> Reactor::run_once(int timeout_ms) {
    std::array<epoll_event, 64> evs{};
    const int n = ::epoll_wait(ep_.get(), evs.data(), static_cast<int>(evs.size()), timeout_ms);
    if (n < 0) {
        if (errno == EINTR) {
            return 0;
        }
        return os_error("epoll_wait (offset: errno)");
    }
    for (int k = 0; k < n; ++k) {
        const auto ev = evs[static_cast<std::size_t>(k)];
        const auto it = handlers_.find(ev.data.fd);
        if (it == handlers_.end()) {
            continue;   // removed by an earlier handler in this batch
        }
        Handler h = it->second;   // a copy: the handler may remove itself
        h(ev.events);
    }
    return n;
}

EventFd::EventFd() : fd_(::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC)) {
    if (!fd_) {
        throw std::system_error(errno, std::generic_category(), "eventfd");
    }
}

void EventFd::notify() noexcept {
    const std::uint64_t one = 1;
    // A full counter (2^64-2 pending) cannot happen at our rates; EAGAIN is ignored.
    [[maybe_unused]] const auto r = ::write(fd_.get(), &one, sizeof one);
}

std::uint64_t EventFd::drain() noexcept {
    std::uint64_t v = 0;
    if (::read(fd_.get(), &v, sizeof v) != static_cast<ssize_t>(sizeof v)) {
        return 0;
    }
    return v;
}

TimerFd::TimerFd() : fd_(::timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC)) {
    if (!fd_) {
        throw std::system_error(errno, std::generic_category(), "timerfd_create");
    }
}

Result<void> TimerFd::arm_at(Millis ms) {
    itimerspec its{};
    // a zero it_value disarms, so an expiry at or before the epoch is moved to 1 ns
    its.it_value.tv_sec = ms > 0 ? ms / 1000 : 0;
    its.it_value.tv_nsec = ms > 0 ? (ms % 1000) * 1'000'000 : 1;
    if (its.it_value.tv_sec == 0 && its.it_value.tv_nsec == 0) {
        its.it_value.tv_nsec = 1;
    }
    if (::timerfd_settime(fd_.get(), TFD_TIMER_ABSTIME, &its, nullptr) != 0) {
        return os_error("timerfd_settime (offset: errno)");
    }
    return {};
}

Result<void> TimerFd::disarm() {
    itimerspec its{};
    if (::timerfd_settime(fd_.get(), 0, &its, nullptr) != 0) {
        return os_error("timerfd_settime (offset: errno)");
    }
    return {};
}

std::uint64_t TimerFd::drain() noexcept {
    std::uint64_t v = 0;
    if (::read(fd_.get(), &v, sizeof v) != static_cast<ssize_t>(sizeof v)) {
        return 0;
    }
    return v;
}

} // namespace ksim
