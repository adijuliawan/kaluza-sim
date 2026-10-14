// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "platform/clock.hpp"

#include <ctime>

namespace ksim {

namespace {
std::int64_t read_ns(clockid_t id) noexcept {
    timespec ts{};
    ::clock_gettime(id, &ts);
    return static_cast<std::int64_t>(ts.tv_sec) * 1'000'000'000 + ts.tv_nsec;
}
} // namespace

std::int64_t monotonic_ns() noexcept {
    return read_ns(CLOCK_MONOTONIC);
}

std::int64_t realtime_ns() noexcept {
    return read_ns(CLOCK_REALTIME);
}

Millis MonotonicClock::now_ms() const noexcept {
    return monotonic_ns() / 1'000'000;
}

} // namespace ksim
