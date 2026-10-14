// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Clocks (plan M13, architecture §5). Timers run on CLOCK_MONOTONIC in
// milliseconds; capture timestamps and the SFN epoch use CLOCK_REALTIME. A
// ManualClock stands in for either in tests and in virtual time.

#pragma once

#include <atomic>
#include <cstdint>

namespace ksim {

using Millis = std::int64_t;   // milliseconds on a clock's own scale

class Clock {
public:
    virtual ~Clock() = default;
    virtual Millis now_ms() const noexcept = 0;
};

/// CLOCK_MONOTONIC.
class MonotonicClock final : public Clock {
public:
    Millis now_ms() const noexcept override;
};

/// A clock that moves only when told to: tests and virtual time.
class ManualClock final : public Clock {
public:
    explicit ManualClock(Millis start = 0) noexcept : t_(start) {}
    Millis now_ms() const noexcept override { return t_.load(std::memory_order_acquire); }
    void set(Millis t) noexcept { t_.store(t, std::memory_order_release); }
    void advance(Millis d) noexcept { t_.fetch_add(d, std::memory_order_acq_rel); }

private:
    std::atomic<Millis> t_;
};

std::int64_t monotonic_ns() noexcept;
/// Nanoseconds since the Unix epoch (pcapng timestamps, the SFN epoch).
std::int64_t realtime_ns() noexcept;

} // namespace ksim
