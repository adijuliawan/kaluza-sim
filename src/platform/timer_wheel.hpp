// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// A hierarchical timer wheel at 1 ms resolution (plan M13, architecture §5):
// four levels of 256 slots cover 2^32 ms (49.7 days, past the longest NAS
// timer), with an overflow list beyond. One wheel per shard, used from that
// shard's thread only.
//
// Semantics, which the property test checks against a reference model:
//   - a timer fires in the first advance(now) with now >= its deadline; one
//     whose deadline has already passed fires at the next advance;
//   - within an advance, timers fire tick by tick; at one tick in the order
//     they were scheduled; a timer a callback schedules for that tick or an
//     earlier one fires at that tick, after the ones already due;
//   - a handle carries a generation, so cancel() of a timer that fired or was
//     cancelled (its slot reused or not) is a no-op that returns false, and a
//     cancelled timer never fires.
//   - next_deadline() is exact, so a tickless timerfd can sleep until it.

#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

#include "platform/clock.hpp"

namespace ksim {

struct TimerId {
    std::uint32_t index = UINT32_MAX;
    std::uint32_t generation = 0;
    bool valid() const noexcept { return index != UINT32_MAX; }
    friend bool operator==(const TimerId&, const TimerId&) = default;
};

class TimerWheel {
public:
    using Callback = std::function<void()>;

    explicit TimerWheel(Millis now = 0);

    TimerId schedule_at(Millis deadline, Callback cb);
    TimerId schedule_in(Millis delay, Callback cb) { return schedule_at(now_ + (delay > 0 ? delay : 0), std::move(cb)); }
    /// True if the timer was pending and now never fires.
    bool cancel(TimerId id) noexcept;
    bool pending(TimerId id) const noexcept;

    /// Fire every timer due at or before `now`; returns how many fired.
    std::size_t advance(Millis now);
    /// The earliest pending deadline (the current time for one already due).
    std::optional<Millis> next_deadline() const;

    Millis now() const noexcept { return now_; }
    std::size_t size() const noexcept { return live_; }

private:
    static constexpr int kLevels = 4;
    static constexpr int kBits = 8;
    static constexpr std::uint32_t kSlots = 1U << kBits;
    static constexpr std::int32_t kNone = -1;
    static constexpr std::uint16_t kDue = 0xFFFE;        // list: overdue at scheduling
    static constexpr std::uint16_t kOverflow = 0xFFFD;   // list: beyond the top level

    struct Node {
        Millis deadline = 0;
        std::uint64_t seq = 0;
        std::uint32_t generation = 0;
        std::int32_t prev = kNone;
        std::int32_t next = kNone;
        std::uint16_t list = 0;   // level * kSlots + slot, kDue or kOverflow
        bool active = false;
        Callback cb;
    };

    std::int32_t& head(std::uint16_t list);
    void link(std::int32_t i, std::uint16_t list);
    void unlink(std::int32_t i);
    void place(std::int32_t i);
    void release(std::int32_t i);
    std::vector<std::int32_t> take(std::uint16_t list);
    void fire_sorted(std::vector<std::int32_t>& batch, std::size_t& fired);
    std::size_t fire_due();
    /// The next tick after now_ at which a slot fires or a non-empty slot
    /// cascades; ticks between change nothing, so advance() jumps over them.
    std::optional<Millis> next_event_tick() const;
    void cascade_at(std::uint64_t t);

    Millis now_;
    std::uint64_t seq_ = 0;
    std::size_t live_ = 0;
    std::vector<Node> nodes_;
    std::vector<std::int32_t> free_;
    std::array<std::int32_t, static_cast<std::size_t>(kLevels) * kSlots> slots_{};
    std::int32_t due_ = kNone;
    std::int32_t overflow_ = kNone;
};

} // namespace ksim
