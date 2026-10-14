// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "platform/timer_wheel.hpp"

#include <algorithm>

namespace ksim {

namespace {
constexpr std::uint16_t kDetached = 0xFFFF;   // taken from its list, about to fire
} // namespace

TimerWheel::TimerWheel(Millis now) : now_(now) {
    slots_.fill(kNone);
}

std::int32_t& TimerWheel::head(std::uint16_t list) {
    if (list == kDue) {
        return due_;
    }
    if (list == kOverflow) {
        return overflow_;
    }
    return slots_[list];
}

void TimerWheel::link(std::int32_t i, std::uint16_t list) {
    Node& n = nodes_[static_cast<std::size_t>(i)];
    std::int32_t& h = head(list);
    n.list = list;
    n.prev = kNone;
    n.next = h;
    if (h != kNone) {
        nodes_[static_cast<std::size_t>(h)].prev = i;
    }
    h = i;
}

void TimerWheel::unlink(std::int32_t i) {
    Node& n = nodes_[static_cast<std::size_t>(i)];
    if (n.list == kDetached) {
        return;
    }
    if (n.prev != kNone) {
        nodes_[static_cast<std::size_t>(n.prev)].next = n.next;
    } else {
        head(n.list) = n.next;
    }
    if (n.next != kNone) {
        nodes_[static_cast<std::size_t>(n.next)].prev = n.prev;
    }
    n.prev = n.next = kNone;
    n.list = kDetached;
}

/// The list for a node's deadline relative to now_: overdue, the lowest level
/// whose block holds both, or overflow.
void TimerWheel::place(std::int32_t i) {
    const Millis d = nodes_[static_cast<std::size_t>(i)].deadline;
    if (d <= now_) {
        link(i, kDue);
        return;
    }
    const auto ud = static_cast<std::uint64_t>(d);
    const auto un = static_cast<std::uint64_t>(now_);
    for (int level = 0; level < kLevels; ++level) {
        const int shift = kBits * (level + 1);
        if ((ud >> shift) == (un >> shift)) {
            const auto slot = static_cast<std::uint16_t>((ud >> (kBits * level)) & (kSlots - 1));
            link(i, static_cast<std::uint16_t>(level * static_cast<int>(kSlots) + slot));
            return;
        }
    }
    link(i, kOverflow);
}

void TimerWheel::release(std::int32_t i) {
    Node& n = nodes_[static_cast<std::size_t>(i)];
    n.active = false;
    n.cb = nullptr;
    ++n.generation;
    free_.push_back(i);
    --live_;
}

TimerId TimerWheel::schedule_at(Millis deadline, Callback cb) {
    std::int32_t i;
    if (!free_.empty()) {
        i = free_.back();
        free_.pop_back();
    } else {
        i = static_cast<std::int32_t>(nodes_.size());
        nodes_.emplace_back();
    }
    Node& n = nodes_[static_cast<std::size_t>(i)];
    n.deadline = deadline;
    n.seq = seq_++;
    n.active = true;
    n.cb = std::move(cb);
    n.list = kDetached;
    ++live_;
    place(i);
    return {static_cast<std::uint32_t>(i), n.generation};
}

bool TimerWheel::pending(TimerId id) const noexcept {
    return id.index < nodes_.size() && nodes_[id.index].active && nodes_[id.index].generation == id.generation;
}

bool TimerWheel::cancel(TimerId id) noexcept {
    if (!pending(id)) {
        return false;
    }
    const auto i = static_cast<std::int32_t>(id.index);
    unlink(i);
    release(i);
    return true;
}

std::vector<std::int32_t> TimerWheel::take(std::uint16_t list) {
    std::vector<std::int32_t> out;
    for (std::int32_t i = head(list); i != kNone;) {
        const std::int32_t next = nodes_[static_cast<std::size_t>(i)].next;
        out.push_back(i);
        Node& n = nodes_[static_cast<std::size_t>(i)];
        n.prev = n.next = kNone;
        n.list = kDetached;
        i = next;
    }
    head(list) = kNone;
    return out;
}

void TimerWheel::fire_sorted(std::vector<std::int32_t>& batch, std::size_t& fired) {
    std::sort(batch.begin(), batch.end(), [this](std::int32_t a, std::int32_t b) {
        return nodes_[static_cast<std::size_t>(a)].seq < nodes_[static_cast<std::size_t>(b)].seq;
    });
    // Each entry with the generation it had when taken: an earlier callback may
    // cancel a later one, and its node may already serve a new timer.
    std::vector<std::pair<std::int32_t, std::uint32_t>> work;
    work.reserve(batch.size());
    for (std::int32_t i : batch) {
        work.emplace_back(i, nodes_[static_cast<std::size_t>(i)].generation);
    }
    for (auto [i, gen] : work) {
        Node& n = nodes_[static_cast<std::size_t>(i)];
        if (!n.active || n.generation != gen || n.list != kDetached) {
            continue;
        }
        Callback cb = std::move(n.cb);
        release(i);   // not pending while it runs; its node may be reused at once
        ++fired;
        if (cb) {
            cb();
        }
    }
}

std::size_t TimerWheel::fire_due() {
    std::size_t fired = 0;
    while (due_ != kNone) {
        auto batch = take(kDue);
        fire_sorted(batch, fired);
    }
    return fired;
}

void TimerWheel::cascade_at(std::uint64_t t) {
    if ((t & 0xFFFF'FFFFULL) == 0) {
        for (std::int32_t i : take(kOverflow)) {
            place(i);
        }
    }
    for (int level = kLevels - 1; level >= 1; --level) {
        const int shift = kBits * level;
        if ((t & ((1ULL << shift) - 1)) == 0) {
            const auto slot = static_cast<std::uint16_t>((t >> shift) & (kSlots - 1));
            for (std::int32_t i : take(static_cast<std::uint16_t>(level * static_cast<int>(kSlots) + slot))) {
                place(i);
            }
        }
    }
}

std::optional<Millis> TimerWheel::next_event_tick() const {
    const auto un = static_cast<std::uint64_t>(now_);
    for (int level = 0; level < kLevels; ++level) {
        const int shift = kBits * level;
        const auto here = static_cast<std::uint32_t>((un >> shift) & (kSlots - 1));
        for (std::uint32_t s = here + 1; s < kSlots; ++s) {
            if (slots_[static_cast<std::size_t>(level) * kSlots + s] != kNone) {
                // level 0: the slot's own tick; above: the tick its slot cascades
                const int above = kBits * (level + 1);
                return static_cast<Millis>(((un >> above) << above) | (std::uint64_t{s} << shift));
            }
        }
    }
    if (overflow_ != kNone) {
        return static_cast<Millis>(((un >> 32) + 1) << 32);
    }
    return std::nullopt;
}

std::size_t TimerWheel::advance(Millis now) {
    std::size_t fired = fire_due();
    while (now_ < now) {
        const auto next = next_event_tick();
        if (!next || *next > now) {
            now_ = now;   // nothing fires or cascades before then
            break;
        }
        now_ = *next;
        const auto t = static_cast<std::uint64_t>(now_);
        cascade_at(t);
        auto batch = take(static_cast<std::uint16_t>(t & (kSlots - 1)));
        fire_sorted(batch, fired);
        fired += fire_due();
    }
    return fired;
}

std::optional<Millis> TimerWheel::next_deadline() const {
    if (due_ != kNone) {
        return now_;
    }
    const auto un = static_cast<std::uint64_t>(now_);
    for (int level = 0; level < kLevels; ++level) {
        const int shift = kBits * level;
        const auto here = static_cast<std::uint32_t>((un >> shift) & (kSlots - 1));
        for (std::uint32_t s = here + 1; s < kSlots; ++s) {
            std::int32_t i = slots_[static_cast<std::size_t>(level) * kSlots + s];
            if (i == kNone) {
                continue;
            }
            Millis best = nodes_[static_cast<std::size_t>(i)].deadline;
            for (; i != kNone; i = nodes_[static_cast<std::size_t>(i)].next) {
                best = std::min(best, nodes_[static_cast<std::size_t>(i)].deadline);
            }
            return best;
        }
    }
    std::optional<Millis> best;
    for (std::int32_t i = overflow_; i != kNone; i = nodes_[static_cast<std::size_t>(i)].next) {
        const Millis d = nodes_[static_cast<std::size_t>(i)].deadline;
        best = best ? std::min(*best, d) : d;
    }
    return best;
}

} // namespace ksim
