// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The timer wheel (plan M13): its semantics (timer_wheel.hpp) against a plain
// reference model on random schedules, cancels and advances, including
// callbacks that schedule and cancel; handle generations; exact next
// deadlines on every level and beyond.

#include <gtest/gtest.h>

#include <map>
#include <random>
#include <vector>

#include "platform/timer_wheel.hpp"

namespace ksim {
namespace {

TEST(TimerWheel, FiresAtItsDeadlineInScheduleOrder) {
    TimerWheel w(1000);
    std::vector<int> order;
    w.schedule_at(1005, [&] { order.push_back(2); });
    w.schedule_at(1003, [&] { order.push_back(1); });
    w.schedule_at(1005, [&] { order.push_back(3); });
    EXPECT_EQ(w.advance(1004), 1U);
    EXPECT_EQ(order, (std::vector<int>{1}));
    EXPECT_EQ(w.advance(1005), 2U);
    EXPECT_EQ(order, (std::vector<int>{1, 2, 3}));
    EXPECT_EQ(w.size(), 0U);
}

TEST(TimerWheel, OverdueTimersFireAtTheNextAdvance) {
    TimerWheel w(50);
    int n = 0;
    w.schedule_at(10, [&] { ++n; });
    w.schedule_in(-5, [&] { ++n; });
    EXPECT_EQ(*w.next_deadline(), 50);
    EXPECT_EQ(w.advance(50), 2U);
    EXPECT_EQ(n, 2);
}

// A handle carries a generation: once its timer fired or was cancelled, the
// handle cannot cancel the timer that now uses the same node.
TEST(TimerWheel, StaleHandlesDoNothing) {
    TimerWheel w(0);
    int fired = 0;
    const TimerId a = w.schedule_at(10, [&] { fired += 1; });
    EXPECT_TRUE(w.cancel(a));
    EXPECT_FALSE(w.cancel(a));
    const TimerId b = w.schedule_at(10, [&] { fired += 10; });
    EXPECT_EQ(a.index, b.index);   // the node was reused
    EXPECT_FALSE(w.cancel(a));
    EXPECT_TRUE(w.pending(b));
    w.advance(10);
    EXPECT_EQ(fired, 10);
    EXPECT_FALSE(w.cancel(b));
    EXPECT_FALSE(w.pending(b));
}

TEST(TimerWheel, CallbacksCancelLaterTimersAndScheduleDueOnes) {
    TimerWheel w(0);
    std::vector<int> order;
    TimerId later;
    w.schedule_at(5, [&] {
        order.push_back(1);
        w.cancel(later);                                  // due at the same tick: must not fire
        w.schedule_at(3, [&] { order.push_back(3); });    // already due: fires at this tick
    });
    later = w.schedule_at(5, [&] { order.push_back(2); });
    w.schedule_at(6, [&] { order.push_back(4); });
    w.advance(6);
    EXPECT_EQ(order, (std::vector<int>{1, 3, 4}));
}

// Exact next deadlines on each level and in the overflow list.
TEST(TimerWheel, NextDeadlineIsExact) {
    for (Millis start : {Millis{0}, Millis{255}, Millis{65535}, Millis{123456789}}) {
        for (Millis delay : {Millis{1}, Millis{200}, Millis{300}, Millis{70'000}, Millis{5LL * 3'600'000},
                             Millis{60LL * 86'400'000}}) {
            TimerWheel w(start);
            bool fired = false;
            w.schedule_in(delay, [&] { fired = true; });
            w.schedule_in(delay + 7, [] {});
            ASSERT_EQ(*w.next_deadline(), start + delay) << start << "+" << delay;
            w.advance(start + delay - 1);
            ASSERT_FALSE(fired) << start << "+" << delay;
            ASSERT_EQ(*w.next_deadline(), start + delay);
            w.advance(start + delay);
            ASSERT_TRUE(fired) << start << "+" << delay;
            ASSERT_EQ(*w.next_deadline(), start + delay + 7);
        }
    }
}

// The reference: a map ordered by (effective deadline, sequence), advanced a
// tick at a time, firing what is due at each tick with the same rules.
class Reference {
public:
    explicit Reference(Millis now) : now_(now) {}
    std::uint64_t schedule_at(Millis d, std::uint64_t tag) {
        const std::uint64_t seq = seq_++;
        entries_[{std::max(d, now_), seq}] = tag;
        return seq;
    }
    bool cancel(std::uint64_t seq) {
        for (auto it = entries_.begin(); it != entries_.end(); ++it) {
            if (it->first.second == seq) {
                entries_.erase(it);
                return true;
            }
        }
        return false;
    }
    template <class Fire>
    void advance(Millis now, Fire fire) {
        fire_until(now_, fire);
        // tick by tick in effect: nothing happens between entries
        while (!entries_.empty() && entries_.begin()->first.first <= now) {
            now_ = std::max(now_, entries_.begin()->first.first);
            fire_until(now_, fire);
        }
        now_ = std::max(now_, now);
    }
    std::optional<Millis> next() const {
        return entries_.empty() ? std::nullopt : std::optional(entries_.begin()->first.first);
    }
    Millis now_;

private:
    template <class Fire>
    void fire_until(Millis t, Fire fire) {
        while (!entries_.empty() && entries_.begin()->first.first <= t) {
            const auto [key, tag] = *entries_.begin();
            entries_.erase(entries_.begin());
            fire(key.second, tag);
        }
    }
    std::map<std::pair<Millis, std::uint64_t>, std::uint64_t> entries_;
    std::uint64_t seq_ = 0;
};

TEST(TimerWheel, AgreesWithTheReferenceModel) {
    for (std::uint32_t seed = 1; seed <= 20; ++seed) {
        std::mt19937_64 rng(seed);
        const Millis start = static_cast<Millis>(rng() % 100'000);
        TimerWheel w(start);
        Reference ref(start);
        std::vector<std::uint64_t> got;
        std::vector<std::uint64_t> want;
        std::map<std::uint64_t, std::pair<TimerId, std::uint64_t>> live;   // tag -> (wheel id, reference seq)
        std::uint64_t next_tag = 0;
        const auto delay = [&rng]() -> Millis {
            switch (rng() % 6) {
            case 0: return static_cast<Millis>(rng() % 4) - 2;         // overdue or now
            case 1: return static_cast<Millis>(rng() % 300);            // level 0 and 1
            case 2: return static_cast<Millis>(rng() % 70'000);         // level 1 and 2
            case 3: return static_cast<Millis>(rng() % 20'000'000);     // level 2 and 3
            default: return static_cast<Millis>(rng() % 3000);
            }
        };
        // Timers both know; some callbacks also schedule a follow-up in the
        // wheel alone (tag + 1'000'000), which must not disturb the others.
        const auto schedule = [&](std::uint64_t tag) {
            const Millis d = w.now() + delay();
            const bool chains = rng() % 8 == 0;
            const Millis follow_delay = delay();
            const TimerId id = w.schedule_at(d, [&, tag, chains, follow_delay] {
                got.push_back(tag);
                live.erase(tag);
                if (chains) {
                    w.schedule_in(follow_delay, [&got, tag] { got.push_back(1'000'000 + tag); });
                }
            });
            live[tag] = {id, ref.schedule_at(d, tag)};
        };
        for (int op = 0; op < 4000; ++op) {
            const auto r = rng() % 10;
            if (r < 6) {
                schedule(next_tag++);
            } else if (r < 8 && !live.empty()) {
                auto it = live.begin();
                std::advance(it, static_cast<long>(rng() % live.size()));
                EXPECT_TRUE(w.cancel(it->second.first));
                EXPECT_TRUE(ref.cancel(it->second.second));
                live.erase(it);
            } else {
                const Millis to = w.now() + static_cast<Millis>(rng() % 5000);
                w.advance(to);
                ref.advance(to, [&](std::uint64_t, std::uint64_t tag) { want.push_back(tag); });
                ASSERT_EQ(w.now(), ref.now_);
            }
        }
        w.advance(w.now() + 30'000'000);
        ref.advance(ref.now_ + 30'000'000, [&](std::uint64_t, std::uint64_t tag) { want.push_back(tag); });
        // A chained follow-up is scheduled inside the wheel's callback, so the
        // reference learns of it only then; compare the firing order of the
        // timers both knew from the start, and that every follow-up fired.
        std::vector<std::uint64_t> got_main;
        std::size_t follow = 0;
        for (auto t : got) {
            if (t >= 1'000'000) {
                ++follow;
            } else {
                got_main.push_back(t);
            }
        }
        std::vector<std::uint64_t> want_main;
        for (auto t : want) {
            if (t < 1'000'000) {
                want_main.push_back(t);
            }
        }
        ASSERT_EQ(got_main, want_main) << "seed " << seed;
        EXPECT_EQ(w.size(), 0U) << "seed " << seed;
        EXPECT_GT(follow, 0U);
    }
}

// Without callbacks that schedule, the two agree exactly, deadline by deadline.
TEST(TimerWheel, NextDeadlineAgreesWithTheReference) {
    std::mt19937_64 rng(99);
    TimerWheel w(0);
    Reference ref(0);
    std::uint64_t tag = 0;
    for (int op = 0; op < 20000; ++op) {
        if (rng() % 3 != 0) {
            const Millis d = w.now() + static_cast<Millis>(rng() % (rng() % 2 ? 500 : 10'000'000));
            w.schedule_at(d, [] {});
            ref.schedule_at(d, tag++);
        } else {
            const Millis to = w.now() + static_cast<Millis>(rng() % 20'000);
            w.advance(to);
            ref.advance(to, [](std::uint64_t, std::uint64_t) {});
        }
        ASSERT_EQ(w.next_deadline(), ref.next()) << "op " << op;
    }
}

} // namespace
} // namespace ksim
