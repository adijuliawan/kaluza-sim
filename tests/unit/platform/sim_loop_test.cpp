// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Virtual time (P1 N1, ADR 0009 point 5): hours of protocol timers run in
// milliseconds, fire exactly at their deadlines, and a run is a pure function
// of its seed.

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <vector>

#include "platform/rng.hpp"
#include "platform/sim_loop.hpp"

namespace ksim {
namespace {

TEST(SimLoop, TimeJumpsFromDeadlineToDeadline) {
    SimLoop loop(0);
    std::vector<Millis> fired;
    loop.start_timer(3'600'000, [&] { fired.push_back(loop.now()); });
    loop.start_timer(15'000, [&] { fired.push_back(loop.now()); });
    EXPECT_EQ(loop.run_until(10'000'000), 2u);
    EXPECT_EQ(fired, (std::vector<Millis>{15'000, 3'600'000}));
    EXPECT_EQ(loop.now(), 10'000'000);
    EXPECT_TRUE(loop.idle());
}

TEST(SimLoop, RunReadyDoesNotMoveTime) {
    SimLoop loop(500);
    int ran = 0;
    loop.post([&] { ++ran; });
    loop.start_timer(0, [&] { ++ran; });
    loop.start_timer(1, [&] { ++ran; });
    EXPECT_EQ(loop.run_ready(), 2u);
    EXPECT_EQ(loop.now(), 500);
    EXPECT_EQ(loop.pending_timers(), 1u);
}

TEST(SimLoop, RunUntilAPredicateStopsAtTheStepThatSatisfiesIt) {
    SimLoop loop(0);
    int count = 0;
    for (int i = 1; i <= 10; ++i) {
        loop.start_timer(Millis{i} * 1000, [&] { ++count; });
    }
    EXPECT_TRUE(loop.run_until([&] { return count == 4; }, 1'000'000));
    EXPECT_EQ(loop.now(), 4000);
    EXPECT_FALSE(loop.run_until([&] { return count == 100; }, 6500));
    EXPECT_EQ(count, 6);
}

// A model of a UE's NAS timers (TS 24.501 §10.2): mostly the periodic timer
// T3512 (54 min here) and T3502 (12 min), sometimes a short one (T3510, T3511,
// T3517, T3521: 10–15 s) and T3346 (random back-off). Some timers are stopped
// before they expire, as a procedure that completes stops its timer.
struct NasTimerModel {
    struct Ue {
        TimerId pending{};
        Millis started = 0;
        Millis delay = 0;
    };

    SimLoop loop{0};
    Rng rng;
    std::vector<Ue> ues;
    std::uint64_t digest = 0xcbf29ce484222325ULL;
    std::uint64_t fired = 0;
    std::uint64_t early_or_late = 0;

    NasTimerModel(std::uint64_t seed, int n_ues) : rng(seed, {Rng::label("nas-timers")}), ues(static_cast<std::size_t>(n_ues)) {}

    Millis pick() {
        const double p = rng.unit();
        if (p < 0.70) return 3'240'000;
        if (p < 0.85) return 720'000;
        if (p < 0.95) {
            static constexpr std::array<Millis, 4> kShort = {15'000, 10'000, 15'000, 15'000};
            return kShort[rng.below(kShort.size())];
        }
        return rng.uniform(1'000, 1'800'000);
    }

    void note(std::uint64_t v) {
        digest ^= v;
        digest *= 0x100000001b3ULL;
    }

    void arm(std::size_t i) {
        Ue& u = ues[i];
        u.delay = pick();
        u.started = loop.now();
        u.pending = loop.start_timer(u.delay, [this, i] { expire(i); });
        if (rng.chance(0.2)) {
            // the procedure completes first: the timer is stopped and another started
            const Millis after = rng.uniform(0, u.delay - 1);
            loop.start_timer(after, [this, i] {
                if (loop.stop_timer(ues[i].pending)) {
                    note(0x5700 + i);
                    arm(i);
                }
            });
        }
    }

    void expire(std::size_t i) {
        const Ue& u = ues[i];
        if (loop.now() != u.started + u.delay) {
            ++early_or_late;
        }
        ++fired;
        note(static_cast<std::uint64_t>(loop.now()) * 131 + i);
        arm(i);
    }

    void run(Millis hours) {
        for (std::size_t i = 0; i < ues.size(); ++i) {
            arm(i);
        }
        loop.run_until(hours * 3'600'000);
    }
};

TEST(SimLoop, TenHoursOfNasTimersFireExactlyAtTheirDeadlinesAndQuickly) {
    NasTimerModel m(42, 1000);
    const auto t0 = std::chrono::steady_clock::now();
    m.run(10);
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    EXPECT_EQ(m.early_or_late, 0u);
    EXPECT_GT(m.fired, 10'000u);
    RecordProperty("wall_ms", static_cast<int>(ms));
#if defined(NDEBUG) && !defined(__SANITIZE_ADDRESS__) && !defined(__SANITIZE_THREAD__)
    EXPECT_LT(ms, 100) << "10 h of 1000 UEs' NAS timers took " << ms << " ms";
#else
    EXPECT_LT(ms, 5000) << "10 h of 1000 UEs' NAS timers took " << ms << " ms (debug or sanitizer build)";
#endif
}

TEST(SimLoop, ARunIsAPureFunctionOfItsSeed) {
    std::vector<std::uint64_t> digests;
    for (std::uint64_t seed = 1; seed <= 100; ++seed) {
        NasTimerModel a(seed, 20);
        NasTimerModel b(seed, 20);
        a.run(10);
        b.run(10);
        ASSERT_EQ(a.digest, b.digest) << "seed " << seed;
        ASSERT_EQ(a.fired, b.fired) << "seed " << seed;
        digests.push_back(a.digest);
    }
    std::sort(digests.begin(), digests.end());
    EXPECT_EQ(std::unique(digests.begin(), digests.end()), digests.end()) << "two seeds gave the same run";
}

} // namespace
} // namespace ksim
