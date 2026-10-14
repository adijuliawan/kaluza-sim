// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The simulation's keyed pseudo-random streams (P1 N1; requirements §3.3).

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <set>
#include <vector>

#include "platform/rng.hpp"

namespace ksim {
namespace {

std::vector<std::uint64_t> draw(Rng r, int n) {
    std::vector<std::uint64_t> v;
    v.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        v.push_back(r.next());
    }
    return v;
}

TEST(Rng, TheSameSeedAndKeyGiveTheSameStream) {
    EXPECT_EQ(draw(Rng(7, {1, 2}), 50), draw(Rng(7, {1, 2}), 50));
    EXPECT_NE(draw(Rng(7, {1, 2}), 50), draw(Rng(8, {1, 2}), 50));
    EXPECT_NE(draw(Rng(7, {1, 2}), 50), draw(Rng(7, {2, 1}), 50));
    EXPECT_NE(draw(Rng(7, {1}), 50), draw(Rng(7, {1, 0}), 50));
}

TEST(Rng, StreamsDoNotPerturbEachOther) {
    // Drawing from one UE's stream must not change another's: adding a UE or a
    // draw somewhere keeps the rest of a run as it was.
    const Rng run(1234);
    Rng ue1 = run.stream({1});
    const auto before = draw(run.stream({2}), 20);
    for (int i = 0; i < 1000; ++i) {
        ue1.next();
    }
    EXPECT_EQ(draw(run.stream({2}), 20), before);
    EXPECT_EQ(draw(run.stream({1}), 5), draw(Rng(1234, {1}), 5));
}

TEST(Rng, BelowAndUniformStayInRangeAndCoverIt) {
    Rng r(99, {Rng::label("range")});
    std::array<int, 7> hist{};
    for (int i = 0; i < 70'000; ++i) {
        const auto v = r.below(7);
        ASSERT_LT(v, 7u);
        ++hist[v];
    }
    for (int c : hist) {
        EXPECT_NEAR(c, 10'000, 600);   // about 6 standard deviations
    }
    std::set<std::int64_t> seen;
    for (int i = 0; i < 2000; ++i) {
        const auto v = r.uniform(-3, 3);
        ASSERT_GE(v, -3);
        ASSERT_LE(v, 3);
        seen.insert(v);
    }
    EXPECT_EQ(seen.size(), 7u);
    EXPECT_EQ(r.below(1), 0u);
    EXPECT_EQ(r.uniform(5, 5), 5);
    (void)r.uniform(INT64_MIN, INT64_MAX);   // the full range is allowed
}

TEST(Rng, UnitIsInTheHalfOpenInterval) {
    Rng r(5);
    double sum = 0;
    for (int i = 0; i < 100'000; ++i) {
        const double u = r.unit();
        ASSERT_GE(u, 0.0);
        ASSERT_LT(u, 1.0);
        sum += u;
    }
    EXPECT_NEAR(sum / 100'000, 0.5, 0.01);
}

TEST(Rng, FillIsTheStreamsBytes) {
    Rng a(3);
    Rng b(3);
    std::array<std::uint8_t, 13> buf{};
    a.fill(buf);
    const std::uint64_t first = b.next();
    for (int i = 0; i < 8; ++i) {
        EXPECT_EQ(buf[static_cast<std::size_t>(i)], static_cast<std::uint8_t>(first >> (8 * i)));
    }
    EXPECT_EQ(a.draws(), 2u);
}

TEST(Rng, LabelsAreStableAndDistinct) {
    static_assert(Rng::label("kair.jitter") == Rng::label("kair.jitter"));
    static_assert(Rng::label("") == 0xcbf29ce484222325ULL);   // FNV-1a offset basis
    EXPECT_NE(Rng::label("kair.jitter"), Rng::label("kair.loss"));
}

} // namespace
} // namespace ksim
