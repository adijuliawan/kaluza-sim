// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The event ring and its NDJSON form (P1 N1, ADR 0009 point 6). Event names in
// tests are not registered: check_events.py scans only src/ and apps/.

#include <gtest/gtest.h>

#include <chrono>
#include <string>
#include <thread>
#include <vector>

#include "platform/clock.hpp"
#include "platform/event.hpp"
#include "platform/mutation.hpp"

namespace ksim {
namespace {

TEST(EventRing, NumbersEventsAndKeepsTheNewest) {
    ManualClock clock(100);
    EventRing ring(3, clock);
    for (int i = 0; i < 5; ++i) {
        clock.advance(10);
        ring.emit("test.step", "ue:1", {{"i", std::to_string(i)}});
    }
    EXPECT_EQ(ring.last_seq(), 5u);
    EXPECT_EQ(ring.dropped(), 2u);
    const auto all = ring.since(0);
    ASSERT_EQ(all.size(), 3u);
    EXPECT_EQ(all.front().seq, 3u);
    EXPECT_EQ(all.front().time_ms, 130);
    EXPECT_EQ(*all.back().find("i"), "4");
    EXPECT_EQ(all.back().find("nope"), nullptr);
    EXPECT_EQ(ring.since(4).size(), 1u);
    EXPECT_EQ(ring.since(0, 2).size(), 2u);
}

TEST(EventRing, WaitFindsAMatchThatArrivesLater) {
    MonotonicClock clock;
    EventRing ring(64, clock);
    ring.emit("test.other", "ue:1", {});
    const std::uint64_t mark = ring.last_seq();
    std::thread producer([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        ring.emit("test.noise", "ue:2", {});
        ring.emit("test.target", "ue:2", {{"result", "ACCEPT"}});
    });
    const auto got = ring.wait(mark, [](const Event& e) { return e.name == "test.target"; }, std::chrono::seconds(5));
    producer.join();
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(got->seq, 3u);
    EXPECT_EQ(*got->find("result"), "ACCEPT");
    EXPECT_FALSE(ring.wait(ring.last_seq(), [](const Event&) { return true; }, std::chrono::milliseconds(20)));
    // Waiting from 0 also matches what is already recorded (like grepping a log).
    EXPECT_TRUE(ring.wait(0, [](const Event& e) { return e.name == "test.other"; }, std::chrono::milliseconds(1)));
}

TEST(EventRing, TheListenerSeesEveryEventInOrder) {
    ManualClock clock;
    EventRing ring(2, clock);
    std::vector<std::uint64_t> seen;
    ring.on_emit([&](const Event& e) { seen.push_back(e.seq); });
    for (int i = 0; i < 4; ++i) {
        ring.emit("test.x", "s", {});
    }
    EXPECT_EQ(seen, (std::vector<std::uint64_t>{1, 2, 3, 4}));
}

TEST(EventRing, NdjsonIsOneEscapedLine) {
    Event e;
    e.seq = 7;
    e.time_ms = 1500;
    e.wall_ns = 42;
    e.name = "nas.reg.accept";
    e.subject = "ue:imsi-001010000300001";
    e.fields = {{"GUTI", "00101-cafe"}, {"note", "a \"quoted\"\ttab\nline\x01"}};
    EXPECT_EQ(to_ndjson(e),
              "{\"seq\":7,\"t_ms\":1500,\"wall_ns\":42,\"event\":\"nas.reg.accept\","
              "\"subject\":\"ue:imsi-001010000300001\",\"fields\":{\"GUTI\":\"00101-cafe\","
              "\"note\":\"a \\\"quoted\\\"\\ttab\\nline\\u0001\"}}");
}

TEST(Mutation, NothingIsSwitchedOnWithoutTheEnvironment) {
    // A normal build compiles every KSIM_MUTANT site to false; a mutant build
    // switches one on only by the KSIM_MUTANT environment variable.
    EXPECT_TRUE(active_mutant().empty() || kMutationsBuild);
    if (!kMutationsBuild) {
        EXPECT_FALSE(mutant_active("anything"));
    }
    EXPECT_FALSE(mutant_active(""));
}

} // namespace
} // namespace ksim
