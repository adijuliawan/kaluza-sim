// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The listening side's association (P2 Q2): an accepted association is
// reported up and forwarded; a second one while the first is up is aborted;
// after a loss the next one is taken.

#include <gtest/gtest.h>

#include <memory>
#include <vector>

#include "platform/assoc_slot.hpp"

namespace ksim {
namespace {

class FakeAssoc final : public IAssoc {
public:
    void set_handlers(OnMessage m, OnEvent e) override {
        on_message = std::move(m);
        on_event = std::move(e);
    }
    Result<void> send(ByteView msg, SctpMeta meta) override {
        sent.emplace_back(msg.begin(), msg.end());
        streams_used.push_back(meta.stream);
        return {};
    }
    bool up() const noexcept override { return is_up; }
    std::uint16_t out_streams() const noexcept override { return 8; }
    std::uint16_t in_streams() const noexcept override { return 8; }
    void shutdown() override { is_up = false; }
    void abort() override {
        is_up = false;
        aborted = true;
        if (abort_seen != nullptr) {
            *abort_seen = true;
        }
    }
    Endpoint peer() const override { return Endpoint::v4(127, 0, 10, 2, 40000); }

    void lose() {
        is_up = false;
        if (on_event) {
            on_event(LinkEvent::lost);
        }
    }

    bool is_up = true;
    bool aborted = false;
    bool* abort_seen = nullptr;   // outlives the association
    std::vector<Bytes> sent;
    std::vector<std::uint16_t> streams_used;
    OnMessage on_message;
    OnEvent on_event;
};

TEST(AssocSlot, AnAcceptedAssociationIsReportedUpAndForwarded) {
    AssocSlot slot;
    std::vector<LinkEvent> events;
    std::vector<Bytes> got;
    slot.set_handlers([&](ByteView m, SctpMeta) { got.emplace_back(m.begin(), m.end()); },
                      [&](LinkEvent e) { events.push_back(e); });
    EXPECT_FALSE(slot.up());
    EXPECT_FALSE(slot.send(Bytes{1}, SctpMeta{62, 0}));
    auto a = std::make_unique<FakeAssoc>();
    FakeAssoc* raw = a.get();
    ASSERT_TRUE(slot.take(std::move(a)));
    ASSERT_EQ(events.size(), 1u);
    EXPECT_EQ(events[0], LinkEvent::up);
    EXPECT_TRUE(slot.up());
    EXPECT_EQ(slot.out_streams(), 8);
    ASSERT_TRUE(slot.send(Bytes{1, 2}, SctpMeta{62, 3}));
    EXPECT_EQ(raw->streams_used.back(), 3);
    raw->on_message(Bytes{9}, SctpMeta{62, 1});
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(got[0], Bytes{9});
}

TEST(AssocSlot, ASecondPeerIsRefusedWhileTheFirstIsUp) {
    AssocSlot slot;
    slot.set_handlers([](ByteView, SctpMeta) {}, [](LinkEvent) {});
    ASSERT_TRUE(slot.take(std::make_unique<FakeAssoc>()));
    auto second = std::make_unique<FakeAssoc>();
    bool aborted = false;
    second->abort_seen = &aborted;
    EXPECT_FALSE(slot.take(std::move(second)));
    EXPECT_TRUE(aborted);
    EXPECT_TRUE(slot.up());
    EXPECT_EQ(slot.refused(), 1u);
    EXPECT_EQ(slot.taken(), 1u);
}

TEST(AssocSlot, AfterALossTheNextPeerIsTaken) {
    AssocSlot slot;
    std::vector<LinkEvent> events;
    slot.set_handlers([](ByteView, SctpMeta) {}, [&](LinkEvent e) { events.push_back(e); });
    auto a = std::make_unique<FakeAssoc>();
    FakeAssoc* first = a.get();
    ASSERT_TRUE(slot.take(std::move(a)));
    first->lose();
    EXPECT_FALSE(slot.up());
    ASSERT_TRUE(slot.take(std::make_unique<FakeAssoc>()));
    EXPECT_TRUE(slot.up());
    const std::vector<LinkEvent> want{LinkEvent::up, LinkEvent::lost, LinkEvent::up};
    EXPECT_EQ(events, want);
    EXPECT_EQ(slot.taken(), 2u);
}

} // namespace
} // namespace ksim
