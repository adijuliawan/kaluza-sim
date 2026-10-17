// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Several associations behind one listening side (P3 R2; ADR 0013 point 2): each
// gets its own link, its messages and events come with that link, a send goes on
// the link named, a link that goes leaves the others up, and a limit refuses one
// association too many.

#include <gtest/gtest.h>

#include <memory>
#include <utility>
#include <vector>

#include "platform/assoc_pool.hpp"

namespace ksim {
namespace {

class FakeAssoc final : public IAssoc {
public:
    void set_handlers(OnMessage m, OnEvent e) override {
        on_message = std::move(m);
        on_event = std::move(e);
    }
    Result<void> send(ByteView msg, SctpMeta) override {
        sent.emplace_back(msg.begin(), msg.end());
        return {};
    }
    bool up() const noexcept override { return is_up; }
    std::uint16_t out_streams() const noexcept override { return streams; }
    std::uint16_t in_streams() const noexcept override { return streams; }
    void shutdown() override { is_up = false; }
    void abort() override {
        is_up = false;
        if (abort_seen != nullptr) {
            *abort_seen = true;
        }
        if (on_event) {
            on_event(LinkEvent::lost);
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
    std::uint16_t streams = 10;
    bool* abort_seen = nullptr;
    std::vector<Bytes> sent;
    OnMessage on_message;
    OnEvent on_event;
};

struct Seen {
    std::vector<std::pair<LinkId, Bytes>> messages;
    std::vector<std::pair<LinkId, LinkEvent>> events;
};

void watch(AssocPool& pool, Seen& seen) {
    pool.set_handlers([&seen](LinkId l, ByteView m, SctpMeta) { seen.messages.emplace_back(l, Bytes(m.begin(), m.end())); },
                      [&seen](LinkId l, LinkEvent e) { seen.events.emplace_back(l, e); });
}

TEST(AssocPool, EachAcceptedAssociationIsItsOwnLink) {
    AssocPool pool;
    Seen seen;
    watch(pool, seen);
    auto a = std::make_unique<FakeAssoc>();
    auto b = std::make_unique<FakeAssoc>();
    b->streams = 4;
    FakeAssoc* ra = a.get();
    FakeAssoc* rb = b.get();
    ASSERT_TRUE(pool.take(std::move(a)));
    ASSERT_TRUE(pool.take(std::move(b)));
    ASSERT_EQ(pool.links(), (std::vector<LinkId>{1, 2}));
    EXPECT_EQ(pool.out_streams(2), 4);
    ra->on_message(Bytes{1}, SctpMeta{62, 0});
    rb->on_message(Bytes{2}, SctpMeta{62, 0});
    ASSERT_EQ(seen.messages.size(), 2u);
    EXPECT_EQ(seen.messages[0], (std::pair<LinkId, Bytes>{1, Bytes{1}}));
    EXPECT_EQ(seen.messages[1], (std::pair<LinkId, Bytes>{2, Bytes{2}}));
    ASSERT_TRUE(pool.send(2, Bytes{7}, SctpMeta{62, 1}));
    EXPECT_TRUE(ra->sent.empty());
    ASSERT_EQ(rb->sent.size(), 1u);
    EXPECT_FALSE(pool.send(9, Bytes{7}, SctpMeta{62, 1}));
}

TEST(AssocPool, ALinkThatGoesLeavesTheOthersUp) {
    AssocPool pool;
    Seen seen;
    watch(pool, seen);
    auto a = std::make_unique<FakeAssoc>();
    FakeAssoc* ra = a.get();
    ASSERT_TRUE(pool.take(std::move(a)));
    ASSERT_TRUE(pool.take(std::make_unique<FakeAssoc>()));
    ra->lose();
    EXPECT_FALSE(pool.up(1));
    EXPECT_TRUE(pool.up(2));
    EXPECT_EQ(pool.links(), std::vector<LinkId>{2});
    EXPECT_EQ(seen.events.back(), (std::pair<LinkId, LinkEvent>{1, LinkEvent::lost}));
    ASSERT_TRUE(pool.take(std::make_unique<FakeAssoc>()));   // frees the one that went
    EXPECT_EQ(pool.links(), (std::vector<LinkId>{2, 3}));
    pool.abort_all();
    EXPECT_TRUE(pool.links().empty());
}

TEST(AssocPool, OneOverTheLimitIsRefused) {
    AssocPool pool(1);
    Seen seen;
    watch(pool, seen);
    ASSERT_TRUE(pool.take(std::make_unique<FakeAssoc>()));
    auto second = std::make_unique<FakeAssoc>();
    bool aborted = false;
    second->abort_seen = &aborted;
    EXPECT_FALSE(pool.take(std::move(second)));
    EXPECT_TRUE(aborted);
    EXPECT_EQ(pool.refused(), 1u);
    EXPECT_EQ(pool.taken(), 1u);
}

TEST(AssocPool, BorrowedAssociationsAndASingleOneAreLinksToo) {
    FakeAssoc x;
    FakeAssoc y;
    AssocPool pool;
    Seen seen;
    watch(pool, seen);
    EXPECT_EQ(pool.add(x), 1u);
    EXPECT_EQ(pool.add(y), 2u);
    y.on_event(LinkEvent::up);
    EXPECT_EQ(seen.events.back(), (std::pair<LinkId, LinkEvent>{2, LinkEvent::up}));
    y.lose();
    EXPECT_TRUE(pool.up(1));
    EXPECT_FALSE(pool.up(2));

    FakeAssoc z;
    SingleAssocPool one(z);
    std::vector<LinkId> from;
    one.set_handlers([&](LinkId l, ByteView, SctpMeta) { from.push_back(l); }, [](LinkId, LinkEvent) {});
    z.on_message(Bytes{1}, SctpMeta{62, 0});
    EXPECT_EQ(from, std::vector<LinkId>{1});
    EXPECT_TRUE(one.send(1, Bytes{3}, SctpMeta{62, 0}));
    EXPECT_FALSE(one.send(2, Bytes{3}, SctpMeta{62, 0}));
    EXPECT_EQ(one.links(), std::vector<LinkId>{1});
}

} // namespace
} // namespace ksim
