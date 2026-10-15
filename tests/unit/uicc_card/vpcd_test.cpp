// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The vpcd framing and its two roles (P1 N14; sim-uicc.md §5): the soft card
// behind the protocol answers the ATR request and APDUs, and a terminal over
// VpcdTransport reaches it as it reaches an in-process card. The stream here
// is a pair in memory, delivering in order through the executor, as a socket
// would; bytes are cut at every octet to exercise the deframer.

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

#include "fixture.hpp"
#include "platform/sim_loop.hpp"
#include "uicc/transport/vpcd.hpp"

namespace ksim::uicc::test {
namespace {

/// One end of an in-memory stream pair; what one end sends the other gets on the loop.
class PipeEnd final : public IStream {
public:
    explicit PipeEnd(SimLoop& loop) : loop_(loop) {}
    void set_handlers(OnData on_data, OnClosed on_closed) override {
        on_data_ = std::move(on_data);
        on_closed_ = std::move(on_closed);
    }
    Result<void> send(ByteView data) override {
        if (!open_ || peer_ == nullptr) {
            return make_error(Errc::closed, 0, "closed");
        }
        for (std::uint8_t b : data) {   // one octet at a time: the deframer must join them
            loop_.post([p = peer_, b] {
                if (p->open_ && p->on_data_) {
                    const std::uint8_t one[1] = {b};
                    p->on_data_(ByteView(one, 1));
                }
            });
        }
        return {};
    }
    bool open() const noexcept override { return open_; }
    void close() override {
        if (!open_) {
            return;
        }
        open_ = false;
        if (peer_ != nullptr && peer_->open_) {
            loop_.post([p = peer_] {
                p->open_ = false;
                if (p->on_closed_) {
                    p->on_closed_();
                }
            });
        }
    }
    Endpoint peer() const override { return {}; }

    PipeEnd* peer_ = nullptr;

private:
    SimLoop& loop_;
    bool open_ = true;
    OnData on_data_;
    OnClosed on_closed_;
};

TEST(Vpcd, FramesAreALengthOfTwoOctetsAndThePayload) {
    EXPECT_EQ(to_hex(vpcd::frame(Bytes{0x04})), "000104");
    std::vector<std::string> got;
    vpcd::Deframer d([&](ByteView m) { got.push_back(to_hex(m)); });
    d.feed(Bytes{0x00, 0x01, 0x04, 0x00});
    d.feed(Bytes{0x02, 0x90});
    EXPECT_EQ(got, std::vector<std::string>{"04"});
    d.feed(Bytes{0x00, 0x00, 0x00});
    EXPECT_EQ(got, (std::vector<std::string>{"04", "9000", ""}));
    EXPECT_EQ(d.buffered(), 0u);
}

TEST(Vpcd, TheCardAnswersTheAtrRequestAndApdusAndNotThePowerCodes) {
    SimLoop loop;
    auto card = make_card();
    PipeEnd reader(loop), card_end(loop);
    reader.peer_ = &card_end;
    card_end.peer_ = &reader;
    std::vector<std::string> taps;
    vpcd::VpcdCard vc(card_end, *card, [&](ByteView c, ByteView r) { taps.push_back(to_hex(c) + "/" + to_hex(r)); });
    std::vector<std::string> got;
    vpcd::Deframer d([&](ByteView m) { got.push_back(to_hex(m)); });
    reader.set_handlers([&](ByteView data) { d.feed(data); }, [] {});
    ASSERT_TRUE(reader.send(vpcd::frame(Bytes{vpcd::kPowerOn})));
    ASSERT_TRUE(reader.send(vpcd::frame(Bytes{vpcd::kReset})));
    ASSERT_TRUE(reader.send(vpcd::frame(Bytes{vpcd::kAtr})));
    ASSERT_TRUE(reader.send(vpcd::frame(*from_hex("00A40004023F00"))));   // SELECT MF, no Le: 61xx (T=0)
    ASSERT_TRUE(reader.send(vpcd::frame(Bytes{vpcd::kAtr})));   // pcscd's presence poll: answered, not tapped
    loop.run_for(10);
    ASSERT_EQ(got.size(), 3u);
    EXPECT_EQ(got[2], got[0]);
    EXPECT_EQ(got[0], to_hex(card->atr()));
    EXPECT_EQ(got[1].substr(0, 2), "61");
    EXPECT_TRUE(vc.powered());
    EXPECT_EQ(vc.resets(), 1u);
    EXPECT_EQ(vc.apdus(), 1u);
    EXPECT_EQ(taps.size(), 2u);
    EXPECT_EQ(taps[1], "00a40004023f00/" + got[1]);
}

TEST(Vpcd, ATerminalReachesTheCardThroughTheTransportInOrder) {
    SimLoop loop;
    auto card = make_card();
    auto term_end = std::make_unique<PipeEnd>(loop);
    PipeEnd card_end(loop);
    term_end->peer_ = &card_end;
    card_end.peer_ = term_end.get();
    PipeEnd* term_raw = term_end.get();
    vpcd::VpcdCard vc(card_end, *card);
    vpcd::VpcdTransport t(loop, std::move(term_end));
    std::vector<std::string> got;
    t.reset([&](const Result<Bytes>& r) { got.push_back(r ? to_hex(*r) : "err"); });
    t.transmit(*from_hex("00A40004023F00"), [&](const Result<Bytes>& r) { got.push_back(r ? to_hex(*r) : "err"); });
    t.transmit(*from_hex("00B0000002"), [&](const Result<Bytes>& r) { got.push_back(r ? to_hex(*r) : "err"); });
    loop.run_for(10);
    ASSERT_EQ(got.size(), 3u);
    EXPECT_EQ(got[0], to_hex(card->atr()));
    EXPECT_EQ(got[1].substr(0, 2), "61");
    EXPECT_EQ(vc.resets(), 1u);
    // The card goes away: what waits fails with closed.
    std::string last;
    t.transmit(*from_hex("00F2000000"), [&](const Result<Bytes>& r) { last = r ? to_hex(*r) : errc_name(r.error().code); });
    card_end.close();
    loop.run_for(10);
    (void)term_raw;
    EXPECT_EQ(last, "closed");
}

TEST(Vpcd, ACommandShorterThanAHeaderIsRefusedWithoutSendingIt) {
    SimLoop loop;
    auto end = std::make_unique<PipeEnd>(loop);
    PipeEnd other(loop);
    end->peer_ = &other;
    other.peer_ = end.get();
    std::size_t seen = 0;
    other.set_handlers([&](ByteView d) { seen += d.size(); }, [] {});
    vpcd::VpcdTransport t(loop, std::move(end));
    std::string got;
    t.transmit(Bytes{0x00, 0xA4}, [&](const Result<Bytes>& r) { got = r ? "ok" : errc_name(r.error().code); });
    loop.run_for(10);
    EXPECT_EQ(got, "invalid_argument");
    EXPECT_EQ(seen, 0u);
}

} // namespace
} // namespace ksim::uicc::test
