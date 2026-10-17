// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The fault registry and its wrappers (P3 R3; node/aio/faults.hpp): rules as cli.md writes
// them, counts and percentages, the record a run keeps, the air link's AM retransmissions,
// and drop, delay and duplicate on an association and a datagram port.

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <sstream>

#include <unistd.h>

#include "codec/asn1/msg/ngap.hpp"
#include "codec/asn1/msg/names.hpp"
#include "node/aio/faults.hpp"
#include "platform/memlink.hpp"
#include "platform/sim_loop.hpp"

namespace ksim::node {
namespace {

struct Rig {
    SimLoop loop{0};
    EventRing events{1024, loop.clock()};
    Faults faults{events, "test:faults", 7};

    std::size_t named(std::string_view n) const {
        std::size_t k = 0;
        for (const auto& e : events.since(0, 1024)) {
            k += e.name == n ? 1 : 0;
        }
        return k;
    }
};

TEST(Faults, ARuleIsReadAsCliMdWritesItAndPrintedBackTheSame) {
    auto r = parse_rule("uu.ul msg=PRACH ue=17 drop x2");
    ASSERT_TRUE(r) << r.error().what;
    EXPECT_EQ(r->link, "uu");
    EXPECT_EQ(r->dir, "ul");
    EXPECT_EQ(r->message, "PRACH");
    EXPECT_EQ(r->ue, 17u);
    EXPECT_EQ(r->count, 2u);
    EXPECT_EQ(rule_text(*r), "uu.ul msg=PRACH ue=17 drop x2");
    auto d = parse_rule("n3.any delay=40 x* pct=30");
    ASSERT_TRUE(d);
    EXPECT_EQ(d->action, FaultRule::Action::delay);
    EXPECT_EQ(d->delay_ms, 40);
    EXPECT_EQ(d->count, 0u);
    EXPECT_EQ(rule_text(*d), "n3.any delay=40 x* pct=30");
    for (const char* bad : {"", "uu", "uu.ul", "uu.ul drop x0", "uu.ul drop pct=", "uu.ul jump"}) {
        EXPECT_FALSE(parse_rule(bad)) << bad;
    }
    Rig g;
    for (const char* bad : {"xn.ul drop", "uu.tx drop", "n3.ul drop pct=0", "n3.ul drop pct=101", "ngap.ul ue=1 drop",
                            "f1ap.dl delay=0"}) {
        auto p = parse_rule(bad);
        EXPECT_TRUE(!p || !g.faults.set(*p)) << bad;
    }
    EXPECT_EQ(g.faults.size(), 0u);
}

TEST(Faults, ADropOfNMatchesActsOnTheFirstNThenIsSpentEventedAndRecorded) {
    Rig g;
    const auto path = std::filesystem::temp_directory_path() / ("ksim-faults-" + std::to_string(::getpid()) + ".tsv");
    std::filesystem::remove(path);
    g.faults.record_to(path.string());
    auto r = parse_rule("n3.dl msg=G-PDU drop x2");
    ASSERT_TRUE(r);
    r->row = "ksim-p3.faults.msg-drop";
    auto id = g.faults.set(*r);
    ASSERT_TRUE(id);
    EXPECT_TRUE(g.faults.on("n3"));
    EXPECT_FALSE(g.faults.on("ngap"));
    EXPECT_FALSE(g.faults.check("n3", "ul", "G-PDU").drop);          // the other direction
    EXPECT_FALSE(g.faults.check("n3", "dl", "Echo Request").drop);   // another message
    EXPECT_TRUE(g.faults.check("n3", "dl", "G-PDU").drop);
    EXPECT_TRUE(g.faults.check("n3", "dl", "G-PDU").drop);
    EXPECT_FALSE(g.faults.check("n3", "dl", "G-PDU").drop);   // spent
    EXPECT_EQ(g.faults.size(), 0u);
    EXPECT_FALSE(g.faults.on("n3"));
    EXPECT_EQ(g.named("fault.set"), 1u);
    EXPECT_EQ(g.named("fault.hit"), 2u);
    std::ifstream f(path);
    std::stringstream s;
    s << f.rdbuf();
    EXPECT_EQ(s.str(), "set\t" + std::to_string(*id) + "\tksim-p3.faults.msg-drop\t0\tn3.dl msg=G-PDU drop x2\n" +
                           "spent\t" + std::to_string(*id) + "\tksim-p3.faults.msg-drop\t2\tn3.dl msg=G-PDU drop x2\n");
    std::filesystem::remove(path);
}

TEST(Faults, APercentageActsOnAboutThatShareAndTheSameSeedGivesTheSameDraws) {
    auto run = [] {
        Rig g;
        auto r = parse_rule("uu.dl drop x* pct=30");
        EXPECT_TRUE(r && g.faults.set(*r));
        std::string pattern;
        for (int i = 0; i < 1000; ++i) {
            pattern += g.faults.check("uu", "dl", "KEEPALIVE").drop ? '1' : '0';
        }
        return pattern;
    };
    const std::string a = run();
    EXPECT_EQ(a, run());
    const auto ones = std::count(a.begin(), a.end(), '1');
    EXPECT_GT(ones, 240);
    EXPECT_LT(ones, 360);
}

TEST(Faults, Ts38322_5_3_2_OnALossyAirLinkAnAmSduIsRetransmittedAndPastMaxRetxIsARadioLinkFailure) {
    Rig g;
    air::Frame am;
    am.type = air::FrameType::ul_sdu;
    am.radio_id = 3;
    am.sdus.push_back(air::Sdu{4, air::RlcMode::am, Bytes{1, 2, 3}});
    air::Frame um = am;
    um.sdus.front().mode = air::RlcMode::um;
    auto half = parse_rule("uu.ul ue=3 drop x* pct=50");
    ASSERT_TRUE(half);
    auto id = g.faults.set(*half);
    ASSERT_TRUE(id);
    int delayed = 0;
    int lost_um = 0;
    for (int i = 0; i < 200; ++i) {
        const auto v = g.faults.air("ul", am);
        EXPECT_FALSE(v.drop && !v.rlf);   // an AM SDU is delivered, later, or the link has failed
        EXPECT_EQ(v.delay_ms % Faults::kPollRetransmitMs, 0);
        delayed += v.delay_ms > 0 ? 1 : 0;
        lost_um += g.faults.air("ul", um).drop ? 1 : 0;
    }
    EXPECT_GT(delayed, 50);
    EXPECT_GT(lost_um, 60);
    air::Frame other = am;
    other.radio_id = 4;
    EXPECT_FALSE(g.faults.air("ul", other).drop);   // another UE's link
    ASSERT_TRUE(g.faults.clear(*id));
    auto all = parse_rule("uu.ul ue=3 drop x*");
    ASSERT_TRUE(all && g.faults.set(*all));
    const auto v = g.faults.air("ul", am);
    EXPECT_TRUE(v.drop);
    EXPECT_TRUE(v.rlf);
    // A rule on N matches drops the frame itself: no retransmission.
    g.faults.clear_all();
    auto once = parse_rule("uu.ul msg=UL_SDU drop x1");
    ASSERT_TRUE(once && g.faults.set(*once));
    const auto w = g.faults.air("ul", am);
    EXPECT_TRUE(w.drop);
    EXPECT_FALSE(w.rlf);
}

TEST(Faults, OnAnAssociationADropADelayAndADuplicateActOnTheNamedApMessage) {
    Rig g;
    MemAssocPair link(g.loop, Endpoint::v4(127, 0, 0, 2, 0), g.loop, Endpoint::v4(127, 0, 0, 1, 38412), 2);
    FaultAssoc gnb(link.a(), g.faults, g.loop, "ngap", "ul", "dl");
    std::vector<std::string> at_amf;
    std::vector<std::string> at_gnb;
    link.b().set_handlers([&](ByteView m, SctpMeta) { at_amf.push_back(asn1::message_name("ngap", m)); }, {});
    gnb.set_handlers([&](ByteView m, SctpMeta) { at_gnb.push_back(asn1::message_name("ngap", m)); }, {});
    link.connect();
    g.loop.run_until([&] { return gnb.up(); }, g.loop.now() + 100);
    const auto setup = ngap::encode(ngap::NgSetupFailure{ngap::Cause{"misc", "unspecified"}, std::nullopt});
    const auto reset = ngap::encode(ngap::NgReset{ngap::Cause{"misc", "om-intervention"}, true, {}});
    ASSERT_TRUE(setup && reset);
    EXPECT_EQ(asn1::message_name("ngap", *setup), "NGSetupFailure");
    auto drop = parse_rule("ngap.ul msg=NGReset drop x1");
    auto dup = parse_rule("ngap.dl msg=NGSetupFailure dup x1");
    auto delay = parse_rule("ngap.ul msg=NGSetupFailure delay=50 x1");
    ASSERT_TRUE(drop && dup && delay);
    ASSERT_TRUE(g.faults.set(*drop) && g.faults.set(*dup) && g.faults.set(*delay));
    ASSERT_TRUE(gnb.send(*reset, SctpMeta{60, 0}));   // dropped
    ASSERT_TRUE(gnb.send(*setup, SctpMeta{60, 0}));   // delayed 50 ms
    ASSERT_TRUE(gnb.send(*reset, SctpMeta{60, 0}));   // goes
    g.loop.run_until([] { return false; }, g.loop.now() + 20);
    EXPECT_EQ(at_amf, std::vector<std::string>{"NGReset"});
    g.loop.run_until([] { return false; }, g.loop.now() + 60);
    EXPECT_EQ(at_amf, (std::vector<std::string>{"NGReset", "NGSetupFailure"}));
    ASSERT_TRUE(link.b().send(*setup, SctpMeta{60, 0}));   // taken twice
    g.loop.run_until([] { return false; }, g.loop.now() + 20);
    EXPECT_EQ(at_gnb, (std::vector<std::string>{"NGSetupFailure", "NGSetupFailure"}));
    EXPECT_EQ(g.faults.size(), 0u);
}

TEST(Faults, OnADatagramPortGtpuMessagesAreNamedByType) {
    Rig g;
    MemNet net;
    auto a = net.bind(g.loop, Endpoint::v4(127, 0, 0, 1, 2152));
    auto b = net.bind(g.loop, Endpoint::v4(127, 0, 0, 2, 2152));
    ASSERT_TRUE(a && b);
    FaultDatagram up(std::move(*a), g.faults, g.loop, "n3", "ul", "dl");
    int got = 0;
    (*b)->set_handler([&](ByteView, const Endpoint&) { ++got; });
    auto r = parse_rule("n3.ul msg=G-PDU drop x1");
    ASSERT_TRUE(r && g.faults.set(*r));
    const Bytes gpdu{0x30, 0xFF, 0x00, 0x04, 0, 0, 0, 1, 0x45, 0, 0, 0};
    const Bytes echo{0x32, 0x01, 0x00, 0x04, 0, 0, 0, 0, 0, 1, 0, 0};
    ASSERT_TRUE(up.send_to(gpdu, Endpoint::v4(127, 0, 0, 2, 2152)));
    ASSERT_TRUE(up.send_to(echo, Endpoint::v4(127, 0, 0, 2, 2152)));
    ASSERT_TRUE(up.send_to(gpdu, Endpoint::v4(127, 0, 0, 2, 2152)));
    g.loop.run_until([] { return false; }, g.loop.now() + 20);
    EXPECT_EQ(got, 2);
}

} // namespace
} // namespace ksim::node
