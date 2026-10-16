// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The UE's ideal MAC (random access per TS 38.321 §5.1 at KAIR level) and the
// SDAP entity (TS 37.324 §5.2), in virtual time (P1 N6).

#include <gtest/gtest.h>

#include <vector>

#include "entity/mac/ue_ideal.hpp"
#include "entity/rlc/ideal.hpp"
#include "entity/sdap/sdap.hpp"
#include "platform/sim_loop.hpp"

namespace ksim::entity {
namespace {

Bytes h(const char* s) { return *from_hex(s); }

/// A UE MAC with SRB0 attached, its frames captured.
struct Rig {
    SimLoop loop;
    std::vector<air::Frame> sent;
    UeIdealMac mac{loop, Rng(1, {2}), UeMacConfig{7, 10, 64, 3, 20, 56},
                   [this](air::Frame f) { sent.push_back(std::move(f)); }};
    IdealRlc srb0{0, RlcMode::tm, mac};
    std::vector<Bytes> ccch;
    std::optional<bool> result;

    Rig() { srb0.set_upper([this](Bytes b) { ccch.push_back(std::move(b)); }); }
    void start(const Bytes& sdu) {
        mac.start_ra(sdu, [this](bool ok) { result = ok; });
    }
    air::Frame rar_for(const air::Frame& prach, std::uint16_t tc) const {
        air::Frame r;
        r.type = air::FrameType::rar;
        r.rnti = prach.prach->ra_rnti();
        r.rar = air::Rar{prach.prach->preamble, tc, 0, 0};
        return r;
    }
    air::Frame msg4(std::uint16_t tc, ByteView ccch_of, const Bytes& setup) const {
        air::Frame m;
        m.type = air::FrameType::msg4;
        m.rnti = tc;
        m.contention_id = air::contention_id_of(ccch_of);
        m.sdus.push_back({0, RlcMode::tm, setup});
        return m;
    }
};

const Bytes kSetupRequest = h("1d2468acf13d");

TEST(UeMac, Clause5_1_RandomAccessResolvesContentionAndTakesTheCRnti) {
    Rig r;
    r.start(kSetupRequest);
    ASSERT_EQ(r.sent.size(), 1u);
    EXPECT_EQ(r.sent[0].type, air::FrameType::prach);
    EXPECT_EQ(r.sent[0].radio_id, 7u);
    r.mac.on_frame(r.rar_for(r.sent[0], 0x4601));
    ASSERT_EQ(r.sent.size(), 2u);
    EXPECT_EQ(r.sent[1].type, air::FrameType::msg3);
    EXPECT_EQ(r.sent[1].rnti, 0x4601);
    EXPECT_EQ(r.sent[1].sdus.at(0).data, kSetupRequest);
    r.mac.on_frame(r.msg4(0x4601, kSetupRequest, h("2040")));
    EXPECT_EQ(r.result, true);
    EXPECT_EQ(r.mac.c_rnti(), 0x4601);
    ASSERT_EQ(r.ccch.size(), 1u);
    EXPECT_EQ(r.ccch[0], h("2040"));
    // With a C-RNTI, SRB1 goes out in UL_SDU frames.
    IdealRlc srb1(1, RlcMode::am, r.mac);
    srb1.write_sdu(h("0000aa00000000"));
    ASSERT_EQ(r.sent.size(), 3u);
    EXPECT_EQ(r.sent[2].type, air::FrameType::ul_sdu);
    EXPECT_EQ(r.sent[2].rnti, 0x4601);
}

TEST(UeMac, Clause5_1_5_AnotherUesIdentityInMsg4MeansContentionLostAndARetry) {
    Rig r;
    r.start(kSetupRequest);
    r.mac.on_frame(r.rar_for(r.sent[0], 0x4601));
    r.mac.on_frame(r.msg4(0x4601, h("1d0000000000"), h("2040")));   // someone else's Msg3 won
    EXPECT_FALSE(r.result);
    EXPECT_EQ(r.mac.stats().contention_lost, 1u);
    EXPECT_FALSE(r.mac.c_rnti());
    EXPECT_TRUE(r.ccch.empty());
    r.loop.run_for(21);   // the backoff, then a new preamble
    ASSERT_EQ(r.sent.size(), 3u);
    EXPECT_EQ(r.sent[2].type, air::FrameType::prach);
}

TEST(UeMac, Clause5_1_4_NoResponseWithinTheWindowEndsInAnRaProblem) {
    Rig r;
    r.start(kSetupRequest);
    r.loop.run_for(1'000);
    EXPECT_EQ(r.result, false);   // preambleTransMax 3
    EXPECT_EQ(r.mac.stats().ra_attempts, 3u);
    EXPECT_FALSE(r.mac.ra_running());
}

TEST(UeMac, AResponseForAnotherPreambleIsIgnored) {
    Rig r;
    r.start(kSetupRequest);
    air::Frame rar = r.rar_for(r.sent[0], 0x4601);
    rar.rar->rapid = static_cast<std::uint8_t>((rar.rar->rapid + 1) % 56);
    r.mac.on_frame(rar);
    EXPECT_EQ(r.sent.size(), 1u);   // no Msg3
}

TEST(UeMac, DownlinkSdusForAnotherRntiOrAnUnattachedLcidAreDropped) {
    Rig r;
    r.start(kSetupRequest);
    r.mac.on_frame(r.rar_for(r.sent[0], 0x4601));
    r.mac.on_frame(r.msg4(0x4601, kSetupRequest, h("2040")));
    air::Frame d;
    d.type = air::FrameType::dl_sdu;
    d.rnti = 0x4602;
    d.sdus.push_back({0, RlcMode::tm, h("00")});
    r.mac.on_frame(d);
    d.rnti = 0x4601;
    d.sdus[0].lcid = 5;
    r.mac.on_frame(d);
    EXPECT_EQ(r.mac.stats().dropped, 2u);
    EXPECT_EQ(r.ccch.size(), 1u);
}

TEST(Sdap, Clause5_2_1_FlowsMapToTheirDrbOrTheDefaultWithTheHeaderWhereConfigured) {
    Sdap s(1);
    s.configure(SdapDrb{1, true, true, true, {9}, {}});
    s.configure(SdapDrb{2, false, false, false, {5}, {}});
    auto a = s.map_ul(9, h("45"));
    ASSERT_TRUE(a);
    EXPECT_EQ(a->drb_id, 1);
    EXPECT_EQ(to_hex(a->pdu), "8945");
    auto b = s.map_ul(5, h("45"));
    ASSERT_TRUE(b);
    EXPECT_EQ(b->drb_id, 2);
    EXPECT_EQ(to_hex(b->pdu), "45");
    auto c = s.map_ul(7, h("45"));   // unmapped: the default DRB
    ASSERT_TRUE(c);
    EXPECT_EQ(c->drb_id, 1);
    EXPECT_EQ(to_hex(c->pdu), "8745");
    s.release(1);
    EXPECT_FALSE(s.map_ul(7, h("45")));   // no default DRB left: discarded
    auto d = s.on_dl(2, h("45"));
    ASSERT_TRUE(d);
    EXPECT_FALSE(d->header);
    EXPECT_FALSE(s.on_dl(1, h("45")));   // released
}

TEST(Sdap, TheDownlinkHeaderIsReadAndStripped) {
    Sdap s(1);
    s.configure(SdapDrb{1, false, true, true, {}, {}});
    auto d = s.on_dl(1, h("4945"));
    ASSERT_TRUE(d);
    ASSERT_TRUE(d->header);
    EXPECT_TRUE(d->header->rqi);
    EXPECT_EQ(d->header->qfi, 9);
    EXPECT_EQ(to_hex(d->sdu), "45");
    EXPECT_FALSE(s.on_dl(1, {}));
}

} // namespace
} // namespace ksim::entity
