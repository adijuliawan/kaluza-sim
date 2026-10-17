// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// What the fault verbs do to the procedures, in virtual time (P3 R3; KS-L2R-001, KS-L2R-005;
// net_rig.hpp): du cell off takes the cell off the air, the DU asks for its UEs' release, and
// the UEs lose the cell; du cell on brings it back and they camp again; the DU's RLC giving up
// on a UE is a radio link failure it reports; ue rlf makes the UE lose the link at once, and
// the DU finds out by not hearing it.

#include <gtest/gtest.h>

#include <string>

#include "net_rig.hpp"

namespace ksim::proctest {
namespace {

std::string field(const Event& e, const char* k) {
    const std::string* v = e.find(k);
    return v != nullptr ? *v : std::string("<none>");
}

std::string cm_state(const node::UeDevice& ue) {
    for (const auto& [k, v] : ue.status()) {
        if (k == "CM_STATE") {
            return v;
        }
    }
    return "<none>";
}

TEST(Faults, Ts38473_8_3_2_ACellOffTheAirReleasesItsUesAndTheyCampAgainWhenItIsBack) {
    Net n;
    n.register_ue();
    const auto requests = n.amf.count("UEContextReleaseRequest");
    n.du.cell_power(false);
    const Event* off = n.last("ran.du.cell_off");
    ASSERT_NE(off, nullptr);
    EXPECT_EQ(field(*off, "released"), "1");
    ASSERT_TRUE(n.loop.run_until([&] { return n.amf.count("UEContextReleaseComplete") == 1; }, n.loop.now() + 2'000));
    EXPECT_EQ(n.amf.count("UEContextReleaseRequest"), requests + 1);
    // The UE hears nothing: the RRCRelease never reaches it, its downlink goes (TS 38.331
    // §5.3.10), and in RRC_IDLE the cell it camped on is lost (TS 38.304 §5.2.3).
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("rrc.cell_lost").empty(); }, n.loop.now() + 5'000));
    ASSERT_NE(n.last("rrc.connection_lost"), nullptr);
    EXPECT_EQ(field(*n.last("rrc.connection_lost"), "reason"), "radio link failure");
    EXPECT_EQ(cm_state(*n.ue), "CM-IDLE");
    EXPECT_EQ(n.named("rrc.camped").size(), 1u);
    n.du.cell_power(true);
    ASSERT_TRUE(n.loop.run_until([&] { return n.named("rrc.camped").size() == 2; }, n.loop.now() + 1'000));
    EXPECT_NE(n.last("ran.du.cell_on"), nullptr);
    EXPECT_EQ(n.failures(), "");
}

TEST(Faults, Ts38322_5_3_2_TheDusRlcGivingUpOnAUeIsAReportedRadioLinkFailure) {
    Net n;
    n.register_ue();
    const Event* up = n.last("ran.ue.connected");
    ASSERT_NE(up, nullptr);
    const auto rnti = static_cast<std::uint16_t>(std::stoul(field(*up, "c_rnti")));
    const auto requests = n.amf.count("UEContextReleaseRequest");
    n.du.radio_link_failure(rnti, "rlc max retransmissions");
    n.du.radio_link_failure(rnti, "rlc max retransmissions");   // once
    ASSERT_TRUE(n.loop.run_until([&] { return n.amf.count("UEContextReleaseRequest") > requests; }, n.loop.now() + 500));
    const Event* rlf = n.last("ran.du.rlf");
    ASSERT_NE(rlf, nullptr);
    EXPECT_EQ(field(*rlf, "reason"), "rlc max retransmissions");
    EXPECT_EQ(n.named("ran.du.rlf").size(), 1u);
    n.loop.run_until([] { return false; }, n.loop.now() + 500);
    EXPECT_EQ(n.amf.count("UEContextReleaseRequest"), requests + 1);
}

TEST(Faults, Ts38331_5_3_10_3_UeRlfLosesTheLinkAtOnceAndNasRecoversTheConnection) {
    Net n;
    n.register_ue();
    const auto initial = n.amf.count("InitialUEMessage");
    ASSERT_TRUE(n.ue->radio_link_failure());
    n.loop.run_until([] { return false; }, n.loop.now() + 1);
    ASSERT_NE(n.last("rrc.connection_lost"), nullptr);
    EXPECT_EQ(field(*n.last("rrc.connection_lost"), "reason"), "radio link failure");
    // TS 24.501 §5.5.1.3.2 f: the RRC connection failure makes the UE recover its NAS signalling
    // connection with a mobility registration; the AMF releases the gNB's old context for it.
    ASSERT_TRUE(n.loop.run_until([&] { return n.named("nas.reg.complete").size() == 2; }, n.loop.now() + 5'000))
        << n.failures();
    EXPECT_EQ(field(n.named("nas.reg.request").back(), "type"), "mobility");
    EXPECT_EQ(n.amf.count("InitialUEMessage"), initial + 1);
    ASSERT_TRUE(n.loop.run_until([&] { return n.amf.count("UEContextReleaseComplete") == 1; }, n.loop.now() + 2'000));
    EXPECT_EQ(n.cucp.ues(), 1u);
    EXPECT_TRUE(n.named("rrc.cell_lost").empty());   // the cell is still heard
    EXPECT_EQ(n.failures(), "");
}

TEST(Faults, Ts38473_8_3_2_AUeTheDuNoLongerHearsIsReportedLost) {
    Net n;
    n.register_ue();
    // A sudden loss with no recovery: the UE's radio goes quiet (a battery pull, KS-L2R-005).
    ASSERT_TRUE(n.ue->power_off_abrupt());
    EXPECT_FALSE(n.ue->radio_link_failure());   // in RRC_IDLE there is no link to lose
    ASSERT_TRUE(n.loop.run_until([&] { return n.amf.count("UEContextReleaseComplete") == 1; }, n.loop.now() + 3'000));
    const Event* rlf = n.last("ran.du.rlf");
    ASSERT_NE(rlf, nullptr);
    EXPECT_EQ(field(*rlf, "reason"), "no uplink");
    EXPECT_EQ(n.failures(), "");
}

} // namespace
} // namespace ksim::proctest
