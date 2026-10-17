// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Several cells and gNBs in virtual time (P3 R2; net2_rig.hpp): UEs camp on the
// strongest cell they hear and register through it with its TAI and cell in the
// user location; two DUs under one CU-CP keep their UEs apart, and one DU's F1
// going takes only its UEs; two gNBs share the stub's AMF; a DU with a new TAC
// after NG Setup makes the gNB send RAN CONFIGURATION UPDATE; paging for a TA
// reaches the cells of that TA only.

#include <gtest/gtest.h>

#include <string>

#include "net2_rig.hpp"

namespace ksim::proctest {
namespace {

const char* kSupi1 = "001010000300011";
const char* kSupi2 = "001010000300012";
const char* kSupi3 = "001010000300013";

std::string field(const Event& e, const char* k) {
    const std::string* v = e.find(k);
    return v != nullptr ? *v : std::string("<none>");
}

const Event* camped(const Net2& n, const std::string& supi) {
    static thread_local std::vector<Event> keep;
    keep = n.named("rrc.camped", "ue:imsi-" + supi);
    return keep.empty() ? nullptr : &keep.back();
}

bool registered(Net2& n, const std::string& supi) {
    return !n.named("nas.reg.complete", "ue:imsi-" + supi).empty();
}

TEST(Net2, Ts38304_5_2_3_EachUeCampsOnTheStrongestCellItHearsAndRegistersThroughIt) {
    Net2 n;
    n.add_ue(kSupi1, 11, kCellA1);
    n.add_ue(kSupi2, 12, kCellA2);
    n.add_ue(kSupi3, 13, kCellB1);
    n.start();
    for (auto& [id, ue] : n.ues) {
        ASSERT_TRUE(ue->power_on());
    }
    ASSERT_TRUE(n.loop.run_until([&] { return registered(n, kSupi1) && registered(n, kSupi2) && registered(n, kSupi3); },
                                 n.loop.now() + 20'000))
        << n.failures();
    EXPECT_EQ(field(*camped(n, kSupi1), "cell"), std::to_string(kCellA1));
    EXPECT_EQ(field(*camped(n, kSupi2), "cell"), std::to_string(kCellA2));
    EXPECT_EQ(field(*camped(n, kSupi3), "cell"), std::to_string(kCellB1));
    EXPECT_EQ(field(*camped(n, kSupi1), "rsrp"), "-60");
    EXPECT_EQ(n.a->cucp->dus(), 2u);
    EXPECT_EQ(n.a->cucp->ues(), 2u);
    EXPECT_EQ(n.b->cucp->ues(), 1u);
    EXPECT_EQ(n.amf.gnbs(), 2u);
    EXPECT_EQ(n.amf.count("InitialUEMessage"), 3u);
    EXPECT_EQ(n.failures(), "");   // the user location's TAI and cell are each UE's (TS 38.413 9.2.5.1)
}

TEST(Net2, Ts38304_5_2_2_AConnectedUeStaysOnItsCellWhenAnotherCellsSib1Comes) {
    Net2 n;
    auto& ue = n.add_ue(kSupi1, 11, kCellA1);
    n.start();
    ASSERT_TRUE(ue.power_on());
    ASSERT_TRUE(n.loop.run_until([&] { return registered(n, kSupi1); }, n.loop.now() + 15'000)) << n.failures();
    // Cell A2 becomes the stronger one while the UE is connected: no re-camping (no handover yet).
    n.view.set_ue_cell(11, kCellA2, -50);
    n.loop.run_until([] { return false; }, n.loop.now() + 1'000);
    EXPECT_EQ(n.named("rrc.camped", "ue:imsi-" + std::string(kSupi1)).size(), 1u);
    EXPECT_EQ(field(*camped(n, kSupi1), "cell"), std::to_string(kCellA1));
}

TEST(Net2, Ts38413_8_3_2_OneDusF1GoingReleasesOnlyItsUes) {
    Net2 n;
    n.add_ue(kSupi1, 11, kCellA1);
    n.add_ue(kSupi2, 12, kCellA2);
    n.start();
    for (auto& [id, ue] : n.ues) {
        ASSERT_TRUE(ue->power_on());
    }
    ASSERT_TRUE(n.loop.run_until([&] { return registered(n, kSupi1) && registered(n, kSupi2); }, n.loop.now() + 20'000));
    ASSERT_TRUE(n.loop.run_until([&] { return n.amf.count("InitialContextSetupResponse") == 2; }, n.loop.now() + 2'000));
    const auto requests = n.amf.count("UEContextReleaseRequest");
    n.a->f1s[1]->a().abort();   // cell A2's DU loses F1
    ASSERT_TRUE(n.loop.run_until([&] { return n.amf.count("UEContextReleaseRequest") > requests; }, n.loop.now() + 2'000));
    n.loop.run_until([] { return false; }, n.loop.now() + 500);
    EXPECT_EQ(n.amf.count("UEContextReleaseRequest"), requests + 1);
    EXPECT_EQ(n.a->cucp->dus(), 1u);
    const auto lost = n.named("ran.f1.lost", "gnb:cucp1");
    ASSERT_EQ(lost.size(), 1u);
    EXPECT_EQ(field(lost[0], "ues"), "1");
}

TEST(Net2, Ts38413_8_7_2_ADuWithANewTacAfterNgSetupMakesTheGnbUpdateItsTas) {
    Net2 n({}, /*tac_a2=*/7);
    // DU A2 joins after NG Setup: the first association up is DU A1's alone.
    n.a->f1s[0]->connect();
    n.a->e1.connect();
    n.b->f1s[0]->connect();
    n.b->e1.connect();
    n.ng_a.connect();
    n.ng_b.connect();
    ASSERT_TRUE(n.loop.run_until([&] { return n.a->cucp->ng_ready(); }, n.loop.now() + 2'000));
    EXPECT_EQ(n.amf.gnb_tacs(0x1A0), std::vector<std::uint32_t>{1});
    n.a->f1s[1]->connect();
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("ran.ng.config_update.ack").empty(); }, n.loop.now() + 2'000));
    EXPECT_EQ(field(n.named("ran.ng.config_update.ack")[0], "result"), "ack");
    EXPECT_EQ(n.amf.gnb_tacs(0x1A0), (std::vector<std::uint32_t>{1, 7}));
    EXPECT_EQ(n.amf.count("RANConfigurationUpdate"), 1u);
    EXPECT_EQ(n.failures(), "");
}

TEST(Net2, Ts38413_8_7_1_TwoDusComingTogetherMakeOneNgSetupAndAnUpdateForTheLaterTac) {
    // P3 R4: NG-C up first, then both DUs' F1 Setups while the NG SETUP is out: one NG SETUP,
    // and the TAC it missed in the RAN CONFIGURATION UPDATE after its response.
    Net2 n({}, /*tac_a2=*/7);
    n.ng_a.connect();
    n.ng_b.connect();
    n.b->f1s[0]->connect();
    n.b->e1.connect();
    n.a->e1.connect();
    n.loop.run_until([] { return false; }, n.loop.now() + 1);
    n.a->f1s[0]->connect();
    n.a->f1s[1]->connect();
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("ran.ng.config_update.ack").empty(); }, n.loop.now() + 2'000));
    n.loop.run_until([] { return false; }, n.loop.now() + 200);
    EXPECT_EQ(n.named("ran.ng.setup", "gnb:cucp1").size(), 1u);
    EXPECT_EQ(n.amf.gnb_tacs(0x1A0), (std::vector<std::uint32_t>{1, 7}));
    EXPECT_EQ(n.failures(), "");
}

TEST(Net2, Ts38413_8_5_1_PagingForATaReachesTheCellsOfThatTaOnly) {
    Net2 n({}, /*tac_a2=*/7);
    n.start();
    // A PAGING for TA 7 on gNB A's NG-C: its CU-CP pages on DU A2 (TAC 7) and not on DU A1 (TAC 1).
    ngap::Paging p;
    p.s_tmsi = ngap::FiveGSTmsi::of(0x0CA040000001ULL);
    p.tais = {ngap::Tai{ngap::plmn_id("001", "01"), 7}};
    auto wire = ngap::encode(p);
    ASSERT_TRUE(wire);
    ASSERT_TRUE(n.ng_a.b().send(*wire, SctpMeta{60, 0}));
    n.loop.run_until([] { return false; }, n.loop.now() + 300);
    EXPECT_EQ(n.named("ran.du.paging", "gnb:du1").size(), 0u);
    EXPECT_EQ(n.named("ran.du.paging", "gnb:du2").size(), 1u);
    EXPECT_EQ(n.named("ran.du.paging", "gnb:du3").size(), 0u);   // gNB B was not asked
}

TEST(Net2, Mutant_f1_loss_releases_all_ReleasesTheOtherDusUesToo) {
    if (!kMutationsBuild) {
        GTEST_SKIP() << "mutant build only";
    }
    testing::MutantScope m("f1_loss_releases_all");
    Net2 n;
    n.add_ue(kSupi1, 11, kCellA1);
    n.add_ue(kSupi2, 12, kCellA2);
    n.start();
    for (auto& [id, ue] : n.ues) {
        ASSERT_TRUE(ue->power_on());
    }
    ASSERT_TRUE(n.loop.run_until([&] { return registered(n, kSupi1) && registered(n, kSupi2); }, n.loop.now() + 20'000));
    ASSERT_TRUE(n.loop.run_until([&] { return n.amf.count("InitialContextSetupResponse") == 2; }, n.loop.now() + 2'000));
    const auto requests = n.amf.count("UEContextReleaseRequest");
    n.a->f1s[1]->a().abort();
    n.loop.run_until([] { return false; }, n.loop.now() + 1'000);
    EXPECT_EQ(n.amf.count("UEContextReleaseRequest"), requests + 2);
}

TEST(Net2, Mutant_camp_last_sib1_TheUeCampsOnWhicheverCellItReadLast) {
    if (!kMutationsBuild) {
        GTEST_SKIP() << "mutant build only";
    }
    testing::MutantScope m("camp_last_sib1");
    Net2 n;
    n.add_ue(kSupi1, 11, kCellA1);
    n.start();
    n.loop.run_until([] { return false; }, n.loop.now() + 2'000);
    // An idle UE hearing three cells re-camps on each SIB1: dozens of camps, not one.
    EXPECT_GT(n.named("rrc.camped", "ue:imsi-" + std::string(kSupi1)).size(), 3u);
}

TEST(Net2, Ts38304_5_2_3_AnIdleUeHearingThreeCellsCampsOnceOnTheStrongest) {
    Net2 n;
    n.add_ue(kSupi1, 11, kCellA2);
    n.start();
    n.loop.run_until([] { return false; }, n.loop.now() + 2'000);
    const auto camps = n.named("rrc.camped", "ue:imsi-" + std::string(kSupi1));
    ASSERT_FALSE(camps.empty());
    EXPECT_LE(camps.size(), 2u);   // a weaker cell's SIB1 may come first; then the strongest's
    EXPECT_EQ(field(camps.back(), "cell"), std::to_string(kCellA2));
}

} // namespace
} // namespace ksim::proctest
