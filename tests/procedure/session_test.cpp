// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// PDU sessions end to end in virtual time (P1 N10): a UE device (5GMM, 5GSM,
// RRC and its soft card) over KAIR to the DU; F1-C and E1 over memlink as
// encoded F1AP and E1AP; F1-U and N3 as GTP-U datagrams over a MemNet; NG-C
// to the core stub's AMF, its SMF and its UPF with the DN reflector. A ping
// from the UE crosses SDAP, PDCP with 128-NEA2 on the DRB, F1-U with NR-U, the
// CU-UP, N3 with the PDU Session Container, and comes back.

#include <gtest/gtest.h>

#include <map>
#include <memory>
#include <string>

#include "net_rig.hpp"

namespace ksim::proctest {
namespace {

TEST(Session, E1_8_2_1_TheCuUpSetsUpE1WithTheCuCp) {
    Net n;
    n.start();
    EXPECT_EQ(n.named("ran.e1.setup").size(), 2u);   // the CU-CP's and the CU-UP's
}

// P2 Q2: E1 lost under a UE with a session. The CU-CP asks for the UE's release, since its user plane went
// with the bearer context (TS 38.413 §8.3.2); E1 back, the CU-UP sets E1 up again.
TEST(Session, AnE1LossReleasesTheUesWithSessionsAndE1ComesBack) {
    Net n;
    n.register_ue();
    n.establish();
    n.e1.a().abort();   // the CU-UP's end goes (a CU-UP restart, as the CU-CP sees it)
    ASSERT_TRUE(n.loop.run_until([&] { return n.amf.count("UEContextReleaseRequest") == 1; }, n.loop.now() + 2'000))
        << n.failures();
    const Event* r = n.last("ran.ue.release_request");
    ASSERT_NE(r, nullptr);
    EXPECT_EQ(*r->find("cause"), "release-due-to-ngran-generated-reason");
    EXPECT_FALSE(n.named("ran.e1.lost").empty());
    n.e1.connect();
    // The CU-CP's and the CU-UP's ran.e1.setup, twice.
    ASSERT_TRUE(n.loop.run_until([&] { return n.cucp.e1_ready() && n.named("ran.e1.setup").size() == 4; },
                                 n.loop.now() + 2'000));
}

TEST(Session, Ts24501_6_4_1_AnIpv4SessionIsEstablishedWithAddressDnsAndMtu) {
    Net n;
    n.register_ue();
    n.establish();
    const Event* a = n.last("nas.sm.est.accept");
    ASSERT_NE(a, nullptr);
    EXPECT_EQ(*a->find("psi"), "1");
    EXPECT_EQ(*a->find("ip"), "10.60.0.2");
    EXPECT_EQ(*a->find("dns"), "10.60.0.1");
    EXPECT_EQ(*a->find("mtu"), "1400");
    EXPECT_EQ(*a->find("qfi"), "1");
    EXPECT_EQ(*a->find("dnn"), "internet");
    const auto list = n.ue->sessions();
    ASSERT_EQ(list.size(), 1u);
    EXPECT_EQ(list[0].state, proc::ue::SmState::active);
    EXPECT_EQ(n.cucp.sessions_of(n.amf.ids(0)->ran), std::vector<std::uint8_t>{1});
    EXPECT_EQ(n.cuup.stats().contexts_setup, 1u);
    EXPECT_EQ(n.failures(), "");
    EXPECT_TRUE(n.named("core.anomaly").empty());
}

TEST(Session, APingCrossesTheWholeUserPlaneWithNea2OnTheDrb) {
    Net n;
    n.register_ue();
    n.establish();
    node::PingRequest p;
    p.dst = {10, 60, 0, 1};
    p.count = 3;
    p.interval = 200;
    ASSERT_TRUE(n.ue->ping(p));
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("ue.ping.done").empty(); }, n.loop.now() + 5'000));
    const Event* d = n.last("ue.ping.done");
    EXPECT_EQ(*d->find("sent"), "3");
    EXPECT_EQ(*d->find("received"), "3");
    EXPECT_EQ(*d->find("loss_pct"), "0");
    EXPECT_EQ(n.named("ue.ping.reply").size(), 3u);
    ASSERT_NE(n.amf.upf(), nullptr);
    EXPECT_EQ(n.amf.upf()->stats().echo_replies, 3u);
    EXPECT_EQ(n.cuup.stats().ul_packets, 3u);
    EXPECT_EQ(n.cuup.stats().dl_packets, 3u);
    EXPECT_EQ(n.du.stats().ul_user, 3u);
    EXPECT_EQ(n.du.stats().dl_user, 3u);
    // The DRB was set up with the UP keys: 128-NEA2, no integrity (the policy said "not-needed").
    const auto setup = n.named("ran.session.setup");
    ASSERT_EQ(setup.size(), 1u);
    EXPECT_EQ(*setup[0].find("integrity"), "0");
    EXPECT_EQ(n.failures(), "");
}

// P2 Q8: with the CU-CP preferring 128-NEA1/NIA1 (SNOW 3G), the AS SECURITY MODE COMMAND
// selects them and the user plane runs on NEA1; the CU-CP's t-Reordering reaches the
// CU-UP's entity through E1 (TS 37.483 9.3.1.38) as the UE gets it in RRC.
TEST(Session, Ts33501_6_7_3_Nea1AndNia1FirstCarryTheWholeUserPlane) {
    const ScopedCuCp tweak([](proc::ran::CuCpConfig& c) {
        c.nea_preference = {1, 2};
        c.nia_preference = {1, 2};
        c.t_reordering_ms = 100;
    });
    Net n;
    n.register_ue();
    n.establish();
    const Event* smc = n.last("ran.as.smc");
    ASSERT_NE(smc, nullptr);
    EXPECT_EQ(*smc->find("alg"), "nia1/nea1");
    const Event* bearer = n.last("ran.cuup.bearer.setup");
    ASSERT_NE(bearer, nullptr);
    EXPECT_EQ(*bearer->find("t_reordering"), "100");
    node::PingRequest p;
    p.dst = {10, 60, 0, 1};
    p.count = 3;
    p.interval = 200;
    ASSERT_TRUE(n.ue->ping(p));
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("ue.ping.done").empty(); }, n.loop.now() + 5'000));
    EXPECT_EQ(*n.last("ue.ping.done")->find("received"), "3");
    EXPECT_TRUE(n.named("rrc.integrity_failure").empty());
    EXPECT_TRUE(n.named("ran.rrc.integrity_failure").empty());
    EXPECT_EQ(n.failures(), "");
}

// ---- P2 Q9: the UP security policy (TS 38.413 8.2.1.2, TS 33.501 6.6.1) ---------------

namespace {
bool ping3(Net& n) {
    node::PingRequest p;
    p.dst = {10, 60, 0, 1};
    p.count = 3;
    p.interval = 200;
    const auto before = n.named("ue.ping.done").size();
    if (!n.ue->ping(p) ||
        !n.loop.run_until([&] { return n.named("ue.ping.done").size() > before; }, n.loop.now() + 5'000)) {
        return false;
    }
    return *n.last("ue.ping.done")->find("received") == "3";
}
} // namespace

TEST(Session, Ts38413_8_2_1_2_RequiredUpIntegrityRunsTheDrbWithAMacI) {
    corestub::Profile p;
    p.session.up_integrity = "required";
    Net n(p);
    n.register_ue();
    n.establish();
    EXPECT_EQ(*n.last("ran.up.security")->find("integrity"), "1");
    EXPECT_EQ(*n.last("ran.session.setup")->find("integrity"), "1");
    EXPECT_EQ(*n.last("ran.cuup.bearer.setup")->find("integrity"), "1");
    EXPECT_TRUE(ping3(n));   // a MAC-I both ways, or the pings would not verify
    EXPECT_EQ(n.failures(), "");
}

TEST(Session, Ts38413_8_2_1_2_PreferredFollowsTheCuCpsPolicy) {
    const ScopedCuCp tweak([](proc::ran::CuCpConfig& c) { c.up_policy.preferred_integrity = false; });
    corestub::Profile p;
    p.session.up_integrity = "preferred";
    Net n(p);
    n.register_ue();
    n.establish();
    const Event* e = n.last("ran.up.security");
    EXPECT_EQ(*e->find("asked"), "preferred/required");
    EXPECT_EQ(*e->find("integrity"), "0");
    EXPECT_TRUE(ping3(n));
    EXPECT_EQ(n.failures(), "");
}

TEST(Session, Ts38331_CipheringDisabledWhenConfidentialityIsNotNeeded) {
    corestub::Profile p;
    p.session.up_confidentiality = "not-needed";
    Net n(p);
    n.register_ue();
    n.establish();
    EXPECT_EQ(*n.last("ran.up.security")->find("confidentiality"), "0");
    EXPECT_EQ(*n.last("ran.cuup.bearer.setup")->find("ciphering"), "0");
    EXPECT_TRUE(ping3(n));   // the UE unciphered too (cipheringDisabled), or nothing would pass
    EXPECT_EQ(n.failures(), "");
}

TEST(Session, Ts38413_8_2_1_2_RequiredIntegrityTheGnbCannotDoIsRefused) {
    const ScopedCuCp tweak([](proc::ran::CuCpConfig& c) { c.up_policy.integrity_possible = false; });
    corestub::Profile p;
    p.session.up_integrity = "required";
    Net n(p);
    n.register_ue();
    ASSERT_TRUE(n.ue->ps_establish(proc::ue::SessionRequest{0, "internet", std::nullopt}));
    ASSERT_TRUE(n.loop.run_until([&] { return n.amf.count("PDUSessionResourceSetupResponse") > 0; }, n.loop.now() + 5'000));
    const Event* e = n.last("ran.up.security");
    ASSERT_NE(e, nullptr);
    EXPECT_EQ(*e->find("result"), "up-integrity-protection-not-possible");
    EXPECT_TRUE(n.named("ran.session.setup").empty());
    EXPECT_EQ(n.amf.smf().sessions(), 0u);
    EXPECT_EQ(n.failures(), "");   // the stub takes the refusal (KS-NGAP-B8)
}

TEST(Session, Ts33501_6_6_1_NoSecurityIndicationRunsOnTheCuCpsDefault) {
    corestub::Profile p;
    p.session.up_integrity = "absent";
    Net n(p);
    n.register_ue();
    n.establish();
    const Event* e = n.last("ran.up.security");
    ASSERT_NE(e, nullptr);
    EXPECT_EQ(*e->find("indication"), "absent");
    EXPECT_EQ(*e->find("integrity"), "0");
    EXPECT_EQ(*e->find("confidentiality"), "1");
    EXPECT_TRUE(ping3(n));
    EXPECT_EQ(n.failures(), "");
}

// P2 Q4 (TS 38.425 5.4.2.1): the DU sends the initial DL DATA DELIVERY STATUS once the
// DRB is up, and after DL data reports the highest PDCP SN sent to the UE, which RLC
// AM over the ideal link delivered in sequence. The CU-UP takes it as feedback, not data.
TEST(Session, Ts38425_5_4_2_1_TheDuReportsDownlinkDeliveryStatus) {
    Net n;
    n.register_ue();
    n.establish();
    n.loop.run_for(50);
    ASSERT_GE(n.cuup.stats().ddds_rx, 1u);
    ASSERT_TRUE(n.cuup.last_ddds());
    EXPECT_EQ(n.cuup.last_ddds()->desired_buffer, 8U << 20);
    EXPECT_FALSE(n.cuup.last_ddds()->highest_delivered);   // nothing sent yet
    node::PingRequest p;
    p.dst = {10, 60, 0, 1};
    p.count = 3;
    p.interval = 200;
    ASSERT_TRUE(n.ue->ping(p));
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("ue.ping.done").empty(); }, n.loop.now() + 5'000));
    n.loop.run_for(50);
    ASSERT_TRUE(n.cuup.last_ddds());
    EXPECT_EQ(n.cuup.last_ddds()->highest_delivered, std::optional<std::uint32_t>(2));   // SNs 0, 1, 2
    EXPECT_EQ(n.cuup.last_ddds()->highest_transmitted, std::optional<std::uint32_t>(2));
    EXPECT_GE(n.du.stats().ddds_tx, 2u);
    EXPECT_EQ(n.cuup.stats().ddds_rx, n.du.stats().ddds_tx);
    EXPECT_EQ(n.cuup.stats().ul_packets, 3u);   // the reports were not taken for user data
    EXPECT_EQ(n.failures(), "");
}

// P2 Q5 (TS 37.483 8.6.3; row ksim-p2.e1-inactivity): with no user data for the UE Inactivity
// Timer the CU-UP reports the UE not active, and the CU-CP asks the AMF to release it with
// user-inactivity; the UE ends in CM-IDLE with its session kept. Data before the timer runs
// out keeps it connected.
TEST(Session, Ts37483_8_6_3_TheCuUpsInactivityReportReleasesTheUe) {
    const ScopedInactivity five(5);
    Net n;
    n.register_ue();
    n.establish();
    node::PingRequest p;
    p.dst = {10, 60, 0, 1};
    p.count = 3;
    p.interval = 2'000;
    ASSERT_TRUE(n.ue->ping(p));
    n.loop.run_for(4'500);   // pings every 2 s: active all along
    EXPECT_EQ(n.cuup.stats().inactivity_reports, 0u);
    ASSERT_TRUE(n.loop.run_until([&] { return n.cuup.stats().inactivity_reports == 1; }, n.loop.now() + 8'000));
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("nas.mm.cm_idle").empty(); }, n.loop.now() + 2'000));
    EXPECT_EQ(n.amf.count("UEContextReleaseRequest"), 1u);
    const auto req = n.named("ran.ue.release_request");
    ASSERT_FALSE(req.empty());
    EXPECT_EQ(*req.back().find("cause"), "user-inactivity");
    const auto at_cucp = n.named("ran.e1.inactivity");
    ASSERT_EQ(at_cucp.size(), 2u);   // the CU-UP's report and the CU-CP's taking it
    EXPECT_EQ(n.failures(), "");
}

TEST(Session, ADnPingToTheUeIsAnswered) {
    Net n;
    n.register_ue();
    n.establish();
    ASSERT_TRUE(n.amf.smf().ping_ue(kSupi, 1, 1));
    ASSERT_TRUE(n.loop.run_until([&] { return n.amf.upf()->stats().echo_from_ue == 1; }, n.loop.now() + 1'000));
    EXPECT_EQ(n.named("ue.ping.answered").size(), 1u);
    EXPECT_EQ(n.failures(), "");
}

TEST(Session, Ts24501_6_4_3_TheUeReleasesItsSession) {
    Net n;
    n.register_ue();
    n.establish();
    ASSERT_TRUE(n.ue->ps_release(1));
    ASSERT_TRUE(n.loop.run_until([&] { return n.amf.count("PDUSessionResourceReleaseResponse") == 1 && n.amf.smf().sessions() == 0; },
                                 n.loop.now() + 5'000)) << n.failures();
    const Event* c = n.last("nas.sm.rel.command");
    ASSERT_NE(c, nullptr);
    EXPECT_EQ(*c->find("network"), "0");
    EXPECT_TRUE(n.ue->sessions().empty());
    EXPECT_TRUE(n.cucp.sessions_of(n.amf.ids(0)->ran).empty());
    EXPECT_EQ(n.named("ran.cuup.bearer.release").size(), 1u);   // the last session: the bearer context went
    EXPECT_EQ(n.failures(), "");
}

TEST(Session, Ts24501_6_3_3_TheNetworkReleasesASession) {
    Net n;
    n.register_ue();
    n.establish();
    ASSERT_TRUE(n.amf.nas()->release_session(1, 36));
    ASSERT_TRUE(n.loop.run_until([&] { return n.amf.count("PDUSessionResourceReleaseResponse") == 1 && n.amf.smf().sessions() == 0; },
                                 n.loop.now() + 5'000)) << n.failures();
    const Event* c = n.last("nas.sm.rel.command");
    ASSERT_NE(c, nullptr);
    EXPECT_EQ(*c->find("network"), "1");
    EXPECT_EQ(*c->find("cause"), "36");
    EXPECT_TRUE(n.ue->sessions().empty());
    EXPECT_EQ(n.failures(), "");
}

TEST(Session, TwoSessionsGetTwoDrbsAndBothCarryPings) {
    Net n;
    n.register_ue();
    n.establish("internet");
    n.establish("ims");
    const auto list = n.ue->sessions();
    ASSERT_EQ(list.size(), 2u);
    EXPECT_EQ(list[0].dnn, "internet");
    EXPECT_EQ(list[1].dnn, "ims");
    EXPECT_EQ(n.cucp.sessions_of(n.amf.ids(0)->ran).size(), 2u);
    for (std::uint8_t psi : {std::uint8_t{1}, std::uint8_t{2}}) {
        const auto done = n.named("ue.ping.done").size();
        node::PingRequest p;
        p.psi = psi;
        p.dst = {10, 60, 0, 1};
        p.count = 2;
        p.interval = 100;
        ASSERT_TRUE(n.ue->ping(p));
        ASSERT_TRUE(n.loop.run_until([&] { return n.named("ue.ping.done").size() > done; }, n.loop.now() + 5'000));
        EXPECT_EQ(*n.last("ue.ping.done")->find("received"), "2") << int{psi};
    }
    EXPECT_EQ(n.failures(), "");
}

TEST(Session, Ts24501_6_4_1_4_3_AfterA29WithABackOffTheUeWaitsItOut) {
    corestub::Profile p;
    p.session.establishment = corestub::SessionProfile::Establishment::reject;
    p.session.reject_cause = 29;
    p.session.backoff_s = 60;
    p.session.rejects = 1;
    Net n(p);
    n.register_ue();
    const proc::ue::SessionRequest req{0, "internet", nas::ie::Snssai{1, std::nullopt, std::nullopt, std::nullopt}};
    ASSERT_TRUE(n.ue->ps_establish(req));
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("nas.sm.est.reject").empty(); }, n.loop.now() + 5'000));
    const Event* b = n.last("nas.sm.backoff");
    ASSERT_NE(b, nullptr);
    EXPECT_EQ(*b->find("seconds"), "60");
    EXPECT_EQ(*b->find("cause"), "29");
    // Asked again at once: refused locally, nothing sent.
    EXPECT_FALSE(n.ue->ps_establish(req));
    n.loop.run_until([] { return false; }, n.loop.now() + 1'000);
    EXPECT_EQ(n.amf.smf().requests(), 1);
    EXPECT_EQ(n.named("nas.sm.backoff.blocked").size(), 1u);
    // After the timer: the request goes and is accepted.
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("nas.sm.backoff.expiry").empty(); }, n.loop.now() + 61'000));
    ASSERT_TRUE(n.ue->ps_establish(req));
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("nas.sm.est.accept").empty(); }, n.loop.now() + 5'000));
    EXPECT_EQ(n.amf.smf().requests(), 2);
    EXPECT_EQ(n.failures(), "");
}

TEST(Session, Ts24501_6_4_1_3_AnAcceptWithoutADefaultQosRuleIsReleasedWith83) {
    corestub::Profile p;
    p.session.default_rule = false;
    Net n(p);
    n.register_ue();
    ASSERT_TRUE(n.ue->ps_establish(proc::ue::SessionRequest{0, "internet", std::nullopt}));
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("core.anomaly").empty(); }, n.loop.now() + 5'000));
    ASSERT_TRUE(n.loop.run_until([&] { return n.amf.smf().sessions() == 0; }, n.loop.now() + 5'000));
    EXPECT_EQ(*n.last("nas.sm.rel.command")->find("network"), "0");
}

TEST(Session, Ts24501_6_4_1_6_T3580RetransmitsFourTimesThenAborts) {
    corestub::Profile p;
    p.session.establishment = corestub::SessionProfile::Establishment::silent;
    Net n(p);
    n.register_ue();
    ASSERT_TRUE(n.ue->ps_establish(proc::ue::SessionRequest{0, "internet", std::nullopt}));
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("nas.sm.est.abort").empty(); }, n.loop.now() + Millis{5 * 16'000 + 1'000}));
    EXPECT_EQ(n.named("nas.sm.timer.expiry").size(), 5u);
    EXPECT_EQ(n.amf.smf().requests(), 5);   // the request and four retransmissions
    EXPECT_TRUE(n.ue->sessions().empty());
}

TEST(Session, Ts24501_6_3_2_ANetworkModificationIsCompleted) {
    Net n;
    n.register_ue();
    n.establish();
    ASSERT_TRUE(n.amf.nas()->modify_session(1, 200));
    ASSERT_TRUE(n.loop.run_until([&] { return n.amf.smf().completes() == 1; }, n.loop.now() + 5'000));
    EXPECT_EQ(*n.last("nas.sm.mod.command")->find("ambr_dl"), "200000000");
    EXPECT_EQ(n.failures(), "");
}

// P2 Q10: a ping and its reply on PSI 1 to `dst`; true when it came back.
bool ping_once(Net& n, ip::Addr dst) {
    const auto done = n.named("ue.ping.done").size();
    node::PingRequest p;
    p.psi = 1;
    p.dst = dst;
    p.count = 2;
    p.interval = 100;
    if (!n.ue->ping(p)) {
        return false;
    }
    if (!n.loop.run_until([&] { return n.named("ue.ping.done").size() > done; }, n.loop.now() + 5'000)) {
        return false;
    }
    return *n.last("ue.ping.done")->find("received") == "2";
}

corestub::FlowSpec flow(std::uint8_t qfi, std::uint16_t five_qi, std::uint8_t precedence, const char* filter) {
    corestub::FlowSpec f;
    f.qfi = qfi;
    f.five_qi = five_qi;
    f.precedence = precedence;
    f.filter = filter;
    f.components = *corestub::parse_filter(filter);
    return f;
}

std::uint64_t ul_on(const Net& n, std::uint8_t qfi) {
    const auto& m = n.ue->ul_per_qfi();
    const auto it = m.find({1, qfi});
    return it == m.end() ? 0 : it->second;
}

// P2 Q10 (TS 23.501 5.7.1.5; TS 38.300 12): a second QoS flow of another 5QI gets a DRB of its
// own; the UE's classifier puts a ping to its address on it, the stub's UPF finds the same QFI.
TEST(Session, Ts23501_5_7_1_5_ASecondFlowGetsItsOwnDrbAndItsPackets) {
    corestub::Profile p;
    p.session.flows = {flow(2, 7, 10, "remote=10.60.0.9/32")};
    Net n(p);
    n.register_ue();
    n.establish();
    const auto drbs = n.cucp.drbs_of(n.amf.ids(0)->ran, 1);
    ASSERT_EQ(drbs.size(), 2u);
    EXPECT_TRUE(drbs[0].default_drb);
    EXPECT_EQ(drbs[0].qfis, std::vector<std::uint8_t>{1});
    EXPECT_EQ(drbs[1].qfis, std::vector<std::uint8_t>{2});
    EXPECT_EQ(drbs[1].five_qi, 7);
    ASSERT_TRUE(ping_once(n, {10, 60, 0, 9}));
    ASSERT_TRUE(ping_once(n, {10, 60, 0, 1}));
    EXPECT_EQ(ul_on(n, 2), 2u);
    EXPECT_EQ(ul_on(n, 1), 2u);
    EXPECT_EQ(n.amf.upf()->stats().ul_per_qfi.at(2), 2u);
    EXPECT_EQ(n.failures(), "");
}

// P2 Q10 (TS 38.413 8.2.3): a modification adds a flow on a new DRB through E1, F1 and the UE,
// and a second one releases it there again.
TEST(Session, Ts38413_8_2_3_AModifyAddsAFlowOnItsOwnDrbAndAnotherReleasesIt) {
    Net n;
    n.register_ue();
    n.establish();
    const std::uint32_t ran = n.amf.ids(0)->ran;
    ASSERT_TRUE(n.amf.nas()->qos_add(1, flow(4, 8, 5, "remote=10.60.0.7/32")));
    ASSERT_TRUE(n.loop.run_until([&] { return n.amf.count("PDUSessionResourceModifyResponse") == 1; }, n.loop.now() + 5'000))
        << n.failures();
    ASSERT_TRUE(n.loop.run_until([&] { return n.amf.smf().completes() == 1; }, n.loop.now() + 5'000));
    ASSERT_EQ(n.cucp.drbs_of(ran, 1).size(), 2u);
    EXPECT_FALSE(n.named("ran.cuup.drb.setup").empty());
    EXPECT_EQ(n.ue->sessions().at(0).rules.size(), 2u);
    EXPECT_EQ(n.ue->sessions().at(0).flow_5qi.at(4), 8);
    ASSERT_TRUE(ping_once(n, {10, 60, 0, 7}));
    EXPECT_EQ(ul_on(n, 4), 2u);
    ASSERT_TRUE(n.amf.nas()->qos_del(1, 4));
    ASSERT_TRUE(n.loop.run_until([&] { return n.amf.count("PDUSessionResourceModifyResponse") == 2; }, n.loop.now() + 5'000));
    ASSERT_TRUE(n.loop.run_until([&] { return n.amf.smf().completes() == 2; }, n.loop.now() + 5'000));
    EXPECT_EQ(n.cucp.drbs_of(ran, 1).size(), 1u);
    EXPECT_EQ(n.ue->sessions().at(0).rules.size(), 1u);
    EXPECT_EQ(*n.last("ran.session.modify")->find("drbs_removed"), "2");
    ASSERT_TRUE(ping_once(n, {10, 60, 0, 7}));   // now the default rule's
    EXPECT_EQ(ul_on(n, 1), 2u);
    EXPECT_EQ(n.failures(), "");
}

// P2 Q10 (TS 38.413 8.2.4; TS 23.502 4.3.3.2): a flow the gNB releases itself is told to the AMF
// in PDU SESSION RESOURCE NOTIFY, and the SMF has the UE delete its rule.
TEST(Session, Ts38413_8_2_4_TheGnbsOwnFlowReleaseIsNotifiedAndTheRuleGoes) {
    corestub::Profile p;
    p.session.flows = {flow(2, 7, 10, "remote=10.60.0.9/32")};
    Net n(p);
    n.register_ue();
    n.establish();
    const std::uint32_t ran = n.amf.ids(0)->ran;
    ASSERT_FALSE(n.cucp.release_flow(ran, 1, 9));   // no such flow
    ASSERT_TRUE(n.cucp.release_flow(ran, 1, 2));
    ASSERT_TRUE(n.loop.run_until([&] { return n.amf.notifies() == 1; }, n.loop.now() + 5'000)) << n.failures();
    ASSERT_TRUE(n.loop.run_until([&] { return n.amf.smf().completes() == 1; }, n.loop.now() + 5'000));
    EXPECT_EQ(n.cucp.drbs_of(ran, 1).size(), 1u);
    EXPECT_EQ(*n.last("ran.session.modify")->find("by"), "gnb");
    EXPECT_EQ(n.ue->sessions().at(0).rules.size(), 1u);
    EXPECT_EQ(n.amf.count("PDUSessionResourceModifyResponse"), 0);   // a notify, not a response
    ASSERT_TRUE(ping_once(n, {10, 60, 0, 9}));
    EXPECT_EQ(ul_on(n, 1), 2u);
    EXPECT_EQ(n.failures(), "");
}

// P2 Q10: cucp {drb_map: per-session} keeps every flow of a session on one DRB (P1's way).
TEST(Session, APerSessionMappingPutsBothFlowsOnOneDrb) {
    corestub::Profile p;
    p.session.flows = {flow(2, 7, 10, "remote=10.60.0.9/32")};
    const ScopedCuCp per_session([](proc::ran::CuCpConfig& c) { c.drb_map = proc::ran::DrbMap::per_session; });
    Net n(p);
    n.register_ue();
    n.establish();
    const auto drbs = n.cucp.drbs_of(n.amf.ids(0)->ran, 1);
    ASSERT_EQ(drbs.size(), 1u);
    EXPECT_EQ(drbs[0].qfis, (std::vector<std::uint8_t>{1, 2}));
    ASSERT_TRUE(ping_once(n, {10, 60, 0, 9}));
    EXPECT_EQ(ul_on(n, 2), 2u);
    EXPECT_EQ(n.failures(), "");
}

TEST(Session, Ts38413_8_2_1_ADuplicatePsiIsRefusedByTheGnb) {
    Net n;
    n.register_ue();
    n.establish();
    const auto ids = n.amf.ids(0);
    ASSERT_TRUE(ids.has_value());
    ngap::PduSessionResourceSetupRequest r;
    r.amf = ids->amf;
    r.ran = ids->ran;
    ngap::SessionSetupItem item;
    item.psi = 1;
    item.snssai = ngap::Snssai{1, std::nullopt};
    item.transfer.ul = ngap::GtpTunnel{{127, 0, 0, 9}, 0x51000099};
    item.transfer.flows = {ngap::QosFlowRequest{}};
    r.sessions = {item};
    n.amf.send(r, 1);
    ASSERT_TRUE(n.loop.run_until([&] { return n.amf.count("PDUSessionResourceSetupResponse") == 2; }, n.loop.now() + 2'000));
    EXPECT_EQ(n.named("ran.session.failure").size(), 1u);
    EXPECT_EQ(n.cucp.sessions_of(ids->ran), std::vector<std::uint8_t>{1});   // the first one still stands
}

TEST(Session, Ts29281_7_3_1_AGpduToAnUnknownTeidIsAnsweredWithAnErrorIndication) {
    Net n;
    n.start();
    auto probe = port(n.net, n.loop, 40);
    ASSERT_NE(probe, nullptr);
    entity::gtpu::Endpoint ep(*probe, 0x77);
    int errors = 0;
    ep.on_error_indication([&](std::uint32_t, const Endpoint&) { ++errors; });
    ASSERT_TRUE(ep.send(Endpoint::v4(127, 0, 0, 31, 2152), entity::gtpu::UserData::dl_psc(0x31ABCDEF, 1, Bytes{0x45})));
    bool echoed = false;
    ASSERT_TRUE(ep.echo(Endpoint::v4(127, 0, 0, 31, 2152), [&] { echoed = true; }));
    ASSERT_TRUE(n.loop.run_until([&] { return errors == 1 && echoed; }, n.loop.now() + 1'000));
}

TEST(Session, Mutant_ignore_backoff_SendsTheRequestWhileTheTimerRuns) {
    if (!kMutationsBuild) {
        GTEST_SKIP() << "mutant build only";
    }
    testing::MutantScope m("ignore_backoff");
    corestub::Profile p;
    p.session.establishment = corestub::SessionProfile::Establishment::reject;
    p.session.reject_cause = 29;
    p.session.backoff_s = 60;
    p.session.rejects = 1;
    Net n(p);
    n.register_ue();
    const proc::ue::SessionRequest req{0, "internet", std::nullopt};
    ASSERT_TRUE(n.ue->ps_establish(req));
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("nas.sm.est.reject").empty(); }, n.loop.now() + 5'000));
    EXPECT_TRUE(n.ue->ps_establish(req));
    n.loop.run_until([] { return false; }, n.loop.now() + 1'000);
    EXPECT_EQ(n.amf.smf().requests(), 2);   // the planted fault: the back-off was not honoured
}

// ---- the TUN data plane (P1 N11) ----------------------------------------------------------

TEST(DataPlane, EachSessionGetsATunWithItsAddressMtuTableAndDns) {
    FakeUeNet net;
    {
        Net n({}, &net);
        n.register_ue();
        EXPECT_EQ(net.setups, std::vector<std::string>{"ksim-ue-1"});   // from power on
        n.establish("internet");
        n.establish("ims");
        ASSERT_EQ(net.tuns.size(), 2u);
        const node::UeTun& a = net.specs.at("pdu1");
        EXPECT_EQ(a.addr, (ip::Addr{10, 60, 0, 2}));
        EXPECT_EQ(a.mtu, 1400);
        EXPECT_EQ(a.table, 101);
        EXPECT_TRUE(a.main_default);                         // the first session's
        EXPECT_FALSE(net.specs.at("pdu2").main_default);
        EXPECT_EQ(net.specs.at("pdu2").table, 102);
        ASSERT_EQ(net.dnss.size(), 1u);                      // one resolv.conf: the first session's server
        EXPECT_EQ(net.dnss[0], (ip::Addr{10, 60, 0, 1}));
        EXPECT_EQ(n.named("ue.dataplane.up").size(), 2u);
        const auto list = n.ue->ifaces();
        ASSERT_EQ(list.size(), 2u);
        EXPECT_EQ(list[0].ifname, "pdu1");
        ASSERT_TRUE(n.ue->ps_release(2));
        ASSERT_TRUE(n.loop.run_until([&] { return net.tuns.size() == 1; }, n.loop.now() + 5'000));
        EXPECT_EQ(net.closed, std::vector<std::string>{"pdu2"});
    }
    EXPECT_EQ(net.teardowns, std::vector<std::string>{"ksim-ue-1"});   // the namespace goes with the device
}

TEST(DataPlane, APacketFromTheTunCrossesTheNetworkAndItsReplyComesBack) {
    FakeUeNet net;
    Net n({}, &net);
    n.register_ue();
    n.establish();
    auto* tun = net.tuns.at("pdu1");
    // The namespace's own ping: an echo request from the session's address.
    tun->from_kernel(ip::ping({10, 60, 0, 2}, {10, 60, 0, 1}, 0x4242, 1, 56));
    ASSERT_TRUE(n.loop.run_until([&] { return !tun->written.empty(); }, n.loop.now() + 2'000));
    auto reply = ip::decode(tun->written.front());
    ASSERT_TRUE(reply);
    EXPECT_EQ(reply->src, (ip::Addr{10, 60, 0, 1}));
    EXPECT_EQ(reply->dst, (ip::Addr{10, 60, 0, 2}));
    auto echo = ip::decode_icmp(reply->payload);
    ASSERT_TRUE(echo && *echo);
    EXPECT_TRUE((*echo)->reply);
    EXPECT_EQ((*echo)->id, 0x4242);
    EXPECT_EQ(n.amf.upf()->stats().echo_replies, 1u);
    EXPECT_EQ(n.ue->noise(), 0u);
    // A DN ping reaches the namespace's stack (the TUN), not the device's own answer.
    ASSERT_TRUE(n.amf.smf().ping_ue(kSupi, 1, 9));
    ASSERT_TRUE(n.loop.run_until([&] { return tun->written.size() == 2; }, n.loop.now() + 2'000));
    EXPECT_TRUE(n.named("ue.ping.answered").empty());
    EXPECT_EQ(n.failures(), "");
}

TEST(DataPlane, WhatIsNotIpv4FromTheSessionAddressIsNoise) {
    FakeUeNet net;
    Net n({}, &net);
    n.register_ue();
    n.establish();
    auto* tun = net.tuns.at("pdu1");
    Bytes v6(40, 0);
    v6[0] = 0x60;   // an IPv6 router solicitation's header, say
    tun->from_kernel(v6);
    tun->from_kernel(ip::ping({10, 99, 0, 9}, {10, 60, 0, 1}, 1, 1, 8));   // another source
    n.loop.run_until([] { return false; }, n.loop.now() + 500);
    EXPECT_EQ(n.ue->noise(), 2u);
    EXPECT_EQ(n.named("ue.dataplane.noise").size(), 1u);   // the first one is an event
    EXPECT_EQ(n.amf.upf()->stats().ul_packets, 0u);
}

TEST(DataPlane, InjectModeHasNoNamespaceAndExecIsRefused) {
    Net n;
    n.register_ue();
    n.establish();
    EXPECT_FALSE(n.ue->netns_mode());
    EXPECT_TRUE(n.ue->ifaces().empty());
    auto x = n.ue->exec({"true"}, {});
    ASSERT_FALSE(x);
    EXPECT_EQ(x.error().code, Errc::unsupported);
}

} // namespace
} // namespace ksim::proctest
