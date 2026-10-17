// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// 5GMM completion in virtual time (P1 N12), over the whole network of
// net_rig.hpp: CM-IDLE after a RAN release with T3512 running, the service
// request for uplink data and for paging, the periodic registration without a
// new authentication, network de-registration with re-registration, radio
// loss, the 5G-GUTI and context kept on the USIM across a power cycle, the
// configuration update and identification, and the mutants of the N12 rows.

#include <gtest/gtest.h>

#include <memory>
#include <string>

#include "codec/nas/build.hpp"
#include "net_rig.hpp"

namespace ksim::proctest {
namespace {

std::string field(const Event& e, const char* k) {
    const std::string* v = e.find(k);
    return v != nullptr ? *v : std::string("<none>");
}

/// Registered, a session up, then released by the gNB into CM-IDLE.
void to_idle(Net& n) {
    const auto before = n.named("nas.mm.cm_idle").size();
    const auto completes = n.amf.count("UEContextReleaseComplete");
    const auto ids = n.amf.ids(0);
    ASSERT_TRUE(ids.has_value());
    ASSERT_TRUE(n.cucp.request_release(ids->ran));
    // The UE goes idle on its RRCRelease; the core deactivates the user plane on the gNB's complete.
    ASSERT_TRUE(n.loop.run_until([&] { return n.named("nas.mm.cm_idle").size() > before &&
                                              n.amf.count("UEContextReleaseComplete") > completes; },
                                 n.loop.now() + 2'000));
}

TEST(Idle, Ts38413_8_3_2_ARanReleasePutsTheUeInCmIdleWithT3512Running) {
    Net n;
    n.register_ue();
    n.establish();
    to_idle(n);
    const Event* r = n.last("ran.ue.release_request");
    ASSERT_NE(r, nullptr);
    EXPECT_EQ(field(*r, "cause"), "user-inactivity");
    EXPECT_EQ(n.amf.count("UEContextReleaseRequest"), 1u);
    const Event* t = n.last("nas.mm.t3512");
    ASSERT_NE(t, nullptr);
    EXPECT_EQ(field(*t, "seconds"), "3600");   // the stub's accept
    EXPECT_EQ(n.ue->sessions().size(), 1u);   // the session stays, its user plane does not
    EXPECT_EQ(n.failures(), "");
}

TEST(Idle, Ts24501_5_6_1_AnUplinkPingFromIdleGoesAfterAServiceRequest) {
    Net n;
    n.register_ue();
    n.establish();
    to_idle(n);
    node::PingRequest p;
    p.dst = {10, 60, 0, 1};
    p.count = 2;
    p.interval = 300;
    ASSERT_TRUE(n.ue->ping(p));
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("ue.ping.done").empty(); }, n.loop.now() + 6'000));
    EXPECT_EQ(field(*n.last("ue.ping.done"), "received"), "2");
    const Event* a = n.last("nas.sr.accept");
    ASSERT_NE(a, nullptr);
    EXPECT_EQ(field(*a, "pending_uplink"), "1");
    EXPECT_EQ(n.amf.nas()->service_requests(), 1);
    EXPECT_EQ(n.cucp.sessions_of(n.amf.ids(0)->ran), std::vector<std::uint8_t>{1});   // back in the ICS
    EXPECT_EQ(n.failures(), "");
}

TEST(Idle, Ts24501_5_6_1_1_b_UplinkDataInCmConnectedWithoutUserPlaneAsksForIt) {
    // KS-NAS-D5 (kaluza-core W3): connected for signalling only, the session has
    // no user plane; uplink data then needs a SERVICE REQUEST on that connection.
    Net n;
    n.register_ue();
    n.establish();
    to_idle(n);
    ASSERT_TRUE(n.ue->service_request());   // signalling: the session's user plane stays down
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("nas.sr.accept").empty(); }, n.loop.now() + 3'000));
    ASSERT_TRUE(n.cucp.sessions_of(n.amf.ids(0)->ran).empty());
    node::PingRequest p;
    p.dst = {10, 60, 0, 1};
    p.count = 2;
    p.interval = 300;
    ASSERT_TRUE(n.ue->ping(p));
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("ue.ping.done").empty(); }, n.loop.now() + 6'000));
    EXPECT_EQ(field(*n.last("ue.ping.done"), "received"), "2");
    const Event* r = n.last("nas.sr.request");
    ASSERT_NE(r, nullptr);
    EXPECT_EQ(field(*r, "connected"), "1");
    EXPECT_EQ(field(*r, "type"), "1");   // data
    EXPECT_EQ(n.named("nas.sr.accept").size(), 2u);
    EXPECT_EQ(n.cucp.sessions_of(n.amf.ids(0)->ran), std::vector<std::uint8_t>{1});
    EXPECT_EQ(n.failures(), "");
}

TEST(Idle, Ts23502_4_2_3_3_DownlinkForTheIdleUePagesItAndIsAnswered) {
    Net n;
    n.register_ue();
    n.establish();
    to_idle(n);
    ASSERT_TRUE(n.amf.smf().ping_ue(kSupi, 1, 7));   // held at the UPF: the AMF pages
    ASSERT_TRUE(n.loop.run_until([&] { return n.amf.upf()->stats().echo_from_ue == 1; }, n.loop.now() + 3'000));
    EXPECT_EQ(n.amf.pagings(), 1u);
    EXPECT_EQ(n.named("ran.ngap.paging").size(), 1u);
    EXPECT_EQ(n.named("nas.mm.paged").size(), 1u);
    EXPECT_EQ(field(*n.last("nas.sr.request"), "type"), "2");   // mobile terminated services
    EXPECT_EQ(n.named("ue.ping.answered").size(), 1u);
    EXPECT_EQ(n.failures(), "");
}

TEST(Idle, Ts24501_5_5_1_3_T3512RunsOutAndThePeriodicRegistrationNeedsNoNewAuthentication) {
    corestub::Profile p;
    p.t3512_s = 6;
    Net n(p);
    n.register_ue();
    n.establish();
    to_idle(n);
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("nas.reg.request").empty() &&
                                              field(*n.last("nas.reg.request"), "type") == "periodic"; },
                                 n.loop.now() + 7'000));
    const Event* req = n.last("nas.reg.request");
    EXPECT_EQ(field(*req, "identity"), "5g-guti");
    EXPECT_EQ(field(*req, "protected"), "integrity");
    ASSERT_TRUE(n.loop.run_until([&] { return field(*n.last("nas.reg.accept"), "type") == "periodic"; }, n.loop.now() + 3'000));
    EXPECT_EQ(n.amf.nas()->challenges(), 1);   // no AUTHENTICATION REQUEST since the first registration
    ASSERT_TRUE(n.loop.run_until([&] { return n.named("nas.mm.cm_idle").size() == 2; }, n.loop.now() + 3'000));
    // The session still carries a ping (row amf-ueransim.039).
    node::PingRequest ping;
    ping.dst = {10, 60, 0, 1};
    ping.count = 1;
    ASSERT_TRUE(n.ue->ping(ping));
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("ue.ping.done").empty(); }, n.loop.now() + 5'000));
    EXPECT_EQ(field(*n.last("ue.ping.done"), "received"), "1");
    EXPECT_EQ(n.failures(), "");
}

TEST(Idle, Ts24501_5_5_1_3_2_f_AfterARadioLinkFailureAMobilityRegistrationBringsTheUserPlaneBack) {
    Net n;
    n.register_ue();
    n.establish();
    n.air_down = true;   // the cell out of reach: both ends supervise the link
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("rrc.connection_lost").empty() &&
                                              n.amf.count("UEContextReleaseRequest") == 1; },
                                 n.loop.now() + 3'000));
    EXPECT_EQ(field(*n.last("rrc.connection_lost"), "reason"), "radio link failure");
    // The first attempt meets no cell; T3511's retry carries the Uplink data status again.
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("nas.reg.abort").empty(); }, n.loop.now() + 3'000));
    n.air_down = false;
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("nas.reg.accept").empty() &&
                                              field(*n.last("nas.reg.accept"), "type") == "mobility" &&
                                              n.named("rrc.reconfiguration.complete").size() >= 2; },
                                 n.loop.now() + 30'000)) << n.failures();
    const Event* req = n.last("nas.reg.request");
    EXPECT_EQ(field(*req, "type"), "mobility");
    EXPECT_EQ(field(*req, "identity"), "5g-guti");
    EXPECT_EQ(n.amf.nas()->count_uplink("SERVICE REQUEST"), 0u);
    // The user plane is back without a service request: a ping goes at once.
    node::PingRequest p;
    p.dst = {10, 60, 0, 1};
    p.count = 1;
    ASSERT_TRUE(n.ue->ping(p));
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("ue.ping.done").empty(); }, n.loop.now() + 3'000));
    EXPECT_EQ(field(*n.last("ue.ping.done"), "received"), "1");
    EXPECT_TRUE(n.named("nas.sr.request").empty());
    EXPECT_EQ(n.failures(), "");
}

TEST(Idle, Ts38413_8_7_1_AfterAnAmfRestartTheGnbSetsUpAgainAndTheUeCarriesOnRegistered) {
    Net n;
    n.register_ue();
    n.establish();
    n.amf.status_indication();
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("ran.amf.status").empty(); }, n.loop.now() + 1'000));
    n.ng.b().abort();   // the AMF goes; its UE contexts stay (L11)
    n.amf.rebind(n.ng.b());
    // The gNB releases its UEs on the lost association, the Uu side included.
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("rrc.release").empty() && !n.named("nas.mm.cm_idle").empty(); },
                                 n.loop.now() + 2'000));
    n.ng.connect();
    ASSERT_TRUE(n.loop.run_until([&] { return n.named("ran.ng.setup").size() == 2; }, n.loop.now() + 2'000));
    node::PingRequest p;
    p.dst = {10, 60, 0, 1};
    p.count = 2;
    p.interval = 300;
    ASSERT_TRUE(n.ue->ping(p));
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("ue.ping.done").empty(); }, n.loop.now() + 5'000));
    EXPECT_EQ(field(*n.last("ue.ping.done"), "received"), "2");
    EXPECT_EQ(n.named("nas.reg.request").size(), 1u);   // still registered: a service request, no registration
    EXPECT_EQ(n.named("nas.sr.accept").size(), 1u);
    EXPECT_EQ(n.amf.nas()->challenges(), 1);
    EXPECT_EQ(n.failures(), "");
}

TEST(Idle, Ts24501_5_5_2_2_1_TakingTheUiccOutDeregistersAndPuttingItBackRegistersAgain) {
    Net n;
    n.register_ue();
    n.establish();
    ASSERT_TRUE(n.ue->sim(false));
    ASSERT_TRUE(n.loop.run_until([&] { return n.ue->mm_state() == proc::ue::MmState::deregistered_no_supi; },
                                 n.loop.now() + 3'000)) << n.failures();
    EXPECT_EQ(n.amf.nas()->count_uplink("DEREGISTRATION REQUEST"), 1u);
    EXPECT_EQ(n.named("nas.dereg.accept").size(), 1u);   // a normal de-registration, answered
    EXPECT_TRUE(n.ue->sessions().empty());
    EXPECT_FALSE(n.ue->sim(false).has_value());           // out already
    ASSERT_TRUE(n.ue->sim(true));
    ASSERT_TRUE(n.loop.run_until([&] { return n.named("nas.reg.complete").size() == 2; }, n.loop.now() + 10'000))
        << n.failures();
    EXPECT_EQ(n.failures(), "");   // nothing was written to the absent card
}

TEST(Idle, AirplaneModeDeregistersAsForSwitchOffAndComesBackWithTheGuti) {
    Net n;
    n.register_ue();
    ASSERT_TRUE(n.ue->airplane(true));
    ASSERT_TRUE(n.loop.run_until([&] { return n.amf.nas()->count_uplink("DEREGISTRATION REQUEST") == 1; },
                                 n.loop.now() + 3'000));
    EXPECT_EQ(field(*n.last("nas.dereg.sent"), "switch_off"), "1");
    EXPECT_EQ(field(*n.last("rrc.power"), "on"), "0");
    n.loop.run_until([] { return false; }, n.loop.now() + 1'000);
    ASSERT_TRUE(n.ue->airplane(false));
    ASSERT_TRUE(n.loop.run_until([&] { return n.named("nas.reg.complete").size() == 2; }, n.loop.now() + 10'000))
        << n.failures();
    EXPECT_EQ(field(*n.last("nas.reg.request"), "identity"), "5g-guti");
    EXPECT_EQ(field(*n.last("nas.reg.request"), "protected"), "integrity");
    EXPECT_EQ(n.failures(), "");
}

TEST(Idle, Ts24501_5_5_2_3_4_b_ANetworkDeregistrationWithoutCauseOrReregistrationWaitsForT3502) {
    Net n;
    n.register_ue();
    ASSERT_TRUE(n.amf.nas()->network_deregister(false));
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("nas.dereg.network").empty(); }, n.loop.now() + 2'000));
    EXPECT_EQ(n.ue->mm_state(), proc::ue::MmState::deregistered_attempting_registration);
    EXPECT_EQ(n.named("nas.reg.request").size(), 1u);
    // T3502 (12 min unless the network gave one) runs out: a new registration.
    ASSERT_TRUE(n.loop.run_until([&] { return n.named("nas.reg.request").size() == 2; }, n.loop.now() + 730'000));
    EXPECT_EQ(field(*n.last("nas.mm.state"), "to"), "5GMM-REGISTERED-INITIATED");
}

TEST(Idle, Ts24501_5_5_2_3_2_ANetworkDeregistrationWithCause3MakesTheUsimInvalid) {
    Net n;
    n.register_ue();
    ASSERT_TRUE(n.amf.nas()->network_deregister(false, 3));
    ASSERT_TRUE(n.loop.run_until([&] { return n.ue->mm_state() == proc::ue::MmState::deregistered_no_supi; },
                                 n.loop.now() + 2'000));
    EXPECT_EQ(field(*n.last("nas.dereg.network"), "cause"), "3");
}

TEST(Idle, Ts24501_5_5_2_2_6_d_ANetworkDeregistrationDuringTheUesOwnIsAcceptedWithoutReregistering) {
    corestub::Profile p;
    p.deregistration = corestub::Profile::Deregistration::silent;   // the UE's request goes unanswered
    Net n(p);
    n.register_ue();
    ASSERT_TRUE(n.ue->deregister(false));
    ASSERT_TRUE(n.loop.run_until([&] { return n.ue->mm_state() == proc::ue::MmState::deregistered_initiated; },
                                 n.loop.now() + 1'000));
    ASSERT_TRUE(n.amf.nas()->network_deregister(true));
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("nas.dereg.network").empty(); }, n.loop.now() + 2'000));
    EXPECT_EQ(field(*n.last("nas.dereg.network"), "collision"), "1");
    EXPECT_EQ(n.ue->mm_state(), proc::ue::MmState::deregistered_normal_service);
    n.loop.run_until([] { return false; }, n.loop.now() + 20'000);   // past T3521 and the re-registration delay
    EXPECT_EQ(n.named("nas.reg.request").size(), 1u);   // the UE need not register again
    EXPECT_TRUE(n.named("nas.dereg.abort").empty());   // T3521 stopped
}

TEST(Idle, Ts24501_5_5_2_3_ANetworkDeregistrationWithReregistrationRequiredIsFollowedByARegistration) {
    Net n;
    n.register_ue();
    n.establish();
    ASSERT_TRUE(n.amf.deregister(kSupi, true));
    ASSERT_TRUE(n.loop.run_until([&] { return n.named("nas.reg.complete").size() == 2; }, n.loop.now() + 6'000)) << n.failures();
    const Event* d = n.last("nas.dereg.network");
    ASSERT_NE(d, nullptr);
    EXPECT_EQ(field(*d, "reregistration"), "1");
    EXPECT_TRUE(n.ue->sessions().empty());   // released locally with the de-registration
    EXPECT_EQ(n.amf.smf().sessions(), 0u);
    EXPECT_EQ(n.failures(), "");
}

TEST(Idle, Ts38473_8_3_2_AnAbruptPowerOffLeadsTheGnbToAskForAReleaseForRadioLoss) {
    Net n;
    n.register_ue();
    ASSERT_TRUE(n.ue->power_off_abrupt());
    ASSERT_TRUE(n.loop.run_until([&] { return n.amf.count("UEContextReleaseRequest") == 1; }, n.loop.now() + 3'000));
    EXPECT_EQ(n.named("ran.du.rlf").size(), 1u);
    EXPECT_EQ(field(*n.last("ran.ue.release_request"), "cause"), "radio-connection-with-ue-lost");
    ASSERT_TRUE(n.loop.run_until([&] { return n.cucp.ues() == 0; }, n.loop.now() + 2'000));
    EXPECT_EQ(n.failures(), "");
}

TEST(Idle, Ts24501_4_4_6_AfterAGracefulPowerCycleTheUeRegistersWithItsGutiAndAProtectedRequest) {
    Net n;
    n.register_ue();
    ASSERT_TRUE(n.ue->deregister(true));   // switch-off: the context and the 5G-GUTI go to the USIM
    n.loop.run_until([] { return false; }, n.loop.now() + 1'000);
    ASSERT_TRUE(n.ue->power_on());
    ASSERT_TRUE(n.loop.run_until([&] { return n.named("nas.reg.complete").size() == 2; }, n.loop.now() + 10'000)) << n.failures();
    const auto power = n.named("nas.mm.power_on");
    ASSERT_EQ(power.size(), 2u);
    EXPECT_EQ(field(power[1], "context"), "stored");
    EXPECT_NE(field(power[1], "guti"), "");
    const Event* req = n.last("nas.reg.request");
    EXPECT_EQ(field(*req, "identity"), "5g-guti");
    EXPECT_EQ(field(*req, "protected"), "integrity");
    EXPECT_EQ(n.amf.nas()->challenges(), 1);   // the stored context verified: no new AKA
    EXPECT_EQ(n.failures(), "");
}

TEST(Idle, AfterAnAbruptPowerCyclePsi1IsEstablishedAnewWithoutWaitingForT3580) {
    Net n;
    n.register_ue();
    n.establish();
    ASSERT_TRUE(n.ue->power_off_abrupt());   // the network still holds PSI 1
    ASSERT_TRUE(n.loop.run_until([&] { return n.cucp.ues() == 0; }, n.loop.now() + 3'000));
    ASSERT_TRUE(n.ue->power_on());
    ASSERT_TRUE(n.loop.run_until([&] { return n.named("nas.reg.complete").size() == 2; }, n.loop.now() + 10'000)) << n.failures();
    EXPECT_EQ(field(*n.last("nas.reg.request"), "identity"), "5g-guti");   // EF.5GS3GPPLOCI kept it
    const Millis t0 = n.loop.now();
    n.establish();
    EXPECT_EQ(field(*n.last("nas.sm.est.accept"), "psi"), "1");
    EXPECT_LT(n.loop.now() - t0, 5'000);   // well inside T3580's 16 s
    EXPECT_TRUE(n.named("nas.sm.timer.expiry").empty());
    EXPECT_EQ(n.amf.smf().sessions(), 1u);
    EXPECT_EQ(n.failures(), "");
}

TEST(Idle, Ts24501_5_4_4_AndIdentification_TheUeAnswersAConfigurationUpdateAndAnIdentityRequest) {
    Net n;
    n.register_ue();
    auto cmd = nas::make(nas::Epd::mm, 0x54);
    ASSERT_TRUE(cmd);
    (void)nas::set(*cmd, "Configuration update indication", nas::ie::ConfigurationUpdateIndication{true, false}.encode());
    auto wire = nas::encode(*cmd);
    ASSERT_TRUE(wire);
    n.amf.nas()->send_protected(*wire);
    auto id = nas::make(nas::Epd::mm, 0x5B);
    ASSERT_TRUE(id);
    (void)nas::set(*id, "Identity type", nas::ie::IdentityType{nas::ie::IdentityType::imei}.encode());
    auto idw = nas::encode(*id);
    ASSERT_TRUE(idw);
    n.amf.nas()->send_protected(*idw);
    ASSERT_TRUE(n.loop.run_until([&] { return n.amf.nas()->count_uplink("IDENTITY RESPONSE") == 1; }, n.loop.now() + 2'000));
    EXPECT_EQ(n.amf.nas()->count_uplink("CONFIGURATION UPDATE COMPLETE"), 1u);
    EXPECT_EQ(field(*n.last("nas.mm.config_update"), "ack"), "1");
    EXPECT_EQ(field(*n.last("nas.mm.identity"), "type"), "3");
    EXPECT_EQ(n.failures(), "");
}

TEST(Idle, Ts24501_5_5_2_2_ADeregistrationFromCmIdleEstablishesTheConnectionAndIsAccepted) {
    Net n;
    n.register_ue();
    n.establish();
    to_idle(n);
    ASSERT_TRUE(n.ue->deregister(false));
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("nas.dereg.accept").empty(); }, n.loop.now() + 3'000)) << n.failures();
    EXPECT_EQ(n.named("rrc.setup.complete").size(), 2u);   // the request was an initial NAS message
    EXPECT_EQ(n.amf.nas()->count_uplink("DEREGISTRATION REQUEST"), 1u);
    EXPECT_TRUE(n.ue->sessions().empty());
    EXPECT_EQ(n.failures(), "");
}

TEST(Idle, Ts24501_5_5_2_2_ASwitchOffFromCmIdleReachesTheAmf) {
    Net n;
    n.register_ue();
    to_idle(n);
    ASSERT_TRUE(n.ue->deregister(true));
    ASSERT_TRUE(n.loop.run_until([&] { return n.amf.nas()->count_uplink("DEREGISTRATION REQUEST") == 1; },
                                 n.loop.now() + 3'000)) << n.failures();
    EXPECT_EQ(n.named("rrc.setup.complete").size(), 2u);   // it went in RRCSetupComplete, then the radio went off
    EXPECT_EQ(field(*n.last("rrc.power"), "on"), "0");
    EXPECT_EQ(n.failures(), "");
}

// ---- rejects and their timers (§5.5.1.2.5, §5.6.1.5, §5.3.9) --------------------------------

TEST(Idle, Ts24501_5_5_1_2_5_Reject22WithT3346HoldsTheRegistrationUntilT3346RunsOut) {
    corestub::Profile p;
    p.registration = corestub::Profile::Registration::reject;
    p.reject_cause = 22;
    p.t3346_s = 6;
    Net n(p);
    n.start();
    ASSERT_TRUE(n.ue->power_on());
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("nas.mm.t3346").empty(); }, n.loop.now() + 5'000));
    EXPECT_EQ(field(*n.last("nas.reg.reject"), "cause"), "22");
    EXPECT_EQ(field(*n.last("nas.mm.t3346"), "seconds"), "6");
    const Millis rejected = n.loop.now();
    (void)n.ue->register_initial();
    n.loop.run_until([] { return false; }, rejected + 1'000);
    EXPECT_EQ(n.named("nas.reg.request").size(), 1u);   // T3346 runs: no new attempt
    EXPECT_FALSE(n.named("nas.reg.blocked").empty());
    // T3346 runs out: a new attempt, at once (§5.5.1.2.7 / §5.3.9).
    ASSERT_TRUE(n.loop.run_until([&] { return n.named("nas.reg.request").size() == 2; }, rejected + 8'000));
    EXPECT_GE(n.loop.now() - rejected, 6'000);
    EXPECT_EQ(n.failures(), "");
}

TEST(Idle, Ts24501_5_5_1_2_5_Reject11PutsThePlmnOnTheForbiddenListAndStopsFurtherAttempts) {
    corestub::Profile p;
    p.registration = corestub::Profile::Registration::reject;
    p.reject_cause = 11;
    Net n(p);
    n.start();
    ASSERT_TRUE(n.ue->power_on());
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("nas.reg.reject").empty(); }, n.loop.now() + 5'000));
    EXPECT_EQ(n.ue->mm_state(), proc::ue::MmState::deregistered_plmn_search);
    (void)n.ue->register_initial();
    n.loop.run_until([] { return false; }, n.loop.now() + 30'000);   // past T3511 and T3502's first runs
    EXPECT_EQ(n.named("nas.reg.request").size(), 1u);
    ASSERT_NE(n.last("nas.reg.blocked"), nullptr);
    EXPECT_EQ(field(*n.last("nas.reg.blocked"), "why"), "forbidden PLMN");
    EXPECT_EQ(n.failures(), "");
}

TEST(Idle, Ts24501_5_5_1_2_5_Reject15PutsTheCurrentTaOnTheForbiddenList) {
    corestub::Profile p;
    p.registration = corestub::Profile::Registration::reject;
    p.reject_cause = 15;
    Net n(p);
    n.start();
    ASSERT_TRUE(n.ue->power_on());
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("nas.reg.reject").empty(); }, n.loop.now() + 5'000));
    EXPECT_EQ(n.ue->mm_state(), proc::ue::MmState::deregistered_limited_service);
    (void)n.ue->register_initial();
    n.loop.run_until([] { return false; }, n.loop.now() + 1'000);
    EXPECT_EQ(n.named("nas.reg.request").size(), 1u);   // a fresh UE: the camped cell's TA, not a stored one
    ASSERT_NE(n.last("nas.reg.blocked"), nullptr);
    EXPECT_EQ(field(*n.last("nas.reg.blocked"), "why"), "forbidden TA");
    EXPECT_EQ(n.failures(), "");
}

TEST(Idle, Ts24501_5_3_20_2_AnUnprotectedReject3LeavesTheUsimValidAndForbidsTheTaUntilT3247) {
    corestub::Profile p;
    p.registration = corestub::Profile::Registration::reject;
    p.reject_cause = 3;
    p.reject_unprotected = true;
    Net n(p);
    n.start();
    ASSERT_TRUE(n.ue->power_on());
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("nas.mm.t3247").empty(); }, n.loop.now() + 5'000));
    EXPECT_EQ(field(*n.last("nas.reg.reject"), "protected"), "0");
    EXPECT_EQ(n.ue->mm_state(), proc::ue::MmState::deregistered_limited_service);   // not NO-SUPI
    const long secs = std::stol(field(*n.last("nas.mm.t3247"), "seconds"));
    EXPECT_GE(secs, 1800);
    EXPECT_LE(secs, 3600);
    (void)n.ue->register_initial();
    n.loop.run_until([] { return false; }, n.loop.now() + 60'000);
    EXPECT_EQ(n.named("nas.reg.request").size(), 1u);   // the current TA is forbidden
    EXPECT_EQ(field(*n.last("nas.reg.blocked"), "why"), "forbidden TA");
    // T3247's expiry (the TA allowed again, a new registration) is the next tests', with a short T3247.
}

/// T3247 drawn from one to two minutes, so the tests that do not check its range run quickly.
proc::ue::MmTimerValues short_t3247() {
    proc::ue::MmTimerValues t;
    t.t3247_min = 60'000;
    t.t3247_max = 120'000;
    return t;
}

TEST(Idle, Ts24501_5_3_20_2_TheFourthUnprotectedReject3MakesTheUsimInvalid) {
    corestub::Profile p;
    p.registration = corestub::Profile::Registration::reject;
    p.reject_cause = 3;
    p.reject_unprotected = true;
    Net n(p, nullptr, short_t3247());
    n.start();
    ASSERT_TRUE(n.ue->power_on());
    // Three events are allowed (kMaxInvalidEvents); each T3247 brings the next attempt.
    ASSERT_TRUE(n.loop.run_until([&] { return n.ue->mm_state() == proc::ue::MmState::deregistered_no_supi; },
                                 n.loop.now() + Millis{4} * 130'000));
    EXPECT_EQ(n.named("nas.reg.reject").size(), 4u);
    const auto expiries = n.named("nas.mm.t3247.expiry");
    ASSERT_EQ(expiries.size(), 3u);
    EXPECT_EQ(field(expiries.front(), "usim"), "valid");   // under the maximum, the USIM is valid again
}

TEST(Idle, Ts24501_5_3_20_2_AnUnprotectedReject11InTheHplmnIsLimitedServiceNotAForbiddenPlmn) {
    corestub::Profile p;
    p.registration = corestub::Profile::Registration::reject;
    p.reject_cause = 11;
    p.reject_unprotected = true;
    Net n(p, nullptr, short_t3247());
    n.start();
    ASSERT_TRUE(n.ue->power_on());
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("nas.mm.t3247").empty(); }, n.loop.now() + 5'000));
    EXPECT_EQ(n.ue->mm_state(), proc::ue::MmState::deregistered_limited_service);
    ASSERT_TRUE(n.loop.run_until([&] { return n.named("nas.reg.request").size() == 2; }, n.loop.now() + 130'000));
    EXPECT_TRUE(n.named("nas.reg.blocked").empty() ||
                field(*n.last("nas.reg.blocked"), "why") != "forbidden PLMN");   // the PLMN was not forbidden
}

TEST(Idle, Ts24501_5_5_1_2_5_Reject62KeepsTheRejectedSnssaiOutOfTheNextRequest) {
    corestub::Profile p;
    p.registration = corestub::Profile::Registration::reject;
    p.reject_cause = 62;
    p.rejected_sst = 1;
    Net n(p);
    n.start();
    ASSERT_TRUE(n.ue->power_on());
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("nas.reg.reject").empty(); }, n.loop.now() + 5'000));
    EXPECT_EQ(field(*n.last("nas.reg.reject"), "protected"), "1");
    EXPECT_EQ(n.ue->mm_state(), proc::ue::MmState::deregistered_attempting_registration);
    EXPECT_EQ(field(n.named("nas.reg.request").front(), "nssai"), "1");
    (void)n.ue->register_initial();
    ASSERT_TRUE(n.loop.run_until([&] { return n.named("nas.reg.request").size() == 2; }, n.loop.now() + 5'000));
    EXPECT_EQ(field(*n.last("nas.reg.request"), "nssai"), "");   // §4.6.2.2: not asked for again
}

TEST(Idle, Ts24501_5_6_1_5_ServiceReject22WithT3346KeepsTheUeRegisteredAndHoldsTheNextRequest) {
    Net n;
    n.register_ue();
    n.establish();
    to_idle(n);
    n.amf.nas()->profile().service_reject_cause = 22;
    n.amf.nas()->profile().t3346_s = 5;
    const auto idle = n.named("nas.mm.cm_idle").size();
    ASSERT_TRUE(n.ue->service_request());
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("nas.sr.reject").empty() && n.named("nas.mm.cm_idle").size() > idle; },
                                 n.loop.now() + 3'000));
    EXPECT_EQ(field(*n.last("nas.sr.reject"), "cause"), "22");
    EXPECT_EQ(n.ue->mm_state(), proc::ue::MmState::registered_normal_service);
    EXPECT_FALSE(n.ue->service_request().has_value());   // T3346 runs
    EXPECT_EQ(field(*n.last("nas.sr.blocked"), "why"), "T3346");
    EXPECT_EQ(n.failures(), "");
}

TEST(Idle, Ts24501_5_6_1_5_ServiceReject9StartsAnInitialRegistrationWithTheSuci) {
    Net n;
    n.register_ue();
    n.establish();
    to_idle(n);
    n.amf.nas()->profile().service_reject_cause = 9;
    ASSERT_TRUE(n.ue->service_request());
    ASSERT_TRUE(n.loop.run_until([&] { return n.named("nas.reg.request").size() == 2; }, n.loop.now() + 5'000));
    EXPECT_EQ(field(*n.last("nas.sr.reject"), "cause"), "9");
    EXPECT_EQ(field(*n.last("nas.reg.request"), "type"), "initial");
    EXPECT_EQ(field(*n.last("nas.reg.request"), "identity"), "suci");   // §5.6.1.5 #9: the 5G-GUTI deleted
    EXPECT_TRUE(n.ue->sessions().empty());                                // released locally
}

TEST(Idle, Ts24501_5_6_1_7_T3517RunsOutWithNoAnswerAndTheUeStaysRegistered) {
    Net n;
    n.register_ue();
    to_idle(n);
    n.amf.nas()->profile().silent_service_request = true;
    ASSERT_TRUE(n.ue->service_request());
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("nas.sr.abort").empty(); }, n.loop.now() + 20'000));
    EXPECT_EQ(field(*n.last("nas.sr.abort"), "why"), "T3517");
    EXPECT_EQ(n.ue->mm_state(), proc::ue::MmState::registered_normal_service);
}

TEST(Idle, Ts24501_5_6_1_7_l_And_4_4_3_1_AServiceRequestWithNoRrcConnectionIsNotRetriedAtOnceAndTakesNoCount) {
    // LW5d (KS-NAS-D6, D7): a ps-release from CM-IDLE into a cell that cannot set
    // a connection up. The one SR aborts and is not started again on its own;
    // T3582's retransmission asks again, with the COUNT the failed ones gave back.
    Net n;
    n.register_ue();
    n.establish();
    to_idle(n);
    n.air_down = true;
    ASSERT_TRUE(n.ue->ps_release(1));
    n.loop.run_until([] { return false; }, n.loop.now() + 10'000);
    const auto srs = n.named("nas.sr.request");
    ASSERT_EQ(srs.size(), 1u);
    EXPECT_FALSE(n.named("rrc.setup.failure").empty());
    EXPECT_EQ(field(*n.last("nas.sr.abort"), "why"), "released");
    EXPECT_EQ(n.ue->mm_state(), proc::ue::MmState::registered_normal_service);
    const std::string count = field(srs[0], "count");
    n.air_down = false;
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("nas.sr.accept").empty() && n.ue->sessions().empty(); },
                                 n.loop.now() + 20'000)) << n.failures();
    EXPECT_EQ(n.named("nas.sr.request").size(), 2u);
    EXPECT_EQ(field(*n.last("nas.sr.request"), "count"), count);
    EXPECT_EQ(n.failures(), "");
}

// ---- the mutants of the N12 rows -----------------------------------------------------------

TEST(Idle, Mutant_paging_ignore_LeavesTheDownlinkUnanswered) {
    if (!kMutationsBuild) {
        GTEST_SKIP() << "mutant build only";
    }
    testing::MutantScope m("paging_ignore");
    Net n;
    n.register_ue();
    n.establish();
    to_idle(n);
    ASSERT_TRUE(n.amf.smf().ping_ue(kSupi, 1, 7));
    n.loop.run_until([] { return false; }, n.loop.now() + 3'000);
    EXPECT_EQ(n.amf.upf()->stats().echo_from_ue, 0u);
    EXPECT_TRUE(n.named("nas.sr.request").empty());
}

TEST(Idle, Mutant_dereg_no_reregistration_StaysDeregistered) {
    if (!kMutationsBuild) {
        GTEST_SKIP() << "mutant build only";
    }
    testing::MutantScope m("dereg_no_reregistration");
    Net n;
    n.register_ue();
    ASSERT_TRUE(n.amf.deregister(kSupi, true));
    n.loop.run_until([] { return false; }, n.loop.now() + 6'000);
    EXPECT_EQ(n.named("nas.reg.complete").size(), 1u);
}

TEST(Idle, Mutant_no_release_on_radio_loss_NeverAsksForTheRelease) {
    if (!kMutationsBuild) {
        GTEST_SKIP() << "mutant build only";
    }
    testing::MutantScope m("no_release_on_radio_loss");
    Net n;
    n.register_ue();
    ASSERT_TRUE(n.ue->power_off_abrupt());
    n.loop.run_until([] { return false; }, n.loop.now() + 3'000);
    EXPECT_EQ(n.amf.count("UEContextReleaseRequest"), 0u);
}

TEST(Idle, Mutant_guti_not_persisted_RegistersWithTheSuciAfterAPowerCycle) {
    if (!kMutationsBuild) {
        GTEST_SKIP() << "mutant build only";
    }
    testing::MutantScope m("guti_not_persisted");
    Net n;
    n.register_ue();
    ASSERT_TRUE(n.ue->deregister(true));
    n.loop.run_until([] { return false; }, n.loop.now() + 1'000);
    ASSERT_TRUE(n.ue->power_on());
    ASSERT_TRUE(n.loop.run_until([&] { return n.named("nas.reg.request").size() == 2; }, n.loop.now() + 5'000));
    EXPECT_EQ(field(*n.last("nas.reg.request"), "identity"), "suci");
}

} // namespace
} // namespace ksim::proctest
