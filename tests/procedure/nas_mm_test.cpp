// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// 5GMM procedure tests in virtual time (P1 N5; TS 24.501 j80 §5): the UE's
// 5GMM entity and its soft card against the core stub, named by clause. A
// test passes only if the stub recorded no failed verdict as well as the
// UE ending where the clause says.

#include <gtest/gtest.h>

#include <fstream>
#include <set>
#include <sstream>

#include "crypto/keys5g.hpp"
#include "platform/mutation.hpp"
#include "rig.hpp"

namespace ksim::proctest {
namespace {

using corestub::Profile;
using proc::ue::MmState;
using proc::ue::MmTimer;
using C = Profile::Challenge;

Profile with(std::vector<C> challenges) {
    Profile p;
    p.challenges = std::move(challenges);
    return p;
}

std::string field(const Event& e, std::string_view key) {
    const std::string* v = e.find(key);
    return v != nullptr ? *v : std::string("<none>");
}

TEST(Mm, Clause5_5_1_2_InitialRegistrationWithANullSuciEndsRegistered) {
    Rig r;
    ASSERT_TRUE(r.registered());
    ASSERT_TRUE(r.run_until([&] { return r.amf.registered(); }, 1'000));
    EXPECT_EQ(r.failures(), "");
    EXPECT_EQ(r.amf.uplink(), (std::vector<std::string>{"REGISTRATION REQUEST", "AUTHENTICATION RESPONSE",
                                                          "SECURITY MODE COMPLETE", "REGISTRATION COMPLETE"}));
    EXPECT_EQ(r.ue.supi(), kSupi);
    EXPECT_EQ(r.ue.update_status(), proc::ue::UpdateStatus::u1_updated);
    EXPECT_EQ(r.ue.attempt_counter(), 0);
    ASSERT_TRUE(r.ue.guti());
    EXPECT_EQ(r.ue.guti()->tmsi, 1u);
    const proc::ue::NasSecurityContext* sec = r.ue.security();
    ASSERT_NE(sec, nullptr);
    if (sec != nullptr) {   // gcc's -Wnull-dereference does not see through ASSERT_NE
        EXPECT_EQ(sec->ea(), 2);
        EXPECT_EQ(sec->ia(), 2);
        // The UE's and the AMF's contexts agree on the COUNTs: two protected uplink messages.
        EXPECT_EQ(sec->ul_count(), 2u);
    }
    EXPECT_EQ(r.ue.t3512(), 3'600'000);
    ASSERT_EQ(r.ue.allowed_nssai().size(), 1u);
    EXPECT_FALSE(r.ue.running(MmTimer::t3510));
    EXPECT_FALSE(r.ue.running(MmTimer::t3516));   // the SECURITY MODE COMMAND ended the stored challenge
    EXPECT_EQ(r.ue.unlisted_transitions(), 0u);
    const auto accept = r.named("nas.reg.accept");
    ASSERT_EQ(accept.size(), 1u);
    EXPECT_EQ(field(accept[0], "guti"), "00101-ca-001-01-00000001");
    EXPECT_EQ(field(accept[0], "t3512_s"), "3600");
    const auto smc = r.named("nas.smc.complete");
    ASSERT_EQ(smc.size(), 1u);
    EXPECT_EQ(field(smc[0], "imeisv"), "1");
    EXPECT_EQ(field(smc[0], "container"), "1");
    EXPECT_EQ(r.amf.last_ul_count(), 1u);
}

TEST(Mm, Clause5_4_1_3_7c_AMacFailureIsReportedAndTheNextValidChallengeAccepted) {
    Rig r(with({C::bad_mac, C::ok}));
    ASSERT_TRUE(r.registered());
    EXPECT_EQ(r.failures(), "");
    EXPECT_EQ(r.amf.count_uplink("AUTHENTICATION FAILURE"), 1u);
    EXPECT_EQ(r.amf.challenges(), 2);
    EXPECT_FALSE(r.ue.running(MmTimer::t3520));
    const auto f = r.named("nas.auth.failure");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(field(f[0], "cause"), "20");
}

TEST(Mm, Clause5_4_1_3_7f_ASynchFailureCarriesAutsAndTheResynchronisedChallengeWorks) {
    Rig r(with({C::stale_sqn, C::ok}));
    ASSERT_TRUE(r.registered());
    EXPECT_EQ(r.failures(), "");
    EXPECT_EQ(r.amf.resyncs(), 1);
    EXPECT_EQ(field(r.named("nas.auth.failure").at(0), "cause"), "21");
}

TEST(Mm, Clause5_4_1_3_7d_AChallengeWithoutTheSeparationBitIsRefusedWith26) {
    Rig r(with({C::non_5g, C::ok}));
    const std::uint64_t apdus_before = r.terminal.apdus();
    ASSERT_TRUE(r.registered());
    EXPECT_EQ(r.failures(), "");
    EXPECT_EQ(field(r.named("nas.auth.failure").at(0), "cause"), "26");
    EXPECT_GT(r.terminal.apdus(), apdus_before);
}

TEST(Mm, Clause5_4_1_3_7_ThreeConsecutiveFailedChallengesMeanTheNetworkFailedTheCheck) {
    Rig r(with({C::bad_mac, C::bad_mac, C::bad_mac}));
    r.power_on();
    r.ue.register_initial();
    ASSERT_TRUE(r.run_until([&] { return !r.named("nas.auth.network_failed").empty(); }, 10'000));
    EXPECT_EQ(r.failures(), "");
    EXPECT_EQ(r.amf.count_uplink("AUTHENTICATION FAILURE"), 2u);   // the third is not sent: the UE released
    EXPECT_EQ(r.link.local_releases, 1);
    // T3510, paused for the failures, runs again and ends the attempt (§5.5.1.2.7 c).
    EXPECT_TRUE(r.ue.running(MmTimer::t3510));
    ASSERT_TRUE(r.run_until([&] { return r.ue.state() == MmState::deregistered_attempting_registration; }, 20'000));
    EXPECT_EQ(r.ue.attempt_counter(), 1);
    EXPECT_TRUE(r.ue.running(MmTimer::t3511));
    EXPECT_EQ(r.ue.unlisted_transitions(), 0u);
}

TEST(Mm, Clause5_4_1_3_7_T3520RunningOutMeansTheNetworkFailedTheCheck) {
    Rig r(with({C::bad_mac, C::none}));
    r.power_on();
    r.ue.register_initial();
    ASSERT_TRUE(r.run_until([&] { return r.ue.running(MmTimer::t3520); }, 5'000));
    const Millis started = r.loop.now();
    ASSERT_TRUE(r.run_until([&] { return !r.named("nas.auth.network_failed").empty(); }, 20'000));
    EXPECT_GE(r.loop.now() - started, 15'000);   // T3520's default, Table 10.2.2
    EXPECT_EQ(r.failures(), "");
    EXPECT_EQ(r.link.local_releases, 1);
}

TEST(Mm, Clause5_4_1_3_3_ARetransmittedChallengeIsAnsweredFromTheStoredResStar) {
    Rig r(with({C::lose_response}));
    r.power_on();
    r.ue.register_initial();
    ASSERT_TRUE(r.run_until([&] { return r.named("nas.auth.response").size() == 1; }, 5'000));
    const std::uint64_t apdus = r.terminal.apdus();
    ASSERT_TRUE(r.run_until([&] { return r.ue.state() == MmState::registered_normal_service; }, 30'000));
    EXPECT_EQ(r.failures(), "");
    const auto responses = r.named("nas.auth.response");
    ASSERT_EQ(responses.size(), 2u);
    EXPECT_EQ(field(responses[1], "stored"), "1");
    EXPECT_EQ(r.terminal.apdus(), apdus);   // the USIM was not asked again
    EXPECT_EQ(r.amf.challenges(), 1);
}

TEST(Mm, Clause5_4_1_3_5_AnAuthenticationRejectWhileT3520RunsMakesTheUsimInvalid) {
    Rig r(with({C::bad_mac, C::reject}));
    r.power_on();
    r.ue.register_initial();
    ASSERT_TRUE(r.run_until([&] { return r.ue.state() == MmState::deregistered_no_supi; }, 10'000));
    EXPECT_EQ(r.failures(), "");
    EXPECT_FALSE(r.ue.usim_valid());
    EXPECT_EQ(r.ue.update_status(), proc::ue::UpdateStatus::u3_roaming_not_allowed);
    EXPECT_FALSE(r.ue.running(MmTimer::t3510));
    EXPECT_FALSE(r.ue.running(MmTimer::t3520));
    r.ue.register_initial();   // a USIM considered invalid does not register
    r.loop.run_for(1'000);
    EXPECT_EQ(r.amf.count_uplink("REGISTRATION REQUEST"), 1u);
}

TEST(Mm, Clause5_4_1_3_7m_APlainAuthenticationRejectWithNoTimerRunningIsDiscarded) {
    Rig r(with({C::reject}));
    r.power_on();
    r.ue.register_initial();
    ASSERT_TRUE(r.run_until([&] { return !r.named("nas.sec.discard").empty(); }, 5'000));
    EXPECT_TRUE(r.ue.usim_valid());
    // The stub releases after its reject: an abnormal case of the registration (§5.5.1.2.7 e), not a reject.
    ASSERT_TRUE(r.run_until([&] { return r.ue.state() == MmState::deregistered_attempting_registration; }, 5'000));
    EXPECT_TRUE(r.ue.usim_valid());
    EXPECT_EQ(r.ue.attempt_counter(), 1);
    EXPECT_EQ(field(r.named("nas.reg.abort").at(0), "reason"), "released");
}

TEST(Mm, Clause5_4_2_5_AlteredReplayedCapabilitiesAreRejectedWith23) {
    Profile p;
    p.tamper_replayed_capabilities = true;
    Rig r(p);
    r.power_on();
    r.ue.register_initial();
    ASSERT_TRUE(r.run_until([&] { return r.ue.state() == MmState::deregistered_attempting_registration; }, 10'000));
    EXPECT_EQ(r.failures(), "");
    EXPECT_EQ(field(r.named("nas.smc.reject").at(0), "cause"), "23");
    EXPECT_EQ(r.ue.security(), nullptr);   // the command's context was never taken into use
    EXPECT_EQ(r.ue.attempt_counter(), 1);
    EXPECT_TRUE(r.ue.running(MmTimer::t3511));
}

TEST(Mm, Clause5_4_2_3_NullIntegrityIsRefusedWith24) {
    Profile p;
    p.ia = 0;
    Rig r(p);
    r.power_on();
    r.ue.register_initial();
    ASSERT_TRUE(r.run_until([&] { return !r.named("nas.smc.reject").empty(); }, 10'000));
    EXPECT_EQ(r.failures(), "");
    EXPECT_EQ(field(r.named("nas.smc.reject").at(0), "cause"), "24");
}

TEST(Mm, Clause5_4_2_3_TheImeisvGoesBackOnlyWhenAskedFor) {
    Profile p;
    p.imeisv_request = false;
    Rig r(p);
    ASSERT_TRUE(r.registered());
    EXPECT_EQ(r.failures(), "");
    EXPECT_EQ(field(r.named("nas.smc.complete").at(0), "imeisv"), "0");
}

TEST(Mm, Clause5_4_2_3_RinmrBringsTheWholeRegistrationRequestBack) {
    Profile p;
    p.rinmr = true;
    Rig r(p);
    ASSERT_TRUE(r.registered());
    EXPECT_EQ(r.failures(), "");
    EXPECT_EQ(field(r.named("nas.smc.complete").at(0), "container"), "1");
}

TEST(Mm, Clause4_4_4_2_APlainRegistrationAcceptAfterTheCommandIsDiscarded) {
    Profile p;
    p.registration = Profile::Registration::accept_plain;
    Rig r(p);
    r.power_on();
    r.ue.register_initial();
    ASSERT_TRUE(r.run_until([&] { return !r.named("nas.sec.discard").empty(); }, 10'000));
    EXPECT_EQ(r.ue.state(), MmState::registered_initiated);
    ASSERT_TRUE(r.run_until([&] { return r.ue.state() == MmState::deregistered_attempting_registration; }, 20'000));
    EXPECT_EQ(field(r.named("nas.reg.abort").at(0), "reason"), "T3510");
    EXPECT_EQ(r.failures(), "");
}

TEST(Mm, Clause5_5_1_2_7_FiveFailedAttemptsStartT3502AndItsExpiryStartsAgain) {
    Profile p;
    p.registration = Profile::Registration::silent;
    Rig r(p);
    r.power_on();
    r.ue.register_initial();
    const Millis t0 = r.loop.now();
    ASSERT_TRUE(r.run_until([&] { return r.ue.running(MmTimer::t3502); }, 200'000));
    // Five attempts: 5 × T3510 (15 s) and 4 × T3511 (10 s) between them.
    EXPECT_EQ(r.amf.count_uplink("REGISTRATION REQUEST"), 5u);
    EXPECT_EQ(r.loop.now() - t0, 5 * 15'000 + 4 * 10'000 + 0 * 1);
    EXPECT_EQ(r.ue.attempt_counter(), 5);
    EXPECT_EQ(r.ue.state(), MmState::deregistered_attempting_registration);
    EXPECT_EQ(r.ue.update_status(), proc::ue::UpdateStatus::u2_not_updated);
    EXPECT_FALSE(r.ue.running(MmTimer::t3511));
    ASSERT_TRUE(r.run_until([&] { return r.amf.count_uplink("REGISTRATION REQUEST") == 6; }, 720'000 + 1'000));
    EXPECT_EQ(r.ue.attempt_counter(), 0);   // reset when T3502 expired (§5.5.1.2.1)
    EXPECT_EQ(r.failures(), "");
    EXPECT_EQ(r.ue.unlisted_transitions(), 0u);
}

TEST(Mm, Clause5_5_1_2_5_Reject7MakesTheUsimInvalidForFiveGs) {
    Profile p;
    p.registration = Profile::Registration::reject;
    p.reject_cause = 7;
    Rig r(p);
    r.power_on();
    r.ue.register_initial();
    ASSERT_TRUE(r.run_until([&] { return r.ue.state() == MmState::deregistered_no_supi; }, 10'000));
    EXPECT_EQ(r.failures(), "");
    EXPECT_FALSE(r.ue.usim_valid());
    EXPECT_FALSE(r.ue.guti());
    EXPECT_EQ(r.ue.security(), nullptr);   // ngKSI deleted
    EXPECT_EQ(r.ue.update_status(), proc::ue::UpdateStatus::u3_roaming_not_allowed);
    r.loop.run_for(5'000);   // the network's release finds the UE already out of 5GMM-REGISTERED-INITIATED
    EXPECT_EQ(r.ue.state(), MmState::deregistered_no_supi);
}

TEST(Mm, Clause5_5_1_2_7d_Reject111SetsTheAttemptCounterToFive) {
    Profile p;
    p.registration = Profile::Registration::reject;
    p.reject_cause = 111;
    Rig r(p);
    r.power_on();
    r.ue.register_initial();
    ASSERT_TRUE(r.run_until([&] { return r.ue.running(MmTimer::t3502); }, 10'000));
    EXPECT_EQ(r.ue.attempt_counter(), 5);
    EXPECT_FALSE(r.ue.guti());
    EXPECT_EQ(r.failures(), "");
}

TEST(Mm, Clause5_5_2_2_ANormalDeregistrationIsAccepted) {
    Rig r;
    ASSERT_TRUE(r.registered());
    ASSERT_TRUE(r.run_until([&] { return r.amf.registered(); }, 1'000));
    r.ue.deregister(false);
    EXPECT_EQ(r.ue.state(), MmState::deregistered_initiated);
    EXPECT_TRUE(r.ue.running(MmTimer::t3521));
    ASSERT_TRUE(r.run_until([&] { return r.ue.state() == MmState::deregistered_normal_service; }, 5'000));
    EXPECT_FALSE(r.ue.running(MmTimer::t3521));
    EXPECT_EQ(r.named("nas.dereg.accept").size(), 1u);
    EXPECT_EQ(r.failures(), "");
    EXPECT_EQ(r.ue.unlisted_transitions(), 0u);
}

TEST(Mm, Clause5_5_2_2_ASwitchOffAwaitsNoAccept) {
    Rig r;
    ASSERT_TRUE(r.registered());
    ASSERT_TRUE(r.run_until([&] { return r.amf.registered(); }, 1'000));
    r.ue.deregister(true);
    EXPECT_EQ(r.ue.state(), MmState::null);   // at once: no accept awaited
    r.loop.run_for(5'000);
    EXPECT_EQ(r.amf.count_uplink("DEREGISTRATION REQUEST"), 1u);
    EXPECT_EQ(field(r.named("nas.dereg.sent").at(0), "switch_off"), "1");
    EXPECT_EQ(r.link.network_releases, 0);   // the stub sent nothing back
    EXPECT_EQ(r.failures(), "");
}

TEST(Mm, Clause5_5_2_2_6c_T3521RetransmitsFourTimesThenTheUeGivesUp) {
    Profile p;
    p.deregistration = Profile::Deregistration::silent;
    Rig r(p);
    ASSERT_TRUE(r.registered());
    ASSERT_TRUE(r.run_until([&] { return r.amf.registered(); }, 1'000));
    r.ue.deregister(false);
    const Millis t0 = r.loop.now();
    ASSERT_TRUE(r.run_until([&] { return r.ue.state() == MmState::deregistered_normal_service; }, 100'000));
    EXPECT_EQ(r.loop.now() - t0, 5 * 15'000);
    EXPECT_EQ(r.amf.count_uplink("DEREGISTRATION REQUEST"), 5u);   // each with the next uplink COUNT (checked)
    EXPECT_EQ(field(r.named("nas.dereg.sent").at(4), "transmission"), "5");
    EXPECT_EQ(field(r.named("nas.dereg.abort").at(0), "reason"), "T3521");
    EXPECT_EQ(r.link.local_releases, 1);
    EXPECT_EQ(r.failures(), "");
}

TEST(Mm, Clause7_4_AnUnknownMessageTypeIsAnsweredWithStatus97AndAStatusChangesNothing) {
    Rig r;
    ASSERT_TRUE(r.registered());
    ASSERT_TRUE(r.run_until([&] { return r.amf.registered(); }, 1'000));
    r.amf.send_protected(*from_hex("7e00ff"));   // message type 0xFF: none in Table 9.7.1
    ASSERT_TRUE(r.run_until([&] { return r.amf.count_uplink("5GMM STATUS") == 1; }, 1'000));
    const auto ul = r.named("nas.mm.status");
    ASSERT_EQ(ul.size(), 1u);
    EXPECT_EQ(field(ul[0], "cause"), "97");
    r.amf.send_protected(*from_hex("7e00646f"));   // 5GMM STATUS #111
    ASSERT_TRUE(r.run_until([&] { return r.named("nas.mm.status").size() == 2; }, 1'000));
    EXPECT_EQ(field(r.named("nas.mm.status").at(1), "direction"), "dl");
    EXPECT_EQ(r.ue.state(), MmState::registered_normal_service);
    EXPECT_EQ(r.failures(), "");
}

TEST(Mm, Clause4_4_4_2_APlainMessageAfterSecureExchangeIsNotProcessed) {
    Rig r;
    ASSERT_TRUE(r.registered());
    r.amf.send_plain(*from_hex("7e0046"));   // DEREGISTRATION ACCEPT, plain: only before secure exchange
    ASSERT_TRUE(r.run_until([&] { return !r.named("nas.sec.discard").empty(); }, 1'000));
    EXPECT_EQ(r.ue.state(), MmState::registered_normal_service);
    EXPECT_EQ(r.amf.count_uplink("5GMM STATUS"), 0u);
}

TEST(Mm, Clause5_1_3_2_1_TheStateTableNamesEachUeStateOfTheSpec) {
    std::ifstream in(std::string(KSIM_SOURCE_DIR) + "/spec/nas/24501/mm_states_ue.tsv");
    ASSERT_TRUE(in);
    std::set<std::string> spec;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#' || line.rfind("clause\t", 0) == 0) {
            continue;
        }
        std::istringstream cols(line);
        std::string clause, kind, state;
        std::getline(cols, clause, '\t');
        std::getline(cols, kind, '\t');
        std::getline(cols, state, '\t');
        spec.insert(state);
    }
    std::set<std::string> ours;
    for (MmState s : proc::ue::all_mm_states()) {
        const std::string name = proc::ue::mm_state_name(s);
        ours.insert(name);
        if (const auto dot = name.find('.'); dot != std::string::npos) {
            ours.insert(name.substr(0, dot));   // the main state of a substate
        }
    }
    EXPECT_EQ(ours, spec);
    for (const auto& t : proc::ue::mm_transitions()) {
        EXPECT_NE(std::string(t.clause), "");
        EXPECT_NE(t.from, t.to);
    }
}

/// The K_gNB the AMF would put in the INITIAL CONTEXT SETUP: its own K_AMF and
/// the uplink COUNT of the SECURITY MODE COMPLETE it received (0 after 5G AKA).
SecretBytes amf_kgnb(const Rig& r) {
    const proc::ue::NasSecurityContext* ctx = r.amf.security();
    return ctx != nullptr ? crypto::keys5g::kgnb(ctx->kamf(), 0) : SecretBytes{};
}

TEST(Mm, Clause6_8_1_2_KgnbTakesTheUplinkCountOfTheSecurityModeComplete) {
    Rig r;
    ASSERT_TRUE(r.registered());
    ASSERT_TRUE(r.run_until([&] { return r.amf.registered(); }, 1'000));
    auto k = r.ue.kgnb();   // TS 33.501 6.8.1.2.2: not the next uplink COUNT (2 by now)
    ASSERT_TRUE(k);
    EXPECT_TRUE(ct_equal(*k, amf_kgnb(r)));
    ASSERT_TRUE(r.ue.s_tmsi());
    EXPECT_EQ(*r.ue.s_tmsi(), (std::uint64_t{1} << 38) | (std::uint64_t{1} << 32) | 1u);   // set 1, pointer 1, TMSI 1
}

TEST(CoreStub, ItsProfilesLoadAndAnUnknownKeyIsAnError) {
    const std::string dir = std::string(KSIM_SOURCE_DIR) + "/tests/corestub/profiles/";
    const Profile d = Profile::from_yaml(Yaml::load_file(dir + "default.yaml"));
    EXPECT_EQ(d.challenges, std::vector<C>{C::ok});
    EXPECT_EQ(d.t3512_s, 3600);
    const Profile r = Profile::from_yaml(Yaml::load_file(dir + "resync.yaml"));
    EXPECT_EQ(r.challenges, (std::vector<C>{C::stale_sqn, C::ok}));
    Rig rig(r);
    ASSERT_TRUE(rig.registered());
    EXPECT_EQ(rig.amf.resyncs(), 1);
    EXPECT_THROW(Profile::from_yaml(Yaml::parse("challenges: [ok]\nnot_a_key: 1\n")), YamlError);
    EXPECT_THROW(Profile::from_yaml(Yaml::parse("challenges: [maybe]\n")), YamlError);
}

// ---- mutants (verification.md §1): each one's planted fault must fail a check.

TEST(Mm, Mutant_null_suci_full_imsi_FailsTheSuciCheck) {
    if (!kMutationsBuild) {
        GTEST_SKIP() << "mutant build only";
    }
    testing::MutantScope m("null_suci_full_imsi");
    Rig r;
    r.power_on();
    r.ue.register_initial();
    r.loop.run_for(5'000);
    EXPECT_NE(r.failures().find("MSIN of a known subscriber"), std::string::npos) << r.failures();
    EXPECT_NE(r.ue.state(), MmState::registered_normal_service);
}

TEST(Mm, Mutant_kgnb_wrong_ul_count_GivesAKgnbTheAmfDoesNotHave) {
    if (!kMutationsBuild) {
        GTEST_SKIP() << "mutant build only";
    }
    testing::MutantScope m("kgnb_wrong_ul_count");
    Rig r;
    ASSERT_TRUE(r.registered());
    ASSERT_TRUE(r.run_until([&] { return r.amf.registered(); }, 1'000));
    auto k = r.ue.kgnb();
    ASSERT_TRUE(k);
    EXPECT_FALSE(ct_equal(*k, amf_kgnb(r)));   // the AS SMC's MAC-I then fails (UeRrc.Clause5_3_4_3)
}

TEST(Mm, Mutant_kamf_input_sbi_spelling_FailsTheSecurityModeCommand) {
    if (!kMutationsBuild) {
        GTEST_SKIP() << "mutant build only";
    }
    testing::MutantScope m("kamf_input_sbi_spelling");
    Rig r;
    r.power_on();
    r.ue.register_initial();
    r.loop.run_for(10'000);
    EXPECT_FALSE(r.named("nas.sec.discard").empty());   // the command's MAC does not verify under the wrong K_AMF
    EXPECT_EQ(r.amf.count_uplink("SECURITY MODE COMPLETE"), 0u);
    EXPECT_NE(r.ue.state(), MmState::registered_normal_service);
}

} // namespace
} // namespace ksim::proctest
