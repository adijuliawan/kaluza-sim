// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// EAP-AKA' in virtual time (P1 N12 follow-up; TS 24.501 5.4.1.2, TS 33.501
// 6.1.3.1 and Annex F, RFC 5448/9048): the UE's 5GMM entity and its soft card
// against the core stub playing the AUSF. The stub checks AT_MAC under K_aut
// and RES against XRES, and the SECURITY MODE COMMAND verifies only with the
// K_AMF that EMSK gives, so a passing registration proves the key chain.

#include <gtest/gtest.h>

#include "rig.hpp"

namespace ksim::proctest {
namespace {

using corestub::Profile;
using proc::ue::MmState;
using C = Profile::Challenge;

Profile eap(std::vector<C> challenges = {C::ok}) {
    Profile p;
    p.eap_aka_prime = true;
    p.challenges = std::move(challenges);
    return p;
}

std::string field(const Event& e, std::string_view key) {
    const std::string* v = e.find(key);
    return v != nullptr ? *v : std::string("<none>");
}

std::vector<std::string> subtypes(const Rig& r) {
    std::vector<std::string> out;
    for (const auto& e : r.named("nas.auth.eap.response")) {
        out.push_back(field(e, "subtype"));
    }
    return out;
}

TEST(Eap, Ts33501_6_1_3_1_ARegistrationWithEapAkaPrimeEndsRegistered) {
    Rig r(eap());
    ASSERT_TRUE(r.registered()) << r.failures();
    EXPECT_EQ(r.failures(), "");
    EXPECT_EQ(subtypes(r), std::vector<std::string>{"challenge"});
    EXPECT_EQ(r.named("nas.auth.eap.success").size(), 1u);   // in the SECURITY MODE COMMAND
    EXPECT_EQ(r.named("nas.auth.response").size(), 0u);      // no 5G AKA RES*
    EXPECT_EQ(r.amf.challenges(), 1);
}

TEST(Eap, Ts24501_5_4_1_2_2_4_AnAutnTheUsimRefusesGetsAnAuthenticationReject) {
    Rig r(eap({C::bad_mac, C::ok}));
    ASSERT_TRUE(r.registered()) << r.failures();
    EXPECT_EQ(r.failures(), "");
    EXPECT_EQ(subtypes(r), (std::vector<std::string>{"authentication-reject", "challenge"}));
    EXPECT_EQ(field(r.named("nas.auth.eap.response").front(), "error"), "1");
}

TEST(Eap, Ts24501_5_4_1_2_2_4_AStaleSqnGetsASynchronizationFailureWithAuts) {
    Rig r(eap({C::stale_sqn, C::ok}));
    ASSERT_TRUE(r.registered()) << r.failures();
    EXPECT_EQ(r.failures(), "");   // AT_AUTS verified and AT_KDF copied
    EXPECT_EQ(subtypes(r), (std::vector<std::string>{"synchronization-failure", "challenge"}));
    EXPECT_EQ(r.amf.resyncs(), 1);
}

TEST(Eap, Ts33501_6_1_3_1_AChallengeWithoutTheSeparationBitIsRefused) {
    Rig r(eap({C::non_5g, C::ok}));
    ASSERT_TRUE(r.registered()) << r.failures();
    EXPECT_EQ(r.failures(), "");
    EXPECT_EQ(subtypes(r), (std::vector<std::string>{"authentication-reject", "challenge"}));
}

TEST(Eap, Ts24501_5_4_1_2_2_2_AnotherNetworkNameFailsTheSnnCheck) {
    Profile p = eap();
    p.eap_network_name = "5G:mnc070.mcc999.3gppnetwork.org";
    Rig r(p);
    ASSERT_TRUE(r.registered()) << r.failures();
    EXPECT_EQ(r.failures(), "");
    EXPECT_EQ(subtypes(r), (std::vector<std::string>{"authentication-reject", "challenge"}));
    EXPECT_EQ(field(r.named("nas.auth.eap.response").front(), "why"), "the serving network name check failed");
}

TEST(Eap, Ts24501_5_4_1_2_2_12_a_AKeyDerivationFunctionOtherThan1IsAnIncorrectAutn) {
    Profile p = eap();
    p.eap_kdf = 2;
    Rig r(p);
    ASSERT_TRUE(r.registered()) << r.failures();
    EXPECT_EQ(r.failures(), "");
    EXPECT_EQ(subtypes(r), (std::vector<std::string>{"authentication-reject", "challenge"}));
    EXPECT_EQ(field(r.named("nas.auth.eap.response").front(), "why"), "the key derivation function is not 1");
}

TEST(Eap, Ts24501_5_4_1_2_2_4_AnAtMacThatDoesNotVerifyGetsAClientError) {
    Profile p = eap();
    p.eap_bad_at_mac = true;
    Rig r(p);
    ASSERT_TRUE(r.registered()) << r.failures();
    EXPECT_EQ(r.failures(), "");
    EXPECT_EQ(subtypes(r), (std::vector<std::string>{"client-error", "challenge"}));
}

TEST(Eap, Ts24501_8_2_3_AnEapSuccessInAnAuthenticationResultMakesTheKeysCount) {
    Profile p = eap();
    p.eap_result_message = true;
    Rig r(p);
    ASSERT_TRUE(r.registered()) << r.failures();
    EXPECT_EQ(r.failures(), "");
    const auto success = r.named("nas.auth.eap.success");
    const auto smc = r.named("nas.smc.complete");
    ASSERT_EQ(success.size(), 1u);
    ASSERT_EQ(smc.size(), 1u);
    EXPECT_LT(success.front().seq, smc.front().seq);
}

TEST(Eap, Ts24501_5_4_1_2_5_AnAuthenticationRejectWithEapFailureMakesTheUsimInvalid) {
    Rig r(eap({C::bad_mac, C::reject}));
    r.power_on();
    r.ue.register_initial();
    ASSERT_TRUE(r.run_until([&] { return r.ue.state() == MmState::deregistered_no_supi; }, 10'000)) << r.failures();
    EXPECT_FALSE(r.ue.usim_valid());
    EXPECT_EQ(r.named("nas.auth.reject").size(), 1u);
}

TEST(Eap, Ts24501_5_4_1_2_4_5_e_ThreeErrorsInARowAndTheNetworkFailedTheCheck) {
    Rig r(eap({C::bad_mac, C::bad_mac, C::bad_mac, C::ok}));
    r.power_on();
    r.ue.register_initial();
    ASSERT_TRUE(r.run_until([&] { return !r.named("nas.auth.network_failed").empty(); }, 20'000)) << r.failures();
    EXPECT_EQ(subtypes(r), (std::vector<std::string>{"authentication-reject", "authentication-reject",
                                                     "authentication-reject"}));
    EXPECT_EQ(field(r.named("nas.auth.eap.response").back(), "sent"), "0");
}

} // namespace
} // namespace ksim::proctest
