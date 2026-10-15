// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// SMS over NAS in virtual time (P1 N13), over the whole network of net_rig.hpp
// with the core stub's SMSF: SMS requested and allowed at registration, MO
// and MT (the UE writes to its own MSISDN, so both directions run on one UE),
// GSM 7-bit, UCS2 and concatenated messages, MO from idle and MT to an idle
// UE through paging, the memory full with RP-ERROR #22 and RP-SMMA, a UE
// without SMS in its subscription, and the mutant of the N13 rows.

#include <gtest/gtest.h>

#include <string>

#include "net_rig.hpp"

namespace ksim::proctest {
namespace {

const std::string kOwnMsisdn = "99900300001";   // 999 and the MSIN's last eight digits

std::string field(const Event& e, const char* k) {
    const std::string* v = e.find(k);
    return v != nullptr ? *v : std::string("<none>");
}

std::size_t count_dir(const Net& n, std::string_view name, const char* dir) {
    std::size_t c = 0;
    for (const auto& e : n.named(name)) {
        c += field(e, "dir") == dir ? 1 : 0;
    }
    return c;
}

void to_idle(Net& n) {
    const auto before = n.named("nas.mm.cm_idle").size();
    const auto ids = n.amf.ids(0);
    ASSERT_TRUE(ids.has_value());
    ASSERT_TRUE(n.cucp.request_release(ids->ran));
    ASSERT_TRUE(n.loop.run_until([&] { return n.named("nas.mm.cm_idle").size() > before &&
                                              n.amf.count("UEContextReleaseComplete") >= 1; },
                                 n.loop.now() + 2'000));
}

TEST(Sms, Ts24501_5_5_1_2_4_TheUeAsksForSmsAndTheAcceptAllowsIt) {
    Net n;
    n.register_ue();
    EXPECT_EQ(field(*n.last("nas.reg.accept"), "sms_allowed"), "1");
    EXPECT_TRUE(n.ue->sms_allowed());
    EXPECT_EQ(n.failures(), "");
}

TEST(Sms, Ts24011_5_And_6_AnMoMessageToTheUesOwnNumberComesBackOnceWithTheSameUserData) {
    Net n;
    n.register_ue();
    auto r = n.ue->sms_send(proc::ue::SmsSubmit{kOwnMsisdn, "Hello from ksim", false, false, std::nullopt});
    ASSERT_TRUE(r) << r.error().what;
    EXPECT_EQ(*r, 1u);
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("sms.mt.deliver").empty() && !n.named("sms.mo.done").empty(); },
                                 n.loop.now() + 5'000));
    n.loop.run_until([] { return false; }, n.loop.now() + 500);   // the last CP-ACKs
    EXPECT_EQ(field(*n.last("sms.mo.done"), "result"), "ack");
    const Event d = *n.last("sms.mt.deliver");   // a copy: last() reuses its buffer
    EXPECT_EQ(field(d, "from"), kOwnMsisdn);
    EXPECT_EQ(field(d, "text"), "Hello from ksim");
    EXPECT_EQ(field(d, "ud"), field(*n.last("sms.mo.submit"), "ud"));   // TS 23.040: the SC relays TP-UD
    EXPECT_EQ(n.named("sms.mt.deliver").size(), 1u);
    // Four CP-DATA and four CP-ACK: MO RP-DATA and RP-ACK, MT RP-DATA and RP-ACK.
    EXPECT_EQ(count_dir(n, "sms.cp.data", "ul") + count_dir(n, "sms.cp.data", "dl"), 4u);
    EXPECT_EQ(count_dir(n, "sms.cp.ack", "ul") + count_dir(n, "sms.cp.ack", "dl"), 4u);
    EXPECT_EQ(n.ue->sms_list().size(), 1u);
    EXPECT_EQ(n.failures(), "");   // the SMSF's checks: RP-DA, TI flags, CP-ACKs
}

TEST(Sms, Ts23038_Ucs2_AKoreanTextIsDeliveredAsSent) {
    Net n;
    n.register_ue();
    ASSERT_TRUE(n.ue->sms_send(proc::ue::SmsSubmit{kOwnMsisdn, "안녕하세요 ksim", true, false, std::nullopt}));
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("sms.mt.deliver").empty(); }, n.loop.now() + 5'000));
    EXPECT_EQ(field(*n.last("sms.mt.deliver"), "text"), "안녕하세요 ksim");
    EXPECT_EQ(field(*n.last("sms.mt.deliver"), "dcs"), "8");
    EXPECT_EQ(n.failures(), "");
}

TEST(Sms, Ts23040_9_2_3_24_1_ALongTextGoesInThreeConcatenatedParts) {
    Net n;
    n.register_ue();
    std::string text;
    for (int i = 0; text.size() < 400; ++i) {
        text += "part of a long message " + std::to_string(i) + ". ";
    }
    auto r = n.ue->sms_send(proc::ue::SmsSubmit{kOwnMsisdn, text, false, false, std::nullopt});
    ASSERT_TRUE(r);
    EXPECT_EQ(*r, 3u);
    ASSERT_TRUE(n.loop.run_until([&] { return n.named("sms.mt.deliver").size() == 3; }, n.loop.now() + 20'000)) << n.failures();
    std::string joined;
    for (const auto& e : n.named("sms.mt.deliver")) {
        joined += field(e, "text");
    }
    EXPECT_EQ(joined, text);
    EXPECT_EQ(field(n.named("sms.mt.deliver").back(), "concat"), "3/3");
    EXPECT_EQ(n.failures(), "");
}

TEST(Sms, Ts24011_6_3_1_AnMoMessageFromIdleGoesAfterAServiceRequest) {
    Net n;
    n.register_ue();
    to_idle(n);
    ASSERT_TRUE(n.ue->sms_send(proc::ue::SmsSubmit{kOwnMsisdn, "from idle", false, false, std::nullopt}));
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("sms.mt.deliver").empty(); }, n.loop.now() + 5'000)) << n.failures();
    ASSERT_FALSE(n.named("nas.sr.request").empty());
    // The CP-DATA waited in 5GMM for the service request (§5.6.1.1 c) and was answered after it.
    EXPECT_LT(n.named("nas.sr.request").front().seq, n.named("sms.cp.ack").front().seq);
    EXPECT_EQ(n.amf.nas()->count_uplink("SERVICE REQUEST"), 1u);
    EXPECT_EQ(n.failures(), "");
}

TEST(Sms, Ts23502_4_13_3_6_AnMtMessageToAnIdleUePagesItAndIsDeliveredOnce) {
    Net n;
    n.register_ue();
    to_idle(n);
    ASSERT_TRUE(n.amf.smsf().deliver(kSupi, "99900300002", "to the idle UE"));
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("sms.mt.deliver").empty(); }, n.loop.now() + 5'000)) << n.failures();
    EXPECT_GE(n.amf.pagings(), 1u);
    EXPECT_EQ(field(*n.last("nas.sr.request"), "type"), "2");   // mobile terminated services
    EXPECT_EQ(field(*n.last("sms.mt.deliver"), "text"), "to the idle UE");
    n.loop.run_until([] { return false; }, n.loop.now() + 2'000);
    EXPECT_EQ(n.named("sms.mt.deliver").size(), 1u);
    EXPECT_EQ(n.failures(), "");
}

TEST(Sms, Ts24011_6_3_2_AFullMemoryAnswersRpError22AndRpSmmaBringsTheMessage) {
    Net n;
    n.register_ue();
    n.ue->sms_memory(true);
    ASSERT_TRUE(n.amf.smsf().deliver(kSupi, "99900300002", "kept for later"));
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("sms.rp.error").empty(); }, n.loop.now() + 3'000));
    EXPECT_EQ(field(*n.last("sms.rp.error"), "cause"), "22");
    EXPECT_TRUE(n.named("sms.mt.deliver").empty());
    n.ue->sms_memory(false);   // RP-SMMA (TS 24.011 7.3.2)
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("sms.mt.deliver").empty(); }, n.loop.now() + 5'000)) << n.failures();
    EXPECT_EQ(n.named("sms.rp.smma").size(), 1u);
    EXPECT_EQ(field(*n.last("sms.mt.deliver"), "text"), "kept for later");
    EXPECT_EQ(n.failures(), "");
}

TEST(Sms, Ts24501_5_5_1_2_4_WithoutSmsInTheSubscriptionNothingIsSentUntilAnUpdateAllowsIt) {
    corestub::Profile p;
    p.sms_subscribed = false;
    Net n(p);
    n.register_ue();
    EXPECT_EQ(field(*n.last("nas.reg.accept"), "sms_allowed"), "0");
    EXPECT_FALSE(n.ue->sms_send(proc::ue::SmsSubmit{kOwnMsisdn, "not allowed", false, false, std::nullopt}).has_value());
    EXPECT_TRUE(n.named("sms.cp.data").empty());   // nothing on the air
    n.amf.set_sms_subscribed(kSupi, true);   // the subscription changes
    ASSERT_TRUE(n.ue->register_update());
    ASSERT_TRUE(n.loop.run_until([&] { return field(*n.last("nas.reg.accept"), "type") == "mobility"; },
                                 n.loop.now() + 3'000)) << n.failures();
    EXPECT_EQ(field(*n.last("nas.reg.accept"), "sms_allowed"), "1");
    EXPECT_TRUE(n.ue->sms_allowed());
    EXPECT_EQ(n.failures(), "");
}

TEST(Sms, Ts24011_5_3_2_1_PowerOffEndsTheTransactionsAndNoTimerFiresAfterwards) {
    Net n;
    n.register_ue();
    ASSERT_TRUE(n.ue->sms_send(proc::ue::SmsSubmit{kOwnMsisdn, "cut short", false, false, std::nullopt}));
    ASSERT_TRUE(n.ue->power_off_abrupt());
    n.loop.run_until([] { return false; }, n.loop.now() + 120'000);   // past TC1* x3 and TR1M
    EXPECT_TRUE(n.named("sms.cp.timeout").empty());
    EXPECT_TRUE(n.named("sms.mo.done").empty());
}

TEST(Sms, Mutant_sms_rp_da_empty_GetsAnRpErrorAndNothingIsDelivered) {
    if (!kMutationsBuild) {
        GTEST_SKIP() << "mutant build only";
    }
    testing::MutantScope m("sms_rp_da_empty");
    Net n;
    n.register_ue();
    ASSERT_TRUE(n.ue->sms_send(proc::ue::SmsSubmit{kOwnMsisdn, "no RP-DA", false, false, std::nullopt}));
    ASSERT_TRUE(n.loop.run_until([&] { return !n.named("sms.mo.done").empty(); }, n.loop.now() + 5'000));
    EXPECT_EQ(field(*n.last("sms.mo.done"), "result"), "error");
    EXPECT_TRUE(n.named("sms.mt.deliver").empty());
}

} // namespace
} // namespace ksim::proctest
