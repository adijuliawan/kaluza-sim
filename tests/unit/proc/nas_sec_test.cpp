// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Spec-row tests for the UE's 5G NAS security context (P1 N4; TS 24.501 j80
// §4.4.3, §4.4.4.2, §4.4.6; TS 33.501 §6.4). The expected messages were made
// outside this code: K_NASint and K_NASenc by tests/oracles/keychain.py (our
// pure-Python reading of TS 33.501 Annex A) for K 000102…0f, OPc f0e0…00,
// RAND 0011…ff, SQN 000000000021, AMF 8000, SUPI 001010000300001; the MACs
// (AES-CMAC, 128-NIA2) and ciphertexts (AES-CTR, 128-NEA2) by the Python
// `cryptography` package, with BEARER 1 (the NAS connection identifier of
// 3GPP access, TS 33.501 §6.4.2.1) and DIRECTION 0 up, 1 down. Until P1 N8
// they were made with BEARER 0, the same misreading as the code's (KS-SEC-D2).

#include <gtest/gtest.h>

#include "codec/nas/nas.hpp"
#include "proc/ue/nas_sec/nas_sec.hpp"

namespace ksim::proc::ue {
namespace {

Bytes h(const char* s) { return *from_hex(s); }

NasSecurityContext ctx() {
    auto c = NasSecurityContext::derive(
        nas::ie::NgKsi{false, 1},
        SecretBytes::from_hex("8006a0fa522664dc183602689c946c00aa657f405b7eb62d194b1bf5904922b7").value(), 2, 2);
    EXPECT_TRUE(c);
    return std::move(*c);
}

TEST(NasSecurity, Clause4_4_3_TheSecurityModeCompleteMatchesTheIndependentVector) {
    auto c = ctx();
    auto wire = c.protect(h("7e005e"), Sht::integrity_ciphered_new);
    ASSERT_TRUE(wire);
    EXPECT_EQ(to_hex(*wire), "7e04139c9efc0003f9b4");
    EXPECT_EQ(c.ul_count(), 1u);
}

TEST(NasSecurity, Clause4_4_3_ACommandAndACipheredMessageVerifyAndDecipher) {
    auto c = ctx();
    auto smc = c.unprotect(h("7e03d0955c87007e005d2201028080e1"));
    ASSERT_EQ(smc.verdict, Verdict::ok) << verdict_name(smc.verdict);
    EXPECT_EQ(smc.sht, Sht::integrity_new);
    EXPECT_EQ(to_hex(smc.plain), "7e005d2201028080e1");
    EXPECT_EQ(c.dl_count(), 0u);
    auto dl = c.unprotect(h("7e02423e7f1401d95fc9d524372b47c3128490eb702fac4134"));
    ASSERT_EQ(dl.verdict, Verdict::ok) << verdict_name(dl.verdict);
    EXPECT_EQ(to_hex(dl.plain), "7e00680112000f2e0101c1ffff91a1280100");
    EXPECT_EQ(c.dl_count(), 1u);
}

TEST(NasSecurity, Clause4_4_3_2_AReplayIsDiscardedAndChangesNothing) {
    auto c = ctx();
    const Bytes smc = h("7e03d0955c87007e005d2201028080e1");
    ASSERT_EQ(c.unprotect(smc).verdict, Verdict::ok);
    EXPECT_EQ(c.unprotect(smc).verdict, Verdict::discard_mac);   // COUNT 0 again: estimated as 256, MAC fails
    EXPECT_EQ(c.dl_count(), 0u);
    Bytes tampered = h("7e02423e7f1401d95fc9d524372b47c3128490eb702fac4134");
    tampered[10] ^= 0x01;
    EXPECT_EQ(c.unprotect(tampered).verdict, Verdict::discard_mac);
    EXPECT_EQ(c.unprotect(h("7e02423e7f1401d95fc9d524372b47c3128490eb702fac4134")).verdict, Verdict::ok);
    EXPECT_EQ(c.unprotect(h("7e02")).verdict, Verdict::discard_malformed);
}

TEST(NasSecurity, Clause4_4_3_1_TheOverflowCounterIsEstimatedPastAWrap) {
    auto c = ctx();
    c.restore_counts(0, 0xFF);   // the last verified downlink COUNT: overflow 0, SQN 255
    auto m = c.unprotect(h("7e0186ef7990017e005d2201028080e1"));   // SQN 1: COUNT 257
    ASSERT_EQ(m.verdict, Verdict::ok);
    EXPECT_EQ(m.count, 257u);
    EXPECT_EQ(c.dl_count(), 257u);
    // Uplink: after 0xFFFFFF the COUNT wraps to 0 (the context should have been
    // renewed long before, §4.4.3.5).
    c.restore_counts(0xFFFFFF, 257);
    ASSERT_TRUE(c.protect(h("7e005e"), Sht::integrity));
    EXPECT_EQ(c.ul_count(), 0u);
}

TEST(NasSecurity, TheAlgorithmsP1DoesNotOfferAreRefused) {
    auto k = [] {
        return SecretBytes::from_hex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").value();
    };
    EXPECT_EQ(NasSecurityContext::derive(nas::ie::NgKsi{false, 1}, k(), 3, 2).error().code, Errc::unsupported);   // 5G-EA3
    EXPECT_EQ(NasSecurityContext::derive(nas::ie::NgKsi{false, 1}, k(), 2, 0).error().code, Errc::unsupported);   // 5G-IA0
    EXPECT_EQ(NasSecurityContext::derive(nas::ie::NgKsi{false, 7}, k(), 2, 2).error().code, Errc::invalid_argument);
}

nas::Message msg(const char* hex) {
    auto m = nas::decode(h(hex));
    EXPECT_TRUE(m) << hex;
    return m ? *m : nas::Message{};
}

TEST(NasSecurity, Clause4_4_4_2_WhatTheUeProcessesUnprotected) {
    EXPECT_TRUE(processed_unprotected(msg("7e005b01"), false));          // IDENTITY REQUEST for the SUCI
    EXPECT_FALSE(processed_unprotected(msg("7e005b02"), false));         // … for the 5G-GUTI: no
    EXPECT_TRUE(processed_unprotected(msg("7e00440b"), false));          // REGISTRATION REJECT #11
    EXPECT_FALSE(processed_unprotected(msg("7e00444c"), false));         // … #76: no
    EXPECT_TRUE(processed_unprotected(msg("7e004d0a"), false));          // SERVICE REJECT #10
    EXPECT_FALSE(processed_unprotected(msg("7e004d4e"), false));         // … #78: no
    EXPECT_TRUE(processed_unprotected(msg("7e0046"), false));            // DEREGISTRATION ACCEPT
    EXPECT_FALSE(processed_unprotected(msg("7e0043"), false));           // REGISTRATION COMPLETE is never processed plain
    EXPECT_FALSE(processed_unprotected(msg("7e005b01"), true));          // once secure exchange is up: nothing
}

TEST(NasSecurity, Clause4_4_6_AnInitialRegistrationRequestKeepsOnlyItsCleartextIes) {
    // REGISTRATION REQUEST: initial, ngKSI 7, a null SUCI, 5GMM capability (not
    // cleartext), UE security capability (cleartext).
    const auto m = msg("7e004179000d0100f110000000000000000001" "100107" "2e0480e0e0e0");
    auto s = split_initial(m);
    ASSERT_TRUE(s);
    EXPECT_TRUE(s->has_non_cleartext);
    auto enc = nas::encode(s->cleartext);
    ASSERT_TRUE(enc);
    EXPECT_EQ(to_hex(*enc), "7e004179000d0100f110000000000000000001" "2e0480e0e0e0");
    // A message with only cleartext IEs needs no container.
    auto t = split_initial(msg("7e004179000d0100f110000000000000000001" "2e0480e0e0e0"));
    ASSERT_TRUE(t);
    EXPECT_FALSE(t->has_non_cleartext);
    EXPECT_FALSE(split_initial(msg("7e005e")));   // SECURITY MODE COMPLETE is not an initial message
}

} // namespace
} // namespace ksim::proc::ue
