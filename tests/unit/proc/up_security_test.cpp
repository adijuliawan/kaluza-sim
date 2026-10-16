// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The CU-CP's UP security decision (P2 Q9; TS 38.413 8.2.1.2, TS 33.501 6.6.1).

#include <gtest/gtest.h>

#include "platform/mutation.hpp"
#include "proc/ran/up_security.hpp"

namespace ksim::proc::ran {
namespace {

ngap::SecurityIndication si(const char* integrity, const char* confidentiality) {
    ngap::SecurityIndication s;
    s.integrity = integrity;
    s.confidentiality = confidentiality;
    return s;
}

TEST(UpSecurity, Ts38413_8_2_1_2_EachIndicationAsTheSpecSays) {
    const UpPolicy p;   // preferred performed, absent: ciphering only
    struct Case {
        const char* in;
        const char* cp;
        bool integrity;
        bool confidentiality;
        bool report;
    };
    for (const Case& c : {Case{"required", "required", true, true, false}, Case{"not-needed", "required", false, true, false},
                          Case{"preferred", "required", true, true, true}, Case{"required", "not-needed", true, false, false},
                          Case{"not-needed", "not-needed", false, false, false}, Case{"not-needed", "preferred", false, true, true}}) {
        const auto d = decide_up_security(si(c.in, c.cp), p);
        EXPECT_FALSE(d.refuse) << c.in << "/" << c.cp;
        EXPECT_TRUE(d.indicated);
        EXPECT_EQ(d.integrity, c.integrity) << c.in << "/" << c.cp;
        EXPECT_EQ(d.confidentiality, c.confidentiality) << c.in << "/" << c.cp;
        EXPECT_EQ(d.report, c.report) << c.in << "/" << c.cp;
    }
}

TEST(UpSecurity, PreferredFollowsTheLocalPolicy) {
    UpPolicy p;
    p.preferred_integrity = false;
    p.preferred_confidentiality = false;
    const auto d = decide_up_security(si("preferred", "preferred"), p);
    EXPECT_FALSE(d.integrity);
    EXPECT_FALSE(d.confidentiality);
    EXPECT_TRUE(d.report);   // and says so in the Security Result
}

TEST(UpSecurity, NoIndicationTakesTheLocalDefault) {
    UpPolicy p;
    auto d = decide_up_security(std::nullopt, p);
    EXPECT_FALSE(d.indicated);
    EXPECT_FALSE(d.integrity);
    EXPECT_TRUE(d.confidentiality);
    EXPECT_FALSE(d.report);
    p.absent_integrity = true;
    EXPECT_TRUE(decide_up_security(std::nullopt, p).integrity);
}

TEST(UpSecurity, Ts38413_8_2_1_2_RequiredIntegrityThisGnbCannotDoIsRefused) {
    UpPolicy p;
    p.integrity_possible = false;
    const auto d = decide_up_security(si("required", "required"), p);
    ASSERT_TRUE(d.refuse);
    EXPECT_EQ(d.refuse->group, "radioNetwork");
    EXPECT_EQ(d.refuse->value, "up-integrity-protection-not-possible");
    // "preferred" is not refused: performed without integrity, and reported.
    const auto pref = decide_up_security(si("preferred", "required"), p);
    EXPECT_FALSE(pref.refuse);
    EXPECT_FALSE(pref.integrity);
    EXPECT_TRUE(pref.report);
}

TEST(UpSecurity, Mutant_up_required_accepted_AcceptsWhatItCannotMeet) {
    if (!kMutationsBuild) {
        GTEST_SKIP() << "a mutant build's test";
    }
    const testing::MutantScope m("up_required_accepted");
    UpPolicy p;
    p.integrity_possible = false;
    EXPECT_FALSE(decide_up_security(si("required", "required"), p).refuse);
}

} // namespace
} // namespace ksim::proc::ran
