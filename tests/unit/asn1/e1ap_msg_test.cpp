// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The typed E1AP builders and readers (P1 N10; TS 37.483 j40): every builder's
// output decodes back to the same struct; the E1AP vectors of independent
// producers read where their procedure is in the P1 set; the UP keys are
// zeroed for captures.

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <sstream>

#include "e1ap_samples.hpp"

namespace ksim::e1ap {
namespace {

TEST(E1apMsg, EveryBuilderRoundTrips) {
    for (const auto& s : samples::all()) {
        auto wire = encode(s.pdu);
        ASSERT_TRUE(wire) << s.name << ": " << wire.error().what;
        auto back = decode(*wire);
        ASSERT_TRUE(back) << s.name << ": " << back.error().what;
        EXPECT_EQ(*back, s.pdu) << s.name;
    }
}

TEST(E1apMsg, RedactionZeroesTheUpKeys) {
    for (const auto& s : samples::all()) {
        auto wire = encode(s.pdu);
        ASSERT_TRUE(wire);
        auto r = redact_keys(*wire);
        ASSERT_TRUE(r) << s.name;
        if (std::holds_alternative<BearerContextSetupRequest>(s.pdu)) {
            EXPECT_EQ(r->keys, 2u);
            for (const Bytes& key : {Bytes(4, 0x5A), Bytes(4, 0xA5)}) {
                EXPECT_EQ(std::search(r->pdu.begin(), r->pdu.end(), key.begin(), key.end()), r->pdu.end());
            }
            auto back = decode(r->pdu);
            ASSERT_TRUE(back);
            EXPECT_EQ(std::get<BearerContextSetupRequest>(*back).security.enc_key, Bytes(16, 0));
        } else {
            EXPECT_EQ(r->keys, 0u) << s.name;
            EXPECT_EQ(r->pdu, *wire) << s.name;
        }
    }
}

TEST(E1apMsg, InputsOutOfRangeAreRefused) {
    BearerContextSetupRequest r;
    r.security = Security{2, 2, Bytes(15, 0), Bytes(16, 0)};   // a 120-bit key
    r.sessions = {SessionToSetup{1, "ipv4", Snssai{}, {}, {}, {DrbToSetup{1, true, true, true, 18, {QosFlow{}}}}}};
    EXPECT_FALSE(encode(r));
    r.security.enc_key = Bytes(16, 0);
    r.sessions[0].drbs[0].flows.clear();   // a DRB without flows
    EXPECT_FALSE(encode(r));
    EXPECT_FALSE(encode(E1SetupRequest{1, 1ULL << 36, "", {{PlmnId{}, {}}}}));
}

// P2 Q4 (KS-E1AP-D1; TS 37.483 9.2.2.1): ActivityNotificationLevel "ue" carries the UE
// Inactivity Timer, and a request without it is not built; another level needs none.
TEST(E1apMsg, TheUeLevelCarriesTheUeInactivityTimer) {
    BearerContextSetupRequest r;
    r.security = Security{2, 2, Bytes(16, 0), Bytes(16, 0)};
    r.sessions = {SessionToSetup{1, "ipv4", Snssai{}, {}, {}, {DrbToSetup{1, true, true, true, 18, {QosFlow{}}}}}};
    r.ue_inactivity_s = 15;
    auto w = encode(r);
    ASSERT_TRUE(w);
    auto back = decode(*w);
    ASSERT_TRUE(back);
    const auto& got = std::get<BearerContextSetupRequest>(*back);
    EXPECT_EQ(got.activity_level, "ue");
    EXPECT_EQ(got.ue_inactivity_s, std::optional<std::uint16_t>(15));
    r.ue_inactivity_s.reset();
    EXPECT_FALSE(encode(r));
    r.ue_inactivity_s = 0;
    EXPECT_FALSE(encode(r));   // 1..7200 s
    r.activity_level = "pdu-session";
    r.ue_inactivity_s.reset();
    back = decode(*encode(r));
    ASSERT_TRUE(back);
    EXPECT_FALSE(std::get<BearerContextSetupRequest>(*back).ue_inactivity_s);
    r.activity_level = "cell";
    EXPECT_FALSE(encode(r));
}

TEST(E1apMsg, IndependentProducersVectorsReadOrAreOutsideTheP1Set) {
    std::ifstream in(std::string(KSIM_SOURCE_DIR) + "/tests/vectors/e1ap/index.tsv");
    std::string line;
    bool head = false;
    int read = 0;
    int other = 0;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') {
            continue;
        }
        if (!head) {
            head = true;
            continue;
        }
        std::vector<std::string> cols;
        std::istringstream ss(line);
        std::string c;
        while (std::getline(ss, c, '\t')) {
            cols.push_back(c);
        }
        auto wire = from_hex(cols.back());
        if (!wire || cols.at(2) == "(undecodable)") {
            continue;
        }
        auto d = decode(*wire);
        EXPECT_TRUE(d || d.error().code == Errc::unsupported) << cols.at(0) << " " << cols.at(2) << ": "
                                                               << (d ? "" : d.error().what);
        (d ? read : other) += 1;
    }
    std::printf("E1AP corpus: %d read, %d outside the P1 set\n", read, other);
    EXPECT_GE(read, 9);
}

} // namespace
} // namespace ksim::e1ap
