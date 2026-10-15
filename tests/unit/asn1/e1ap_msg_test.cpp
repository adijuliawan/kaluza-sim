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
