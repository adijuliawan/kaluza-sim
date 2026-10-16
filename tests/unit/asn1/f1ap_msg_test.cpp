// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The typed F1AP builders and readers (P1 N7; TS 38.473 j40): every builder's
// output decodes back to the same struct; the F1AP vectors of independent
// producers in tests/vectors/f1ap (OCUDU and others) read wherever their
// procedure is in the P1 set, and are never malformed to the reader; inputs
// out of range are refused.

#include <gtest/gtest.h>

#include <cstdio>
#include <fstream>
#include <set>
#include <sstream>

#include "f1ap_samples.hpp"

namespace ksim::f1ap {
namespace {

TEST(F1apMsg, EveryBuilderRoundTrips) {
    for (const auto& s : samples::all()) {
        auto wire = encode(s.pdu);
        ASSERT_TRUE(wire) << s.name << ": " << wire.error().what;
        auto back = decode(*wire);
        ASSERT_TRUE(back) << s.name << ": " << back.error().what;
        EXPECT_EQ(*back, s.pdu) << s.name;
        EXPECT_TRUE(peek(*wire)) << s.name;
    }
}

TEST(F1apMsg, PeekReadsTheProcedureAndTheUeIds) {
    auto h = peek(*encode(UlRrcMessageTransfer{7, 1, 1, {0x00, 0x00, 0x10, 0, 0, 0, 0}}));
    ASSERT_TRUE(h);
    EXPECT_EQ(h->procedure, 13);
    EXPECT_EQ(h->cu_ue, 7u);
    EXPECT_EQ(h->du_ue, 1u);
}

TEST(F1apMsg, InputsOutOfRangeAreRefused) {
    EXPECT_FALSE(encode(F1SetupRequest{0, std::uint64_t{1} << 36, "", {}}));
    EXPECT_FALSE(encode(DlRrcMessageTransfer{1, 1, 4, {0x00}}));
    EXPECT_FALSE(encode(UlRrcMessageTransfer{1, 1, 1, {}}));
    EXPECT_FALSE(encode(UeContextReleaseCommand{1, 1, Cause{}, Bytes{0x00}, std::nullopt}));   // a container without its SRB
    EXPECT_FALSE(encode(Paging{1024, 1, {samples::kCgi}, std::nullopt}));
    EXPECT_FALSE(encode(UeContextSetupResponse{1, 1, {}, {}, {}}));
    UeContextModificationRequest m;
    m.cu_ue = 1;
    m.du_ue = 1;
    m.drbs = {DrbToSetup{1, Snssai{1, std::nullopt}, {Flow{1, 9, 8, false, true, std::nullopt, false}}, GtpTunnel{{127, 0, 0, 4}, 1}, 13, std::nullopt}};
    EXPECT_FALSE(encode(m));   // P2 Q4: a PDCP SN is 12 or 18 bits
}

// P2 Q4 (KS-F1AP-D3): the DRB item's DL PDCP SN Length, mandatory in UE Context
// Setup (TS 38.473 DRBs-ToBeSetup-ItemExtIEs), crosses the wire with the UL one.
TEST(F1apMsg, TheDrbItemCarriesItsPdcpSnLengths) {
    UeContextModificationRequest m;
    m.cu_ue = 1;
    m.du_ue = 2;
    m.drbs = {DrbToSetup{4, Snssai{1, 0x000001}, {Flow{1, 9, 8, false, true, std::nullopt, false}}, GtpTunnel{{127, 0, 0, 4}, 7}, 12, 18}};
    auto back = decode(*encode(m));
    ASSERT_TRUE(back);
    const auto& d = std::get<UeContextModificationRequest>(*back).drbs.at(0);
    EXPECT_EQ(d.dl_pdcp_sn_bits, 12);
    EXPECT_EQ(d.ul_pdcp_sn_bits, std::optional<std::uint8_t>(18));
}

TEST(F1apMsg, IndependentProducersVectorsReadOrAreOutsideTheP1Set) {
    std::ifstream in(std::string(KSIM_SOURCE_DIR) + "/tests/vectors/f1ap/index.tsv");
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
        EXPECT_TRUE(peek(*wire)) << cols.at(0);
        auto d = decode(*wire);
        EXPECT_TRUE(d || d.error().code == Errc::unsupported) << cols.at(0) << " " << cols.at(2) << ": "
                                                               << (d ? "" : d.error().what);
        (d ? read : other) += 1;
    }
    std::printf("F1AP corpus: %d read, %d outside the P1 set\n", read, other);
    EXPECT_GE(read, 12);
}

} // namespace
} // namespace ksim::f1ap
