// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The typed NGAP builders and readers (P1 N7; TS 38.413 j40): every builder's
// output decodes back to the same struct; the NGAP vectors of independent
// producers in tests/vectors/ngap (free5gc, OCUDU, phone-side captures …)
// read wherever their procedure is in the P1 set; peek() reads the header
// and UE IDs of any PDU; inputs out of range are refused.

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <set>
#include <sstream>

#include "ngap_samples.hpp"

namespace ksim::ngap {
namespace {

TEST(NgapMsg, EveryBuilderRoundTrips) {
    for (const auto& s : samples::all()) {
        auto wire = encode(s.pdu);
        ASSERT_TRUE(wire) << s.name << ": " << wire.error().what;
        auto back = decode(*wire);
        ASSERT_TRUE(back) << s.name << ": " << back.error().what;
        EXPECT_EQ(*back, s.pdu) << s.name;
        auto h = peek(*wire);
        ASSERT_TRUE(h) << s.name;
    }
}

TEST(NgapMsg, RedactionZeroesTheSecurityKeyAndKeepsTheRest) {
    for (const auto& s : samples::all()) {
        auto wire = encode(s.pdu);
        ASSERT_TRUE(wire) << s.name;
        auto r = redact_keys(*wire);
        ASSERT_TRUE(r) << s.name << ": " << r.error().what;
        auto back = decode(r->pdu);
        ASSERT_TRUE(back) << s.name;
        if (const auto* ics = std::get_if<InitialContextSetupRequest>(&s.pdu)) {
            EXPECT_EQ(r->keys, 1u);
            auto want = *ics;
            want.security_key = Bytes(32, 0);
            EXPECT_EQ(*back, Pdu{want});
            // The placeholder key's octets appear nowhere in the redacted PDU.
            const Bytes a5(4, 0xA5);
            EXPECT_EQ(std::search(r->pdu.begin(), r->pdu.end(), a5.begin(), a5.end()), r->pdu.end());
        } else {
            EXPECT_EQ(r->keys, 0u) << s.name;
            EXPECT_EQ(r->pdu, *wire) << s.name;
        }
    }
    EXPECT_FALSE(redact_keys(*from_hex("ff00ff")));
}

TEST(NgapMsg, PeekReadsTheProcedureAndTheUeIds) {
    auto h = peek(*encode(DownlinkNasTransport{7, 1, {0x7e, 0x00}}));
    ASSERT_TRUE(h);
    EXPECT_EQ(h->procedure, 4);
    EXPECT_EQ(h->kind, Header::Kind::initiating);
    EXPECT_FALSE(h->reject);
    EXPECT_EQ(h->ids.amf, 7u);
    EXPECT_EQ(h->ids.ran, 1u);
    auto r = peek(*encode(UeContextReleaseCommand{9, 3, Cause{"nas", "normal-release"}}));
    ASSERT_TRUE(r);
    EXPECT_TRUE(r->reject);
    EXPECT_EQ(r->ids.amf, 9u);
    EXPECT_EQ(r->ids.ran, 3u);
}

TEST(NgapMsg, ThePlmnIdentityIsTs24008Coded) {
    EXPECT_EQ(to_hex(plmn_id("001", "01")), "00f110");
    EXPECT_EQ(to_hex(plmn_id("999", "70")), "99f907");
    EXPECT_EQ(to_hex(plmn_id("310", "410")), "130014");
}

TEST(NgapMsg, InputsOutOfRangeAreRefused) {
    NgSetupRequest s;
    s.plmn = samples::kPlmn;
    s.gnb_id = 1u << 22;   // 23 bits in a 22-bit ID
    s.tas = {{1, {{samples::kPlmn, {Snssai{}}}}}};
    EXPECT_FALSE(encode(s));
    s.gnb_id = 1;
    s.tas.clear();
    EXPECT_FALSE(encode(s));
    InitialContextSetupRequest ics;
    ics.allowed_nssai = {Snssai{}};
    ics.security_key = Bytes(16, 0);   // a key is 256 bits
    EXPECT_FALSE(encode(ics));
    EXPECT_FALSE(encode(DownlinkNasTransport{std::uint64_t{1} << 40, 1, {0x7e}}));
    EXPECT_FALSE(encode(InitialUeMessage{}));   // no NAS PDU
}

/// The external NGAP corpus: (pdu name, octets).
std::vector<std::pair<std::string, Bytes>> corpus() {
    std::vector<std::pair<std::string, Bytes>> out;
    std::ifstream in(std::string(KSIM_SOURCE_DIR) + "/tests/vectors/ngap/index.tsv");
    std::string line;
    std::vector<std::string> head;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') {
            continue;
        }
        std::vector<std::string> cols;
        std::istringstream ss(line);
        std::string c;
        while (std::getline(ss, c, '\t')) {
            cols.push_back(c);
        }
        if (head.empty()) {
            head = cols;
            continue;
        }
        auto hx = from_hex(cols.back());
        if (hx && cols.size() > 2) {
            out.emplace_back(cols[2], std::move(*hx));
        }
    }
    return out;
}

TEST(NgapMsg, IndependentProducersVectorsReadWhereTheProcedureIsInTheP1Set) {
    const std::set<std::string> p1{"NGSetupRequest", "NGSetupResponse", "NGSetupFailure", "NGReset",
                                   "ErrorIndication", "AMFStatusIndication", "AMFConfigurationUpdate",
                                   "AMFConfigurationUpdateAcknowledge", "Paging", "InitialUEMessage",
                                   "DownlinkNASTransport", "UplinkNASTransport", "InitialContextSetupRequest",
                                   "InitialContextSetupResponse", "UEContextReleaseCommand", "UEContextReleaseComplete",
                                   "UEContextModificationRequest", "UEContextModificationResponse",
                                   "PDUSessionResourceSetupRequest", "PDUSessionResourceSetupResponse",
                                   "PDUSessionResourceReleaseCommand", "PDUSessionResourceReleaseResponse",
                                   "PDUSessionResourceModifyRequest", "PDUSessionResourceModifyResponse"};
    int read = 0;
    int other = 0;
    for (const auto& [name, wire] : corpus()) {
        auto h = peek(wire);
        if (name == "(undecodable)") {
            continue;
        }
        ASSERT_TRUE(h) << name;
        auto d = decode(wire);
        // Never malformed: read, or a procedure (or a RAN node type) P1 does not read.
        EXPECT_TRUE(d || d.error().code == Errc::unsupported) << name << ": " << (d ? "" : d.error().what);
        if (p1.count(name) != 0) {
            read += d ? 1 : 0;
            if (!d) {
                std::printf("NGAP corpus: %s not read: %s\n", name.c_str(), d.error().what);
            }
        } else {
            ++other;
        }
    }
    EXPECT_GE(read, 65);
    EXPECT_GT(other, 0);
    std::printf("NGAP corpus: %d read, %d outside the P1 set\n", read, other);
}

} // namespace
} // namespace ksim::ngap
