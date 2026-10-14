// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// All five ASN.1 libraries in one binary (plan M6). Each protocol builds a
// minimal PDU and must survive encode, decode and re-encode byte-identically.

#include <gtest/gtest.h>

#include "roundtrip.hpp"

using ksim::test::RoundTrip;

namespace {

void expect_identical(const RoundTrip& r) {
    EXPECT_TRUE(r.encoded);
    EXPECT_TRUE(r.decoded);
    EXPECT_TRUE(r.identical) << r.hex;
}

} // namespace

TEST(Asn1LinkAll, NgapNgSetupRequest) {
    expect_identical(ksim::test::ngap_ng_setup_request());
}
TEST(Asn1LinkAll, F1apF1SetupRequest) {
    expect_identical(ksim::test::f1ap_f1_setup_request());
}
TEST(Asn1LinkAll, E1apCuUpE1SetupRequest) {
    expect_identical(ksim::test::e1ap_cu_up_e1_setup_request());
}
TEST(Asn1LinkAll, XnapXnSetupRequest) {
    expect_identical(ksim::test::xnap_xn_setup_request());
}

// UL-CCCH: 1 bit c1 choice + 2 bits rrcSetupRequest + 1 bit ue-Identity choice
// + 39 bits randomValue + 4 bits establishmentCause + 1 bit spare = 48 bits.
TEST(Asn1LinkAll, RrcSetupRequestIsSixOctets) {
    const RoundTrip r = ksim::test::rrc_rrc_setup_request();
    expect_identical(r);
    EXPECT_EQ(r.bits, 48U);
}
