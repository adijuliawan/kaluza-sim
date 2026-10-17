// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The typed XnAP builders and readers (P3 R1; TS 38.423 j40 §8.4): every
// builder's output decodes back to the same struct, inputs out of range are
// refused before encoding, and key material is zeroed for captures. Whether the
// octets are right is judged by tshark and pycrate (oracle.py builders).

#include <gtest/gtest.h>

#include "xnap_samples.hpp"

namespace ksim::xnap {
namespace {

TEST(XnapMsg, EveryBuilderRoundTrips) {
    for (const auto& s : samples::all()) {
        auto wire = encode(s.pdu);
        ASSERT_TRUE(wire) << s.name << ": " << wire.error().what;
        auto back = decode(*wire);
        ASSERT_TRUE(back) << s.name << ": " << back.error().what;
        EXPECT_EQ(*back, s.pdu) << s.name;
        auto r = redact_keys(*wire);
        ASSERT_TRUE(r) << s.name;
        EXPECT_EQ(r->keys, 0u) << s.name;   // no R1 message carries K_NG-RAN*
        EXPECT_EQ(r->pdu, *wire) << s.name;
    }
}

TEST(XnapMsg, InputsOutOfRangeAreRefused) {
    XnSetupRequest r = std::get<XnSetupRequest>(samples::all().at(0).pdu);
    r.gnb.bits = 21;
    EXPECT_FALSE(encode(r));
    r = std::get<XnSetupRequest>(samples::all().at(0).pdu);
    r.amf_regions.clear();
    EXPECT_FALSE(encode(r));
    r = std::get<XnSetupRequest>(samples::all().at(0).pdu);
    r.cells[0].pci = 1008;
    EXPECT_FALSE(encode(r));
    r = std::get<XnSetupRequest>(samples::all().at(0).pdu);
    r.cells[0].meas_timing.clear();
    EXPECT_FALSE(encode(r));
}

TEST(XnapMsg, GarbageIsAnErrorNotACrash) {
    EXPECT_FALSE(decode(Bytes{0x00, 0x11}));
    EXPECT_FALSE(decode(Bytes{}));
}

} // namespace
} // namespace ksim::xnap
