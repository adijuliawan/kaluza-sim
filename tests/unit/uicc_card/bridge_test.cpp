// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The card bridge's filter (P2 Q1; lab.md §7, row ksim-p2.bridge-refuses-admin):
// what only an administrator may send is answered 6982 without --admin; a
// UE's own commands pass.

#include <gtest/gtest.h>

#include "uicc/transport/bridge.hpp"

namespace ksim::uicc::bridge {
namespace {

Bytes hex(const char* h) { return *from_hex(h); }

TEST(BridgeFilter, AdmKeysAreRefusedAndPin1Passes) {
    AdminFilter f(false);
    EXPECT_EQ(f.check(hex("0020000A")), 0x6982);                 // the retry-counter query too
    EXPECT_EQ(f.check(hex("0020000A083131313131313131")), 0x6982);
    EXPECT_EQ(f.check(hex("0024000E10" "31313131313131313131313131313131")), 0x6982);
    EXPECT_EQ(f.check(hex("002C000A10" "31313131313131313131313131313131")), 0x6982);
    EXPECT_FALSE(f.check(hex("00200001")));                       // PIN1's status: the UE's own
    EXPECT_FALSE(f.check(hex("002000010831323334FFFFFFFF")));     // VERIFY PIN1
    EXPECT_EQ(f.refused(), 4u);
}

TEST(BridgeFilter, KeyFilesAreNotWrittenAndOtherEfsAre) {
    AdminFilter f(false);
    EXPECT_FALSE(f.check(hex("00A4000402AF20")));                 // selecting is the card's business
    EXPECT_EQ(f.check(hex("00D600000100")), 0x6982);
    EXPECT_EQ(f.check(hex("00DC010401FF")), 0x6982);
    EXPECT_FALSE(f.check(hex("00A40804047FFFAF30")));
    EXPECT_EQ(f.check(hex("00D600000100")), 0x6982);              // AF30 by path
    EXPECT_FALSE(f.check(hex("00A40004026F07")));
    EXPECT_FALSE(f.check(hex("00D6000009" "083900100000300100")));  // EF.IMSI: the UE may (the card's ARR decides)
    EXPECT_FALSE(f.check(hex("00A4040407A0000000871002")));
    EXPECT_FALSE(f.check(hex("00D600000100")));                   // an ADF selected: no key file
    f.check(hex("00A4000402AF20"));
    f.reset();                                                    // a reset selects nothing
    EXPECT_FALSE(f.check(hex("00D600000100")));
}

TEST(BridgeFilter, CreateDeleteAndTerminateAreRefused) {
    AdminFilter f(false);
    for (const char* c : {"00E000000100", "00E40000026F07", "00E6000000", "00E8000000", "80FE000000"}) {
        EXPECT_EQ(f.check(hex(c)), 0x6982) << c;
    }
    EXPECT_FALSE(f.check(hex("00880081")));   // AUTHENTICATE passes (short: the card judges it)
    EXPECT_FALSE(f.check(hex("00B0")));       // too short to judge: the card does
}

TEST(BridgeFilter, AdminLetsEverythingThrough) {
    AdminFilter f(true);
    EXPECT_FALSE(f.check(hex("0020000A083131313131313131")));
    EXPECT_FALSE(f.check(hex("00A4000402AF20")));
    EXPECT_FALSE(f.check(hex("00D600000100")));
    EXPECT_FALSE(f.check(hex("00E40000026F07")));
    EXPECT_EQ(f.refused(), 0u);
}

} // namespace
} // namespace ksim::uicc::bridge
