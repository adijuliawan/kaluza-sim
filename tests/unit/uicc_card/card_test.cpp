// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Spec-row tests for the soft card's OS (P1 N3): ETSI TS 102 221 V18.4.0
// clauses by name, run as APDUs against the personalised template card.

#include <gtest/gtest.h>

#include "codec/uicc/fcp.hpp"
#include "fixture.hpp"

namespace ksim::uicc::test {
namespace {

TEST(CardOs, TheAtrIsAnIso7816AtrWithItsCheckByte) {
    auto card = make_card();
    const Bytes& atr = card->atr();
    ASSERT_GE(atr.size(), 6u);
    EXPECT_EQ(atr[0], 0x3B);                 // direct convention
    EXPECT_EQ(atr[1] & 0x0F, atr.size() - 7u);   // K historical bytes
    std::uint8_t x = 0;
    for (std::size_t i = 1; i < atr.size(); ++i) {
        x ^= atr[i];
    }
    EXPECT_EQ(x, 0);                         // TCK makes the XOR of T0..TCK zero
}

TEST(CardOs, Clause11_1_1_SelectingTheMfReturnsItsFcpWithThePinTemplate) {
    auto card = make_card();
    const std::string r = apdu(*card, "00A40004023F0000");   // with Le: the data at once
    ASSERT_EQ(sw_of(r), "9000");
    auto fcp = decode_fcp(*from_hex(data_of(r)));
    ASSERT_TRUE(fcp);
    EXPECT_EQ(fcp->file_id(), 0x3F00);
    EXPECT_EQ(fcp->file_descriptor()->file_type(), std::string("df"));
    EXPECT_EQ(fcp->pin_key_references(), (std::vector<std::uint8_t>{0x01, 0x81, 0x0A}));
}

TEST(CardOs, Clause7_3_1_1_4_UnderT0ACaseFourCommandAnswers61xxThenGetResponse) {
    auto card = make_card();
    const std::string r = apdu(*card, "00A40004023F00");     // no Le: T=0 case 4
    ASSERT_EQ(r.substr(0, 2), "61");
    const int waiting = std::stoi(r.substr(2, 2), nullptr, 16);
    ASSERT_GT(waiting, 2);
    // Two octets now; the rest still waits.
    char rest_sw[5];
    std::snprintf(rest_sw, sizeof rest_sw, "61%02X", waiting - 2);
    EXPECT_EQ(sw_of(apdu(*card, "00C0000002")), rest_sw);
    // Asking for more than waits is '6Cxx' with what is left.
    const std::string rest = apdu(*card, "00C00000FF");
    EXPECT_EQ(rest.substr(0, 2), "6C");
    EXPECT_EQ(sw_of(apdu(*card, "00C00000" + rest.substr(2, 2))), "9000");
    // With nothing waiting, GET RESPONSE is refused.
    EXPECT_EQ(sw_of(apdu(*card, "00C0000010")), "6985");
}

TEST(CardOs, Clause8_4_SelectionByFidPathAndAid) {
    auto card = make_card();
    EXPECT_EQ(sw_of(apdu(*card, "00A4000C022FE2")), "9000");                       // EF.ICCID under the MF
    EXPECT_EQ(sw_of(apdu(*card, "00A4080C047FF06F07")), "9000");                   // path from the MF
    EXPECT_EQ(sw_of(apdu(*card, "00A4040C07A0000000871002")), "9000");             // the USIM by its AID prefix
    EXPECT_EQ(sw_of(apdu(*card, "00A4000C026F07")), "9000");                       // EF.IMSI in the current ADF
    EXPECT_EQ(sw_of(apdu(*card, "00A4000C025FC0")), "9000");                       // DF.5GS
    EXPECT_EQ(sw_of(apdu(*card, "00A4000C024F01")), "9000");                       // EF.5GS3GPPLOCI in it
    EXPECT_EQ(sw_of(apdu(*card, "00A4000C027FFF")), "9000");                       // back to the current ADF
    EXPECT_EQ(sw_of(apdu(*card, "00A4000C02ABCD")), "6A82");                       // file not found
    EXPECT_EQ(sw_of(apdu(*card, "00A4040C05A000000099")), "6A82");                 // no such application
}

TEST(CardOs, Clause11_1_3_ReadBinaryReturnsTheContentsAndAWrongLeIs6Cxx) {
    auto card = make_card();
    ASSERT_EQ(sw_of(apdu(*card, "00A4080C047FF06F07")), "9000");
    EXPECT_EQ(apdu(*card, "00B0000009"), "0809101000000300109000");   // EF.IMSI of 001010000300001
    EXPECT_EQ(apdu(*card, "00B0000014"), "6C09");                     // Le 20 of a 9-octet file
    EXPECT_EQ(apdu(*card, "00B0000304"), "100000039000");             // from offset 3
    EXPECT_EQ(sw_of(apdu(*card, "00B0000A01")), "6B00");              // beyond the end
    // By SFI (P1 b8 set): EF.IMSI is SFI 7 in the USIM.
    EXPECT_EQ(apdu(*card, "00A4040C07A0000000871002").substr(0, 4), "9000");
    EXPECT_EQ(apdu(*card, "00B0870002"), "08099000");
}

TEST(CardOs, Clause9_2_AnUpdateNeedsItsAccessCondition) {
    auto card = make_card();
    ASSERT_EQ(sw_of(apdu(*card, "00A4080C047FF06F07")), "9000");
    EXPECT_EQ(sw_of(apdu(*card, "00D6000001AA")), "6982");                       // EF.IMSI: update ADM1
    EXPECT_EQ(sw_of(apdu(*card, "002000000A08" + pin_hex("11111111"))), "6700"); // wrong Lc
    EXPECT_EQ(sw_of(apdu(*card, "0020000A08" + pin_hex("11111111"))), "9000");   // VERIFY ADM1
    EXPECT_EQ(sw_of(apdu(*card, "00D6000001AA")), "9000");
    EXPECT_EQ(apdu(*card, "00B0000001"), "AA9000");
    // A reset clears the security status.
    card->reset();
    ASSERT_EQ(sw_of(apdu(*card, "00A4080C047FF06F07")), "9000");
    EXPECT_EQ(sw_of(apdu(*card, "00D6000001BB")), "6982");
}

TEST(CardOs, AKeyFileIsNeverReadEvenWithAdm) {
    auto card = make_card();
    ASSERT_EQ(sw_of(apdu(*card, "0020000A08" + pin_hex("11111111"))), "9000");
    ASSERT_EQ(sw_of(apdu(*card, "00A4080C047FF0AF20")), "9000");
    EXPECT_EQ(sw_of(apdu(*card, "00B0000010")), "6982");
}

TEST(CardOs, Clause11_1_5_ReadRecordAbsoluteNextAndPrevious) {
    auto card = make_card();
    ASSERT_EQ(sw_of(apdu(*card, "00A4000C022F06")), "9000");   // EF.ARR, 5 records of 40
    const std::string r1 = apdu(*card, "00B2010428");
    EXPECT_EQ(sw_of(r1), "9000");
    EXPECT_EQ(data_of(r1).substr(0, 10), "8001019000");
    EXPECT_EQ(data_of(apdu(*card, "00B2000228")).substr(0, 6), "800101");          // next: record 2
    EXPECT_EQ(data_of(apdu(*card, "00B2000328")), data_of(r1));                     // previous: record 1
    EXPECT_EQ(sw_of(apdu(*card, "00B2000328")), "6A83");                            // no record before 1
    EXPECT_EQ(apdu(*card, "00B2010410"), "6C28");                                    // Le must be the record length
    EXPECT_EQ(sw_of(apdu(*card, "00B2090428")), "6A83");                            // record 9 does not exist
}

TEST(CardOs, Clause11_1_6_ACyclicUpdateWritesTheOldestRecordAsRecordOne) {
    auto mf = std::make_unique<os::File>();
    mf->kind = os::Kind::mf;
    mf->fid = 0x3F00;
    auto cyc = std::make_unique<os::File>();
    cyc->kind = os::Kind::cyclic;
    cyc->fid = 0x6F39;
    cyc->record_len = 2;
    cyc->records = {Bytes{1, 1}, Bytes{2, 2}, Bytes{3, 3}};
    mf->add(std::move(cyc));
    os::Card card(std::move(mf), {});
    ASSERT_EQ(sw_of(apdu(card, "00A4000C026F39")), "9000");
    EXPECT_EQ(sw_of(apdu(card, "00DC010402AAAA")), "6A86");   // absolute is not for a cyclic EF
    EXPECT_EQ(sw_of(apdu(card, "00DC000302AAAA")), "9000");   // PREVIOUS
    EXPECT_EQ(apdu(card, "00B2010402"), "AAAA9000");
    EXPECT_EQ(apdu(card, "00B2020402"), "01019000");
    EXPECT_EQ(apdu(card, "00B2030402"), "02029000");          // 03 03 was the oldest: gone
    EXPECT_EQ(apdu(card, "00B2000202"), "AAAA9000");          // next from 3 wraps to 1
}

TEST(CardOs, Clause11_1_7_SearchRecordFindsThePattern) {
    auto card = make_card();
    ASSERT_EQ(sw_of(apdu(*card, "00A4000C022F06")), "9000");
    EXPECT_EQ(apdu(*card, "00A201040383010100"), "0102039000");   // PIN1 is named in records 1, 2 and 3
    EXPECT_EQ(apdu(*card, "00A205050383010100"), "0302019000");   // backward from 5
    EXPECT_EQ(apdu(*card, "00A2010403830101"), "6103");           // no Le under T=0: '61xx', then GET RESPONSE
    EXPECT_EQ(sw_of(apdu(*card, "00A2010403DEADBE00")), "6A83");
}

TEST(CardOs, Clause11_1_9_To_13_PinsCountDownBlockAndUnblock) {
    auto card = make_card();
    EXPECT_EQ(apdu(*card, "0020008100"), "63C3");                                       // status: 3 tries
    EXPECT_EQ(apdu(*card, "0020008108" + pin_hex("0000")), "63C2");
    EXPECT_EQ(apdu(*card, "0020008108" + pin_hex("0000")), "63C1");
    EXPECT_EQ(apdu(*card, "0020008108" + pin_hex("0000")), "63C0");
    EXPECT_EQ(apdu(*card, "0020008108" + pin_hex("5678")), "6983");                     // blocked, even when right
    EXPECT_EQ(apdu(*card, "002C008110" + pin_hex("00000000") + pin_hex("4321")), "63C9");
    EXPECT_EQ(apdu(*card, "002C008110" + pin_hex("87654321") + pin_hex("4321")), "9000"); // PUK2, new PIN2
    EXPECT_EQ(apdu(*card, "0020008100"), "9000");                                       // verified now
    card->reset();
    EXPECT_EQ(apdu(*card, "0020008108" + pin_hex("4321")), "9000");
    EXPECT_EQ(apdu(*card, "0024008110" + pin_hex("4321") + pin_hex("2468")), "9000");    // CHANGE PIN
    card->reset();
    EXPECT_EQ(apdu(*card, "0020008108" + pin_hex("2468")), "9000");
    EXPECT_EQ(sw_of(apdu(*card, "0020000208" + pin_hex("1234"))), "6A88");              // no such key reference
}

TEST(CardOs, Clause11_1_10_EnablingPin1ProtectsWhatIsBehindIt) {
    auto card = make_card();
    ASSERT_EQ(sw_of(apdu(*card, "00A4040C07A0000000871002")), "9000");
    ASSERT_EQ(sw_of(apdu(*card, "00A4000C026F07")), "9000");
    EXPECT_EQ(sw_of(apdu(*card, "00B0000009")), "9000");             // PIN1 disabled: read PIN1 is granted
    EXPECT_EQ(sw_of(apdu(*card, "0028000108" + pin_hex("1234"))), "9000");   // ENABLE
    card->reset();
    ASSERT_EQ(sw_of(apdu(*card, "00A4080C047FF06F07")), "9000");
    EXPECT_EQ(sw_of(apdu(*card, "00B0000009")), "6982");
    EXPECT_EQ(sw_of(apdu(*card, "0020000108" + pin_hex("1234"))), "9000");
    EXPECT_EQ(sw_of(apdu(*card, "00B0000009")), "9000");
    EXPECT_EQ(sw_of(apdu(*card, "0026000A08" + pin_hex("11111111"))), "6985");   // ADM1 cannot be disabled
}

TEST(CardOs, Clause11_1_17_ManageChannelOpensAndClosesChannels) {
    auto card = make_card();
    EXPECT_EQ(apdu(*card, "0070000001"), "019000");
    EXPECT_EQ(sw_of(apdu(*card, "01A4040C07A0000000871002")), "9000");   // channel 1
    EXPECT_EQ(sw_of(apdu(*card, "01A4000C026F07")), "9000");
    EXPECT_EQ(apdu(*card, "01B0000002"), "08099000");
    EXPECT_EQ(sw_of(apdu(*card, "00B0000002")), "6986");                 // channel 0 has no EF selected
    EXPECT_EQ(apdu(*card, "0070800100"), "9000");                        // close channel 1
    EXPECT_EQ(sw_of(apdu(*card, "01B0000002")), "6881");
    EXPECT_EQ(sw_of(apdu(*card, "0070800000")), "6A86");                 // the basic channel stays
}

TEST(CardOs, StatusAndUnknownCommands) {
    auto card = make_card();
    ASSERT_EQ(sw_of(apdu(*card, "00A4040C07A0000000871002")), "9000");
    const std::string st = apdu(*card, "80F2000110");
    EXPECT_EQ(data_of(st).substr(0, 4), "8410");   // the USIM's DF name TLV
    EXPECT_EQ(sw_of(apdu(*card, "00FE000000")), "6D00");
    EXPECT_EQ(sw_of(apdu(*card, "A0A4000002")), "6E00");   // a GSM-class command
    EXPECT_EQ(sw_of(apdu(*card, "8010000002FFFF")), "9000");   // TERMINAL PROFILE
    EXPECT_EQ(sw_of(apdu(*card, "00")), "6700");          // not an APDU
}

TEST(CardOs, Clause11_1_14_DeactivateAndActivateNeedAdm) {
    auto card = make_card();
    ASSERT_EQ(sw_of(apdu(*card, "00A4080C047FF06F46")), "9000");   // EF.SPN
    EXPECT_EQ(sw_of(apdu(*card, "0004000000")), "6982");
    ASSERT_EQ(sw_of(apdu(*card, "0020000A08" + pin_hex("11111111"))), "9000");
    EXPECT_EQ(sw_of(apdu(*card, "0004000000")), "9000");
    EXPECT_EQ(sw_of(apdu(*card, "00A4080C047FF06F46")), "6283");   // selected file invalidated
    EXPECT_EQ(sw_of(apdu(*card, "00B0000001")), "6985");
    EXPECT_EQ(sw_of(apdu(*card, "0044000000")), "9000");
    EXPECT_EQ(sw_of(apdu(*card, "00B0000001")), "9000");
}

} // namespace
} // namespace ksim::uicc::test
