// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The KAIR v1 codec and the PDCP and SDAP header formats (P1 N6;
// architecture.md §2.3; TS 38.323 §6.2; TS 37.324 §6.2).

#include <gtest/gtest.h>

#include "codec/air/kair.hpp"
#include "codec/pdcp/pdcp.hpp"
#include "codec/sdap/sdap.hpp"

namespace ksim {
namespace {

Bytes h(const char* s) { return *from_hex(s); }

TEST(Kair, AFrameRoundTripsWithItsHeaderInNetworkOrder) {
    air::Frame f;
    f.type = air::FrameType::ul_sdu;
    f.cell_handle = 0x01020304;
    f.radio_id = 7;
    f.tx_time_ns = 0x0102030405060708;
    f.sfn_slot = (513u << 8) | 9u;
    f.rnti = 0x4601;
    f.seq = 3;
    f.sdus.push_back({1, air::RlcMode::am, h("0005e3540eb5e9a2ec15689d750790")});
    f.sdus.push_back({4, air::RlcMode::um, h("81")});
    auto wire = air::encode(f);
    ASSERT_TRUE(wire);
    EXPECT_EQ(to_hex(ByteView(*wire).subspan(0, 32)),
              "4b41010b0000" "001a" "01020304" "00000007" "0102030405060708" "00020109" "4601" "0003");
    EXPECT_EQ(to_hex(ByteView(*wire).subspan(32, 5)), "0100110102");   // SDU TLV: LCID 1, AM
    auto back = air::decode(*wire);
    ASSERT_TRUE(back);
    EXPECT_EQ(*back, f);
    EXPECT_EQ(back->sfn(), 513);
    EXPECT_EQ(back->slot(), 9);
}

TEST(Kair, EachFrameTypeCarriesWhatItNeeds) {
    air::Frame msg4;
    msg4.type = air::FrameType::msg4;
    msg4.sdus.push_back({0, air::RlcMode::tm, h("2040")});
    EXPECT_FALSE(air::encode(msg4));   // no contention resolution identity
    msg4.contention_id = air::contention_id_of(h("1d2468acf13d"));
    auto wire = air::encode(msg4);
    ASSERT_TRUE(wire);
    EXPECT_TRUE(air::decode(*wire));
    air::Frame ka;
    ka.type = air::FrameType::keepalive;
    ka.sdus.push_back({1, air::RlcMode::am, h("00")});
    EXPECT_FALSE(air::encode(ka));   // SDUs in a frame type that carries none
    air::Frame prach;
    prach.type = air::FrameType::prach;
    prach.prach = air::Prach{63, 0, 80, 0, 0};
    EXPECT_FALSE(air::encode(prach));   // t_id 80 is out of range
}

TEST(Kair, TheRaRntiFollowsTs38321) {
    EXPECT_EQ((air::Prach{0, 0, 0, 0, 0}.ra_rnti()), 1);
    EXPECT_EQ((air::Prach{5, 2, 3, 1, 0}.ra_rnti()), 1 + 2 + 14 * 3 + 14 * 80 * 1);
    EXPECT_EQ((air::Prach{0, 13, 79, 7, 1}.ra_rnti()), 1 + 13 + 14 * 79 + 14 * 80 * 7 + 14 * 80 * 8);
}

/// A KEEPALIVE header, with octet `at` set to `value`, then `tlvs`.
Bytes keepalive(std::size_t at = 0, int value = -1, const char* tlvs = "") {
    std::string hex = "4b41010d0000" "0000" "00000000" "00000000" "0000000000000000" "00000000" "0000" "0000";
    hex += tlvs;
    Bytes b = *from_hex(hex);
    if (value >= 0 && at < b.size()) {
        b.at(at) = static_cast<std::uint8_t>(value);
    }
    return b;
}

TEST(Kair, BadInputIsRefusedAndAnUnknownTlvSkipped) {
    air::Frame f;
    f.type = air::FrameType::keepalive;
    EXPECT_EQ(to_hex(*air::encode(f)), to_hex(keepalive()));
    EXPECT_TRUE(air::decode(keepalive()));
    EXPECT_EQ(air::decode(keepalive(0, 0)).error().code, Errc::malformed);      // magic
    EXPECT_EQ(air::decode(keepalive(2, 2)).error().code, Errc::unsupported);    // version 2
    EXPECT_FALSE(air::decode(ByteView(keepalive()).subspan(0, 31)));            // short header
    EXPECT_TRUE(air::decode(keepalive(7, 4, "7f0001aa")));    // a TLV of type 0x7F (unknown) is skipped
    EXPECT_FALSE(air::decode(keepalive(7, 5, "7f0001aa")));   // the length now overruns the frame
}

TEST(PdcpFormat, HeadersOfSrbsAnd12And18BitDrbs) {
    EXPECT_EQ(to_hex(pdcp::data_header(true, pdcp::SnSize::len12, 0xABC)), "0abc");
    EXPECT_EQ(to_hex(pdcp::data_header(false, pdcp::SnSize::len12, 0x1ABC)), "8abc");   // SN modulo 2^12
    EXPECT_EQ(to_hex(pdcp::data_header(false, pdcp::SnSize::len18, 0x2ABCD)), "82abcd");
    auto p = pdcp::parse(false, pdcp::SnSize::len18, h("82abcd00"));
    ASSERT_TRUE(p);
    EXPECT_TRUE(p->data);
    EXPECT_EQ(p->sn, 0x2ABCDu);
    EXPECT_EQ(p->length, 3u);
    auto srb = pdcp::parse(true, pdcp::SnSize::len12, h("fabc0000000000"));   // reserved bits ignored
    ASSERT_TRUE(srb);
    EXPECT_EQ(srb->sn, 0xABCu);
    EXPECT_FALSE(pdcp::parse(true, pdcp::SnSize::len12, h("0abc000000")));   // no room for the MAC-I
    auto ctl = pdcp::parse(false, pdcp::SnSize::len12, h("00"));
    ASSERT_TRUE(ctl);
    EXPECT_FALSE(ctl->data);
}

TEST(PdcpFormat, AStatusReportCarriesTheFirstMissingCountAndItsBitmap) {
    const Bytes wire = pdcp::encode_status_report({0x01020304, h("a0")});
    EXPECT_EQ(to_hex(wire), "0001020304a0");
    auto r = pdcp::decode_status_report(wire);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->fmc, 0x01020304u);
    EXPECT_EQ(to_hex(r->bitmap), "a0");
    EXPECT_FALSE(pdcp::decode_status_report(h("8001020304")));   // a data PDU
}

TEST(SdapFormat, TheOneOctetHeadersBothWays) {
    EXPECT_EQ(sdap::encode(sdap::DlHeader{true, false, 9}), 0x89);
    EXPECT_EQ(sdap::decode_dl(0x49), (sdap::DlHeader{false, true, 9}));
    EXPECT_EQ(sdap::encode(sdap::UlHeader{true, 63}), 0xBF);
    EXPECT_EQ(sdap::decode_ul(0x7F), (sdap::UlHeader{false, 63}));   // the R bit is ignored
}

} // namespace
} // namespace ksim
