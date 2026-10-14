// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Spec-row tests for the user plane codecs (plan M12): GTP-U (TS 29.281 5.1,
// 5.2, 8), the PDU Session Container (TS 38.415 5.5.2) and NR-U (TS 38.425
// 5.5.2).

#include <gtest/gtest.h>

#include <string_view>

#include "codec/up/frames.hpp"
#include "codec/up/gtpu.hpp"

namespace ksim {
namespace {

Bytes hex(std::string_view s) {
    Bytes out;
    for (std::size_t i = 0; i + 1 < s.size(); i += 2) {
        out.push_back(static_cast<std::uint8_t>(std::stoi(std::string(s.substr(i, 2)), nullptr, 16)));
    }
    return out;
}

// ---- GTP-U -------------------------------------------------------------------------------

TEST(Gtpu, EchoRequestWithTheOptionalPart) {
    const Bytes in = hex("32010004000000001234" "0000");   // S set: sequence 0x1234
    auto p = gtpu::decode(in);
    ASSERT_TRUE(p) << p.error().what;
    EXPECT_STREQ(gtpu::message_name(p->type), "Echo Request");
    EXPECT_TRUE(p->s());
    EXPECT_EQ(p->sequence, 0x1234);
    EXPECT_TRUE(p->payload.empty());
    EXPECT_EQ(*gtpu::encode(*p), in);
}

// 5.2.1: each extension header is 4n octets, its last octet the next type.
TEST(Gtpu, AChainOfExtensionHeaders) {
    const Bytes in = hex("34ff00100a0b0c0d" "00000085" "01" "0009" "40" "01" "0868" "00" "45000000");
    auto p = gtpu::decode(in);
    ASSERT_TRUE(p) << p.error().what;
    ASSERT_EQ(p->ext.size(), 2U);
    EXPECT_EQ(p->ext[0].type, gtpu::ext_pdu_session_container);
    EXPECT_EQ(p->ext[0].content, hex("0009"));
    EXPECT_EQ(p->ext[1].type, gtpu::ext_udp_port);
    EXPECT_EQ(p->ext[1].content, hex("0868"));
    EXPECT_EQ(p->payload, hex("45000000"));
    EXPECT_EQ(p->teid, 0x0A0B0C0DU);
    EXPECT_EQ(*gtpu::encode(*p), in);
    EXPECT_TRUE(gtpu::ext_comprehension_required(gtpu::ext_pdu_session_container));
    EXPECT_FALSE(gtpu::ext_comprehension_required(gtpu::ext_udp_port));
}

TEST(Gtpu, LengthVersionAndExtensionErrors) {
    EXPECT_EQ(gtpu::decode(hex("320100050000000012340000")).error().code, Errc::truncated);   // Length too long
    EXPECT_EQ(gtpu::decode(hex("32010004000000001234000000")).error().code, Errc::malformed);  // octets after it
    EXPECT_EQ(gtpu::decode(hex("5201000000000000")).error().code, Errc::unsupported);          // version 2
    EXPECT_EQ(gtpu::decode(hex("2201000000000000")).error().code, Errc::unsupported);          // PT 0: GTP'
    EXPECT_EQ(gtpu::decode(hex("34ff000800000001000000850000aa00")).error().code, Errc::malformed);   // length 0
    EXPECT_EQ(gtpu::decode(hex("34ff000800000001000000850201aa00")).error().code, Errc::truncated);
    gtpu::Pdu p;
    p.octet1 = 0x34;
    p.ext.push_back({gtpu::ext_udp_port, hex("086800")});   // 3 octets: not 4n-2
    EXPECT_FALSE(gtpu::encode(p));
}

TEST(Gtpu, ShortFormsKeepTheirLength) {
    // a G-PDU with no optional part; the Length counts only the T-PDU
    const Bytes in = hex("30ff0004000000014500001c");
    auto p = gtpu::decode(in);
    ASSERT_TRUE(p);
    EXPECT_FALSE(p->has_optional_part());
    EXPECT_EQ(p->payload, hex("4500001c"));
    gtpu::Pdu built;
    built.teid = 1;
    built.payload = hex("4500001c");
    EXPECT_EQ(*gtpu::encode(built), in);
}

// Clause 8: TV IEs have a fixed length, TLV IEs a two-octet length, but the
// Extension Header Type List a one-octet count (8.5).
TEST(Gtpu, InformationElements) {
    const Bytes ies = hex("0e00" "1011223344" "8500040a000001" "8d028485" "e60001" "01" "ff00040001aabb");
    auto v = gtpu::decode_ies(ies);
    ASSERT_TRUE(v) << v.error().what;
    ASSERT_EQ(v->size(), 6U);
    EXPECT_EQ((*v)[0].type, gtpu::ie_recovery);
    EXPECT_EQ((*v)[1].value, hex("11223344"));
    EXPECT_EQ((*v)[2].value, hex("0a000001"));
    EXPECT_EQ((*v)[3].value, hex("8485"));
    EXPECT_EQ((*v)[4].type, gtpu::ie_tunnel_status_information);
    EXPECT_EQ((*v)[5].value, hex("0001aabb"));
    EXPECT_EQ(*gtpu::encode_ies(*v), ies);
    EXPECT_EQ(gtpu::decode_ies(hex("1100")).error().code, Errc::unsupported);   // an unknown TV IE
    EXPECT_EQ(gtpu::decode_ies(hex("85000a0a000001")).error().code, Errc::truncated);
}

// ---- PSC and NR-U frames -------------------------------------------------------------

// TS 38.415 5.5.2.1: DL, every optional field on; the PPI octet carries BSSI and TTNBI.
TEST(Frames, PscDlEveryField) {
    const Bytes in = hex("0ec9a3" "e8d4a51000000001" "000102" "00000003" "000400" "0005" "000000");
    auto f = up::decode(up::Protocol::psc, in);
    ASSERT_TRUE(f) << f.error().what;
    EXPECT_STREQ(f->spec->name, "DL PDU SESSION INFORMATION");
    ASSERT_EQ(f->flags.size(), 3U);
    EXPECT_EQ(f->flags[1] & 0x3F, 9);    // QFI
    EXPECT_EQ(f->flags[2] >> 5, 5);      // PPI
    EXPECT_EQ(*f->value("DL QFI Sequence Number"), 0x000102U);
    EXPECT_EQ(*f->value("DL MBS QFI Sequence Number"), 3U);
    EXPECT_EQ(*f->value("BSSize"), 0x400U);
    EXPECT_EQ(*f->value("TTNB"), 5U);
    EXPECT_EQ(f->tail, hex("000000"));
    EXPECT_EQ(*up::encode(*f), in);
    EXPECT_EQ(in.size() % 4, 2U);
}

// Without PPP the PPI octet is absent, so BSSize and TTNB cannot be there.
TEST(Frames, PscDlWithoutPpiOctet) {
    EXPECT_EQ(up::decode(up::Protocol::psc, hex("04090000")).error().code, Errc::truncated);   // SN cut short
    auto g = up::decode(up::Protocol::psc, hex("0409000001000000"));   // SNP; QFI 9; DL QFI SN 1; padding
    ASSERT_TRUE(g);
    EXPECT_EQ(g->flags.size(), 2U);
    EXPECT_EQ(*g->value("DL QFI Sequence Number"), 1U);
    EXPECT_EQ(g->find("BSSize"), nullptr);
}

TEST(Frames, BuildingSetsTheFlagsAndPads) {
    auto f = up::make(up::Protocol::psc, 1);   // UL
    ASSERT_TRUE(f);
    ASSERT_TRUE(up::set(*f, "UL QFI Sequence Number", 0x10203));
    ASSERT_TRUE(up::set(*f, "UL Available Bitrate", 100000));   // makes the New IE Flags octet, bit 3
    ASSERT_TRUE(up::set_flag(*f, 1, 0, true));                  // QFI bit 0: QFI 1
    auto b = up::encode(*f);
    ASSERT_TRUE(b) << b.error().what;
    EXPECT_EQ(*b, hex("1141" "010203" "08" "000186a0"));   // 10 octets: already 4n-2
    auto back = up::decode(up::Protocol::psc, *b);
    ASSERT_TRUE(back);
    EXPECT_EQ(*back->value("UL Available Bitrate"), 100000U);
    EXPECT_FALSE(up::set(*f, "UL QFI Sequence Number", 0x1000000));   // wider than three octets
    EXPECT_FALSE(up::set(*f, "No Such Field", 1));
}

// TS 38.425 5.5.2.1: discard blocks are a count then SN start (3) and size (1) each.
TEST(Frames, NruDlUserDataBlocks) {
    auto f = up::make(up::Protocol::nru, 0);
    ASSERT_TRUE(f);
    ASSERT_TRUE(up::set(*f, "NR-U Sequence Number", 42));
    ASSERT_TRUE(up::set_blocks(*f, "DL discard Number of blocks", hex("00002005" "00003003")));
    ASSERT_TRUE(up::set(*f, "DL retransmission NR PDCP PDU SN", 0x12));
    auto b = up::encode(*f);
    ASSERT_TRUE(b) << b.error().what;
    EXPECT_EQ(*b, hex("0480" "00002a" "02" "00002005" "00003003" "01" "000012"));   // 18 octets: 4n-2
    auto back = up::decode(up::Protocol::nru, *b);
    ASSERT_TRUE(back);
    EXPECT_EQ(back->find("DL discard Number of blocks")->octets.size(), 9U);
    EXPECT_EQ(*back->value("DL retransmission NR PDCP PDU SN"), 0x12U);
    EXPECT_FALSE(up::set_blocks(*f, "DL discard Number of blocks", hex("000020")));   // not whole blocks
}

TEST(Frames, NruDeliveryStatus) {
    const Bytes in = hex("1108" "00010000" "000f4240" "01" "000005000007" "00");
    auto f = up::decode(up::Protocol::nru, in);
    ASSERT_TRUE(f) << f.error().what;
    EXPECT_STREQ(f->spec->name, "DL DATA DELIVERY STATUS");
    EXPECT_EQ(*f->value("Desired Data Rate"), 1000000U);
    EXPECT_EQ(f->find("Number of lost NR-U Sequence Number ranges reported")->octets, hex("01000005000007"));
    EXPECT_EQ(*up::encode(*f), in);
}

TEST(Frames, Errors) {
    EXPECT_EQ(up::decode(up::Protocol::nru, hex("e000112233")).error().code, Errc::unsupported);   // PDU type 14
    EXPECT_EQ(up::decode(up::Protocol::nru, hex("0400112233030000")).error().code, Errc::truncated);   // 3 blocks
    EXPECT_EQ(up::decode(up::Protocol::psc, hex("00")).error().code, Errc::truncated);
    auto f = up::decode(up::Protocol::psc, hex("0009"));
    ASSERT_TRUE(f);
    f->flags[0] |= 0x04;   // SNP set, but no DL QFI Sequence Number field
    EXPECT_FALSE(up::encode(*f));
}

} // namespace
} // namespace ksim
