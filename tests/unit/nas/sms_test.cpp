// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Spec-row tests for SMS over NAS (plan M11): the CP and RP layers of
// TS 24.011 (7.2, 7.3, 8.1, 8.2), the TPDUs of TS 23.040 (9.2) and the GSM
// 7-bit default alphabet and UCS2 of TS 23.038.

#include <gtest/gtest.h>

#include <string_view>

#include "codec/nas/sms.hpp"

namespace ksim::sms {
namespace {

Bytes hex(std::string_view s) {
    Bytes out;
    for (std::size_t i = 0; i + 1 < s.size(); i += 2) {
        out.push_back(static_cast<std::uint8_t>(std::stoi(std::string(s.substr(i, 2)), nullptr, 16)));
    }
    return out;
}

// ---- TS 23.038 ------------------------------------------------------------------------

// 6.1.2.1.1: the packing example, "hellohello" in nine octets.
TEST(Gsm7, PacksTheSpecExample) {
    auto p = utf8_to_gsm7("hellohello");
    ASSERT_TRUE(p);
    EXPECT_EQ(p->first, hex("e8329bfd4697d9ec37"));
    EXPECT_EQ(p->second, 10U);
    EXPECT_EQ(gsm7_to_utf8(hex("e8329bfd4697d9ec37"), 10), "hellohello");
}

TEST(Gsm7, EightSeptetsFillSevenOctets) {
    auto p = utf8_to_gsm7("12345678");
    ASSERT_TRUE(p);
    EXPECT_EQ(p->first, hex("31d98c56b3dd70"));
    EXPECT_EQ(gsm7_to_utf8(p->first, 8), "12345678");
}

// 6.2.1.1: a character of the extension table costs an escape and a septet.
TEST(Gsm7, TheExtensionTableGoesThroughTheEscape) {
    auto p = utf8_to_gsm7("\xE2\x82\xAC");   // EURO SIGN: 1B 65
    ASSERT_TRUE(p);
    EXPECT_EQ(p->second, 2U);
    EXPECT_EQ(p->first, hex("9b32"));
    EXPECT_EQ(gsm7_to_utf8(p->first, 2), "\xE2\x82\xAC");
}

TEST(Gsm7, ACharacterOutsideTheAlphabetIsAnError) {
    auto p = utf8_to_gsm7("\xE4\xB8\xAD");   // U+4E2D
    ASSERT_FALSE(p);
    EXPECT_EQ(p.error().code, Errc::invalid_argument);
}

// TS 23.040 9.2.3.24: after a user data header the septets start on a septet
// boundary, so fill bits come first.
TEST(Gsm7, FillBitsAfterAHeader) {
    auto p = utf8_to_gsm7("A", 1);
    ASSERT_TRUE(p);
    EXPECT_EQ(p->first, hex("82"));
    EXPECT_EQ(gsm7_to_utf8(p->first, 1, 1), "A");
}

TEST(Gsm7, Ucs2AndTheDataCodingScheme) {
    EXPECT_EQ(ucs2_to_utf8(hex("00480069")), "Hi");
    EXPECT_EQ(ucs2_to_utf8(hex("20ac")), "\xE2\x82\xAC");
    // TS 23.038 4: general data coding group
    EXPECT_TRUE(dcs_is_gsm7(0x00));
    EXPECT_FALSE(dcs_is_gsm7(0x08));
    EXPECT_TRUE(dcs_is_ucs2(0x08));
    EXPECT_FALSE(dcs_is_gsm7(0x04));   // 8-bit data
    EXPECT_TRUE(dcs_is_gsm7(0xF0));    // data coding / message class group, default alphabet
    EXPECT_FALSE(dcs_is_gsm7(0xF4));   // the same group, 8-bit data
}

// ---- TS 23.040 TPDUs ------------------------------------------------------------------

const Bytes kSubmit = hex("112a0b911032547698f00000a705e8329bfd06");

TEST(Tpdu, SubmitFields) {
    auto t = decode_tpdu(kSubmit, TpDir::ms_to_sc);
    ASSERT_TRUE(t) << t.error().what;
    EXPECT_EQ(t->type, TpduType::submit);
    EXPECT_EQ(t->mr, 0x2a);
    EXPECT_EQ(t->address.length, 11);
    EXPECT_EQ(t->address.toa, 0x91);
    EXPECT_EQ(t->address.digits, hex("1032547698f0"));
    EXPECT_EQ(t->vp, hex("a7"));   // TP-VPF 10: relative, one octet (9.2.3.3, 9.2.3.12.1)
    EXPECT_EQ(t->udl, 5);
    EXPECT_EQ(gsm7_to_utf8(t->ud, t->udl), "hello");
    EXPECT_EQ(encode_tpdu(*t), kSubmit);
}

// 9.2.3.1: TP-MTI alone does not name the TPDU; the direction does.
TEST(Tpdu, TheDirectionPicksTheType) {
    struct Case {
        std::uint8_t mti;
        TpduType to_sc, to_ms;
    };
    for (Case c : {Case{0, TpduType::deliver_report, TpduType::deliver},
                   Case{1, TpduType::submit, TpduType::submit_report},
                   Case{2, TpduType::command, TpduType::status_report}}) {
        // the shortest of each kind, built for its own direction
        const Bytes up = c.mti == 0 ? hex("0000") : c.mti == 1 ? hex("01000091000000") : hex("02000000000091" "00");
        const Bytes down = c.mti == 0 ? hex("000091000062014141423200" "00")
                         : c.mti == 1 ? hex("010062014141423200")
                                      : hex("06000091" "62014141423200" "62014141423200" "00");
        auto u = decode_tpdu(up, TpDir::ms_to_sc);
        auto d = decode_tpdu(down, TpDir::sc_to_ms);
        ASSERT_TRUE(u) << int(c.mti) << ": " << u.error().what;
        ASSERT_TRUE(d) << int(c.mti) << ": " << d.error().what;
        EXPECT_EQ(u->type, c.to_sc);
        EXPECT_EQ(d->type, c.to_ms);
        EXPECT_EQ(encode_tpdu(*u), up);
        EXPECT_EQ(encode_tpdu(*d), down);
    }
    auto reserved = decode_tpdu(hex("03"), TpDir::ms_to_sc);
    ASSERT_FALSE(reserved);
    EXPECT_EQ(reserved.error().code, Errc::malformed);
}

// 9.2.3.3: TP-VPF selects no TP-VP, a relative (1 octet), an enhanced or an absolute (7 octets) one.
TEST(Tpdu, ValidityPeriodFormats) {
    for (auto [first, vp] : {std::pair{"01", ""}, std::pair{"11", "a7"}, std::pair{"09", "01000000000000"},
                             std::pair{"19", "62014141423200"}}) {
        const Bytes in = hex(std::string(first) + "000091" "0000" + vp + "00");
        auto t = decode_tpdu(in, TpDir::ms_to_sc);
        ASSERT_TRUE(t) << first << ": " << t.error().what;
        EXPECT_EQ(t->vp, hex(vp)) << first;
        EXPECT_EQ(encode_tpdu(*t), in) << first;
    }
}

TEST(Tpdu, DeliverStatusReportAndCommand) {
    const Bytes deliver = hex("040b911032547698f0000062014141423200" "05e8329bfd06");
    auto d = decode_tpdu(deliver, TpDir::sc_to_ms);
    ASSERT_TRUE(d);
    EXPECT_EQ(d->scts, hex("62014141423200"));
    EXPECT_EQ(encode_tpdu(*d), deliver);

    const Bytes status = hex("062a0b911032547698f0" "62014141423200" "62014141423200" "00");
    auto s = decode_tpdu(status, TpDir::sc_to_ms);
    ASSERT_TRUE(s);
    EXPECT_FALSE(s->pi.has_value());   // 9.2.2.3: TP-PI is optional at the end
    EXPECT_EQ(s->dt, hex("62014141423200"));
    EXPECT_EQ(encode_tpdu(*s), status);

    const Bytes command = hex("022a00012a0b911032547698f000");
    auto c = decode_tpdu(command, TpDir::ms_to_sc);
    ASSERT_TRUE(c);
    EXPECT_EQ(c->type, TpduType::command);
    EXPECT_EQ(c->ct, 1);
    EXPECT_EQ(c->mn, 0x2a);
    EXPECT_EQ(encode_tpdu(*c), command);
}

// 9.2.2.1a: a report for RP-ERROR carries TP-FCS before TP-PI; for RP-ACK it does not.
TEST(Tpdu, ReportsCarryTheFailureCauseOnlyForRpError) {
    const Bytes in = hex("00d000");
    auto e = decode_tpdu(in, TpDir::ms_to_sc, true);
    ASSERT_TRUE(e);
    EXPECT_EQ(e->fcs, std::optional<std::uint8_t>{0xd0});
    EXPECT_EQ(e->pi, std::optional<std::uint8_t>{0x00});
    EXPECT_EQ(encode_tpdu(*e), in);
    auto a = decode_tpdu(hex("0000"), TpDir::ms_to_sc);
    ASSERT_TRUE(a);
    EXPECT_FALSE(a->fcs.has_value());
}

// 9.2.3.27: the extension bit announces another TP-PI octet; a reserved bit
// announces octets after TP-UD, which are discarded, not an error. TP-UDL
// without TP-DCS means the default alphabet.
TEST(Tpdu, ParameterIndicatorExtensionAndReservedBits) {
    const Bytes ext = hex("0087" "00" "0000" "05e8329bfd06");
    auto x = decode_tpdu(ext, TpDir::ms_to_sc);
    ASSERT_TRUE(x) << x.error().what;
    EXPECT_EQ(x->pi_more, hex("00"));
    EXPECT_EQ(gsm7_to_utf8(x->ud, x->udl), "hello");
    EXPECT_EQ(encode_tpdu(*x), ext);

    const Bytes reserved = hex("000c" "05e8329bfd06" "ffee");
    auto r = decode_tpdu(reserved, TpDir::ms_to_sc);
    ASSERT_TRUE(r) << r.error().what;
    EXPECT_FALSE(r->has_dcs);
    EXPECT_EQ(r->discarded, hex("ffee"));
    EXPECT_NE(to_json(*r).find("\"text\":\"hello\""), std::string::npos) << to_json(*r);
    EXPECT_EQ(encode_tpdu(*r), reserved);
}

TEST(Tpdu, ShortOrLongTpdusAreErrors) {
    auto longer = decode_tpdu(hex("112a0b911032547698f00000a708e8329bfd06"), TpDir::ms_to_sc);
    ASSERT_FALSE(longer);   // TP-UDL 8 septets: seven octets, five there
    EXPECT_EQ(longer.error().code, Errc::truncated);
    Bytes trailing = kSubmit;
    trailing.push_back(0);
    auto t = decode_tpdu(trailing, TpDir::ms_to_sc);
    ASSERT_FALSE(t);
    EXPECT_EQ(t.error().code, Errc::malformed);
}

// ---- TS 24.011 CP and RP --------------------------------------------------------------

TEST(Cp, DataAckAndError) {
    const Bytes data = hex("0901" "04" "062a0000");
    auto d = decode_cp(data);
    ASSERT_TRUE(d);
    EXPECT_EQ(d->type, CpType::data);
    EXPECT_EQ(d->user_data, hex("062a0000"));
    EXPECT_EQ(encode_cp(*d), data);

    auto a = decode_cp(hex("8904"));   // TI flag set (8.1.1, TS 24.007 11.2.3.1.3)
    ASSERT_TRUE(a);
    EXPECT_EQ(a->ti, 0x8);
    EXPECT_EQ(encode_cp(*a), hex("8904"));

    auto e = decode_cp(hex("091051"));   // CP-Cause 81: invalid transaction identifier value (8.1.4.2)
    ASSERT_TRUE(e);
    EXPECT_EQ(e->cause, 0x51);
}

TEST(Cp, WrongProtocolUnknownTypeOrTrailingOctets) {
    auto pd = decode_cp(hex("0801"));
    ASSERT_FALSE(pd);
    EXPECT_EQ(pd.error().code, Errc::malformed);
    auto t = decode_cp(hex("0905"));
    ASSERT_FALSE(t);
    EXPECT_EQ(t.error().code, Errc::unsupported);
    auto tr = decode_cp(hex("890400"));
    ASSERT_FALSE(tr);
    EXPECT_EQ(tr.error().code, Errc::malformed);
}

TEST(Rp, DataAckErrorAndSmma) {
    const Bytes data = hex("002a" "00" "0791448720010010" "07" "01000091000000");
    auto d = decode_rp(data);
    ASSERT_TRUE(d) << d.error().what;
    EXPECT_EQ(d->mti, RpMti::data_ms_n);
    EXPECT_TRUE(d->originator.empty());   // 7.3.1.2: empty MS to network
    EXPECT_EQ(d->destination, hex("91448720010010"));
    EXPECT_EQ(*d->user_data, hex("01000091000000"));
    EXPECT_EQ(encode_rp(*d), data);

    const Bytes ack = hex("032a" "41" "09" "010062014141423200");   // RP-ACK network to MS, with RP-User data
    auto a = decode_rp(ack);
    ASSERT_TRUE(a) << a.error().what;
    EXPECT_EQ(a->mti, RpMti::ack_n_ms);
    ASSERT_TRUE(a->user_data.has_value());
    EXPECT_EQ(encode_rp(*a), ack);

    const Bytes error = hex("042a" "026f01");   // RP-Cause 111 with a diagnostic octet (8.2.5.4)
    auto e = decode_rp(error);
    ASSERT_TRUE(e);
    EXPECT_EQ(e->cause, hex("6f01"));
    EXPECT_FALSE(e->user_data.has_value());
    EXPECT_EQ(encode_rp(*e), error);

    auto s = decode_rp(hex("062a"));
    ASSERT_TRUE(s);
    EXPECT_EQ(s->mti, RpMti::smma_ms_n);
}

TEST(Rp, ReservedTypesAndUnknownIes) {
    EXPECT_FALSE(decode_rp(hex("072a")));
    auto ie = decode_rp(hex("022a420100"));
    ASSERT_FALSE(ie);
    EXPECT_EQ(ie.error().code, Errc::malformed);
    auto cut = decode_rp(hex("002a00079144872001"));
    ASSERT_FALSE(cut);
    EXPECT_EQ(cut.error().code, Errc::truncated);
}

// N13: the UE's encoders for MO messages.
TEST(Ucs2, KoreanRoundTripsAndANonBmpCharacterIsRefused) {
    auto u = utf8_to_ucs2("안녕");
    ASSERT_TRUE(u);
    EXPECT_EQ(to_hex(*u), "c548b155");
    EXPECT_EQ(ucs2_to_utf8(*u), "안녕");
    EXPECT_FALSE(utf8_to_ucs2("\xF0\x9F\x98\x80"));   // U+1F600 is outside the BMP
}

TEST(SplitText, PartsHoldAtMostTheirSeptetsAndNeverCutAnEscape) {
    auto one = split_text("hello", false, 160);
    ASSERT_TRUE(one);
    EXPECT_EQ(one->size(), 1u);
    // 152 'a', then '[' (escape + septet): it does not fit the first 153-septet part.
    std::string t(152, 'a');
    t += "[b";
    auto two = split_text(t, false, 153);
    ASSERT_TRUE(two);
    ASSERT_EQ(two->size(), 2u);
    EXPECT_EQ((*two)[0], std::string(152, 'a'));
    EXPECT_EQ((*two)[1], "[b");
    auto u = split_text(std::string(std::size_t{3} * 67, 'x'), true, 67);
    ASSERT_TRUE(u);
    EXPECT_EQ(u->size(), 3u);
    EXPECT_FALSE(split_text("\xE2\x82\xAC\xE2\x98\x83", false, 160));   // a snowman is not GSM 7-bit
}

} // namespace
} // namespace ksim::sms
