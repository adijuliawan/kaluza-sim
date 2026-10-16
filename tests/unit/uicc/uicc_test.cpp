// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Spec-row tests for the UICC codecs (plan M12): APDUs (ETSI TS 102 221 10.1,
// 10.2, table 10.5; TS 31.102 7.1.2.1, 7.5.2), BER-TLV and the FCP template
// (TS 102 221 11.1.1.3, 11.1.1.4).

#include <gtest/gtest.h>

#include <string_view>

#include "codec/uicc/apdu.hpp"
#include "codec/uicc/fcp.hpp"

namespace ksim::uicc {
namespace {

Bytes hex(std::string_view s) {
    Bytes out;
    for (std::size_t i = 0; i + 1 < s.size(); i += 2) {
        out.push_back(static_cast<std::uint8_t>(std::stoi(std::string(s.substr(i, 2)), nullptr, 16)));
    }
    return out;
}

// Table 10.2: the four cases, told apart by length alone.
TEST(Apdu, TheFourCases) {
    struct C {
        const char* hex;
        ApduCase c;
        std::optional<std::uint16_t> le;
        std::size_t lc;
    };
    for (C t : {C{"00708001", ApduCase::one, std::nullopt, 0}, C{"00b0000009", ApduCase::two, 9, 0},
                C{"00c0000000", ApduCase::two, 256, 0}, C{"00a4000c023f00", ApduCase::three, std::nullopt, 2},
                C{"00a40004023f0000", ApduCase::four, 256, 2}}) {
        auto c = decode_command(hex(t.hex));
        ASSERT_TRUE(c) << t.hex;
        EXPECT_EQ(apdu_case(*c), t.c) << t.hex;
        EXPECT_EQ(c->le, t.le) << t.hex;
        EXPECT_EQ(c->data.size(), t.lc) << t.hex;
        EXPECT_EQ(*encode_command(*c), hex(t.hex)) << t.hex;
    }
    EXPECT_EQ(decode_command(hex("00a4000000000102")).error().code, Errc::unsupported);   // extended length
    EXPECT_EQ(decode_command(hex("00a40004023f000000")).error().code, Errc::malformed);
    EXPECT_EQ(decode_command(hex("00a400040300")).error().code, Errc::truncated);
    EXPECT_FALSE(decode_command(hex("00a400")));
}

// Tables 10.3 and 10.4a.
TEST(Apdu, ClassByte) {
    struct C {
        std::uint8_t cla;
        ClaInfo::Coding coding;
        std::uint8_t channel;
    };
    for (C t : {C{0x00, ClaInfo::Coding::interindustry, 0}, C{0x03, ClaInfo::Coding::interindustry, 3},
                C{0x81, ClaInfo::Coding::uicc, 1}, C{0xA0, ClaInfo::Coding::gsm, 0},
                C{0x40, ClaInfo::Coding::interindustry, 4}, C{0x4F, ClaInfo::Coding::interindustry, 19},
                C{0x6A, ClaInfo::Coding::interindustry, 14}, C{0xC5, ClaInfo::Coding::uicc, 9}}) {
        auto i = decode_cla(t.cla);
        ASSERT_TRUE(i) << int(t.cla);
        EXPECT_EQ(i->coding, t.coding) << int(t.cla);
        EXPECT_EQ(i->channel, t.channel) << int(t.cla);
    }
    EXPECT_EQ(decode_cla(0x10).error().code, Errc::unsupported);   // chaining (b5)
    EXPECT_EQ(decode_cla(0x20).error().code, Errc::malformed);
    EXPECT_EQ(decode_cla(0x6C).value().secure_messaging, 1);
}

// Table 10.5: the name depends on the INS and on which class coding is allowed.
TEST(Apdu, CommandNames) {
    EXPECT_STREQ(command_name(0x00, 0xA4), "SELECT FILE");
    EXPECT_EQ(command_name(0x80, 0xA4), nullptr);
    EXPECT_STREQ(command_name(0x80, 0xF2), "STATUS");
    EXPECT_EQ(command_name(0x00, 0xF2), nullptr);
    EXPECT_STREQ(command_name(0x81, 0x78), "GET IDENTITY");
    EXPECT_STREQ(command_name(0x00, 0x89), "AUTHENTICATE");
    EXPECT_STREQ(command_name(0x80, 0x10), "TERMINAL PROFILE");
    EXPECT_EQ(command_name(0x81, 0x10), nullptr);   // '80' only
    EXPECT_STREQ(command_name(0x41, 0xB2), "READ RECORD");
    EXPECT_NE(status_meaning(0x90, 0x00), nullptr);
    EXPECT_NE(status_meaning(0x63, 0xC2), nullptr);
    EXPECT_EQ(status_meaning(0x90, 0x01), nullptr);
}

// TS 31.102 7.1.2.1: the 3G/EPS/5G challenge and the three response forms.
TEST(Apdu, Authenticate) {
    const Bytes challenge = hex("10" "101112131415161718191a1b1c1d1e1f" "10" "202122232425262728292a2b2c2d2e2f");
    auto a = decode_auth_challenge(challenge, AuthContext::umts);
    ASSERT_TRUE(a);
    EXPECT_EQ(a->rand.size(), 16U);
    EXPECT_EQ(encode_auth_challenge(*a, AuthContext::umts), challenge);
    EXPECT_FALSE(decode_auth_challenge(challenge, AuthContext::gsm));   // the AUTN is extra there

    const Bytes ok = hex("db08" "4041424344454647" "10" "505152535455565758595a5b5c5d5e5f" "10"
                         "606162636465666768696a6b6c6d6e6f" "08" "7071727374757677");
    auto r = decode_auth_result(ok, AuthContext::umts);
    ASSERT_TRUE(r) << r.error().what;
    EXPECT_EQ(r->kind, AuthResult::Kind::success);
    EXPECT_EQ(r->ck.at, 11U);   // the key's place in the data, for the caller's SecretBytes
    EXPECT_EQ(r->ck.len, 16U);
    EXPECT_EQ(r->kc.len, 8U);
    EXPECT_EQ(encode_auth_success(r->res, r->ck.in(ok), r->ik.in(ok), r->kc.in(ok)), ok);

    const Bytes sync = hex("dc0e" "707172737475767778797a7b7c7d");
    auto s = decode_auth_result(sync, AuthContext::umts);
    ASSERT_TRUE(s);
    EXPECT_EQ(s->kind, AuthResult::Kind::sync_failure);
    EXPECT_EQ(encode_auth_sync_failure(s->auts), sync);

    const Bytes gsm = hex("04" "01020304" "08" "1112131415161718");
    auto g = decode_auth_result(gsm, AuthContext::gsm);
    ASSERT_TRUE(g);
    EXPECT_EQ(g->res, hex("01020304"));
    EXPECT_EQ(encode_auth_gsm(g->res, g->kc.in(gsm)), gsm);
    EXPECT_EQ(decode_auth_result(hex("dd00"), AuthContext::umts).error().code, Errc::malformed);
    // A Kc present but not 8 octets (TS 31.102 7.1.2.1): the fuzzer's empty one.
    EXPECT_EQ(decode_auth_result(hex("db0004000cdb00040020a50000"), AuthContext::umts).error().code, Errc::malformed);
}

// Keys and PINs never reach the JSON: CK, IK and Kc by length, PIN data by length.
TEST(Apdu, JsonKeepsKeysAndPinsOut) {
    auto c = decode_command(hex("0088008122" "10101112131415161718191a1b1c1d1e1f" "10202122232425262728292a2b2c2d2e2f" "00"));
    ASSERT_TRUE(c);
    auto r = decode_response(hex("db08" "4041424344454647" "10" "505152535455565758595a5b5c5d5e5f" "10"
                                 "606162636465666768696a6b6c6d6e6f" "9000"));
    ASSERT_TRUE(r);
    const std::string j = to_json(*c, &*r);
    EXPECT_NE(j.find("\"ck_len\":16"), std::string::npos) << j;
    EXPECT_EQ(j.find("505152535455565758595a5b5c5d5e5f"), std::string::npos) << j;
    EXPECT_EQ(j.find("606162636465666768696a6b6c6d6e6f"), std::string::npos) << j;
    auto v = decode_command(hex("0020000108" "31323334ffffffff"));
    ASSERT_TRUE(v);
    const std::string vj = to_json(*v, nullptr);
    EXPECT_EQ(vj.find("31323334"), std::string::npos) << vj;
    EXPECT_NE(vj.find("\"data_len\":8"), std::string::npos) << vj;
    auto g = decode_command(hex("00c000002c"));
    const std::string gj = to_json(*g, &*r);
    EXPECT_EQ(gj.find("505152535455565758595a5b5c5d5e5f"), std::string::npos) << gj;
}

// ---- BER-TLV and FCP -----------------------------------------------------------------------

const Bytes kMf = hex("6226" "82027821" "83023f00" "a506800171870101" "8a0105" "8b032f0601" "c60c" "900160"
                      "830101" "830181" "83010a");

TEST(Fcp, MasterFile) {
    auto f = decode_fcp(kMf);
    ASSERT_TRUE(f) << f.error().what;
    auto d = f->file_descriptor();
    ASSERT_TRUE(d);
    EXPECT_STREQ(d->file_type(), "df");
    EXPECT_TRUE(d->shareable());
    EXPECT_EQ(*f->file_id(), 0x3F00);
    EXPECT_EQ(*f->life_cycle(), 0x05);
    EXPECT_EQ(f->pin_key_references(), (std::vector<std::uint8_t>{0x01, 0x81, 0x0A}));
    // PS_DO '60': b8 (PIN1, '01') clear, b7 ('81') and b6 (ADM1, '0A') set (9.5.2)
    EXPECT_EQ(f->pin_enabled(0x01), std::optional<bool>(false));
    EXPECT_EQ(f->pin_enabled(0x81), std::optional<bool>(true));
    EXPECT_EQ(f->pin_enabled(0x0A), std::optional<bool>(true));
    EXPECT_EQ(f->pin_enabled(0x02), std::nullopt);   // not listed
    EXPECT_EQ(*encode_fcp(*f), kMf);
}

// KS-UICC-D4: the PIN's state comes from PS_DO, its bits in the order of the key
// references, a usage qualifier ('95') before a reference not counted as one.
TEST(Fcp, PinStateFromThePsDoWithUsageQualifiers) {
    auto f = decode_fcp(hex("6216" "82027821" "83023f00" "c60c" "900140" "950108" "830101" "830181"));
    ASSERT_TRUE(f) << f.error().what;
    EXPECT_EQ(f->pin_enabled(0x01), std::optional<bool>(false));
    EXPECT_EQ(f->pin_enabled(0x81), std::optional<bool>(true));
    auto no_c6 = decode_fcp(hex("620b" "82027821" "83023f00" "8a0105"));
    ASSERT_TRUE(no_c6) << no_c6.error().what;
    EXPECT_EQ(no_c6->pin_enabled(0x01), std::nullopt);
}

TEST(Fcp, ElementaryFilesAndTheirSfi) {
    // 11.1.1.4.8: '88' absent, the FID's low five bits; '88' empty, no SFI; '88' one octet, b8-b4
    auto l = decode_fcp(hex("621482054221001a04" "83026f40" "8a0105" "80020068" "8800"));
    ASSERT_TRUE(l) << l.error().what;
    EXPECT_STREQ(l->file_descriptor()->structure(), "linear_fixed");
    EXPECT_EQ(*l->file_descriptor()->record_length, 26);
    EXPECT_EQ(*l->file_descriptor()->records, 4);
    EXPECT_FALSE(l->sfi().has_value());
    auto t = decode_fcp(hex("6212820241218302" "6f07" "8a0105" "80020009" "880138"));
    ASSERT_TRUE(t);
    EXPECT_STREQ(t->file_descriptor()->structure(), "transparent");
    EXPECT_EQ(*t->sfi(), 7);
    EXPECT_EQ(*t->file_size(), 9U);
    auto n = decode_fcp(hex("620f820241218302" "6f07" "8a0105" "80020009"));
    ASSERT_TRUE(n);
    EXPECT_EQ(*n->sfi(), 0x07);   // 6F07 & 0x1F
    auto b = decode_fcp(hex("620e82027921" "83026fa1" "8a0105" "800120"));
    ASSERT_TRUE(b);
    EXPECT_STREQ(b->file_descriptor()->structure(), "ber_tlv");
}

TEST(Fcp, BerTlvFormsAreKept) {
    // a long-form length ('81') where the short form would do, and a two-octet tag
    const Bytes in = hex("5f2d8102656e" "a5038001ff");
    auto v = decode_ber(in);
    ASSERT_TRUE(v) << v.error().what;
    ASSERT_EQ(v->size(), 2U);
    EXPECT_EQ((*v)[0].tag, 0x5F2DU);
    EXPECT_EQ((*v)[0].length_octets, 2);
    EXPECT_TRUE((*v)[1].constructed());
    EXPECT_EQ((*v)[1].children.size(), 1U);
    EXPECT_EQ(*encode_ber(*v), in);
    EXPECT_EQ(decode_ber(hex("8205")).error().code, Errc::truncated);
    EXPECT_EQ(decode_ber(hex("8283")).error().code, Errc::malformed);
    EXPECT_EQ(decode_fcp(hex("6f0482027821")).error().code, Errc::malformed);   // not '62'
    EXPECT_EQ(decode_fcp(hex("620383010a")).error().code, Errc::malformed);     // no file descriptor
}

} // namespace
} // namespace ksim::uicc
