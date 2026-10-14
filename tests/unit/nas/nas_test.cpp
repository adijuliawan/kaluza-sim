// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Spec-row tests for the 5GS NAS codec (plan M11): TS 24.007 11.2.4 (unknown
// IEs and comprehension required), TS 24.501 7.5-7.7 (error handling), 9.1.1
// and 9.3 (the security protected header), TS 24.008 10.5.6.3 (the ePCO
// container level), and a sweep of every message table.

#include <gtest/gtest.h>

#include <string_view>

#include "codec/nas/nas.hpp"

namespace ksim::nas {
namespace {

Bytes hex(std::string_view s) {
    Bytes out;
    for (std::size_t i = 0; i + 1 < s.size(); i += 2) {
        out.push_back(static_cast<std::uint8_t>(std::stoi(std::string(s.substr(i, 2)), nullptr, 16)));
    }
    return out;
}

Bytes cat(Bytes a, const Bytes& b) {
    a.insert(a.end(), b.begin(), b.end());
    return a;
}

// REGISTRATION REQUEST (8.2.6): initial registration with follow-on (9), ngKSI 7,
// and a 13-octet SUCI for PLMN 001/01 as the 5GS mobile identity.
const Bytes kReg = hex("7e004179000d0100f110000000000000000001");

TEST(Nas, DecodesTheImperativePartInTableOrder) {
    auto m = decode(kReg);
    ASSERT_TRUE(m) << m.error().what;
    ASSERT_STREQ(m->desc->name, "REGISTRATION REQUEST");
    ASSERT_EQ(m->ies.size(), 7U);
    // half-octet pairs: the IE listed first takes bits 4-1 (TS 24.007 11.2.1.1.1)
    EXPECT_EQ(m->find("5GS registration type")->value, Bytes{0x9});
    EXPECT_EQ(m->find("ngKSI")->value, Bytes{0x7});
    EXPECT_EQ(m->find("5GS mobile identity")->value.size(), 13U);
    EXPECT_EQ(m->find("5GS mobile identity")->offset, 4U);
    auto again = encode(*m);
    ASSERT_TRUE(again);
    EXPECT_EQ(*again, kReg);
}

TEST(Nas, AnOptionalIeIsFoundByName) {
    auto m = decode(cat(kReg, hex("100107")));
    ASSERT_TRUE(m);
    ASSERT_NE(m->find("5GMM capability"), nullptr);
    EXPECT_EQ(m->find("5GMM capability")->value, Bytes{0x07});
}

// TS 24.007 11.2.4 / TS 24.501 7.6.1: an unknown IE in the non-imperative part
// is skipped by its format, which the IEI implies, and the message is kept.
TEST(Nas, UnknownIesAreSkippedAndKept) {
    for (const char* extra : {"5a02aabb", "d3", "7c0001ff"}) {   // TLV, type 1, TLV-E
        const Bytes in = cat(cat(kReg, hex(extra)), hex("100107"));
        auto m = decode(in);
        ASSERT_TRUE(m) << extra << ": " << m.error().what;
        EXPECT_EQ(m->unknown_count(), 1U) << extra;
        ASSERT_NE(m->find("5GMM capability"), nullptr) << extra;
        auto again = encode(*m);
        ASSERT_TRUE(again);
        EXPECT_EQ(*again, in) << extra;
    }
}

// TS 24.501 7.5.1 with TS 24.007 11.2.4: an unknown IE encoded as
// "comprehension required" (TLV IEI 0000 xxxx, TLV-E 0x7E-0x7F) is an error.
TEST(Nas, AnUnknownComprehensionRequiredIeIsAnError) {
    for (const char* extra : {"050100", "7e000100"}) {
        auto m = decode(cat(kReg, hex(extra)));
        ASSERT_FALSE(m) << extra;
        EXPECT_EQ(m.error().code, Errc::malformed) << extra;
    }
}

// TS 24.501 7.6.3: a repeated IE; only the first occurrence is acted on.
TEST(Nas, ARepeatedIeIsMarkedAndTheFirstCounts) {
    const Bytes in = cat(kReg, hex("100107" "100103"));
    auto m = decode(in);
    ASSERT_TRUE(m);
    EXPECT_FALSE(m->ies[m->ies.size() - 2].repeated);
    EXPECT_TRUE(m->ies.back().repeated);
    EXPECT_EQ(m->find("5GMM capability")->value, Bytes{0x07});
    EXPECT_EQ(*encode(*m), in);
}

// TS 24.501 7.7.1 (non-imperative part): an optional IE whose length the table
// does not allow is treated as not present; the message is not rejected.
TEST(Nas, AnOptionalIeOutsideItsLengthRangeIsMarked) {
    auto m = decode(cat(kReg, hex("1000")));   // 5GMM capability, 3-15 octets: here 2
    ASSERT_TRUE(m);
    EXPECT_TRUE(m->ies.back().out_of_range);
}

// TS 24.501 7.5.1 / 7.5.2: a missing or short mandatory IE is a syntactical error.
TEST(Nas, AShortOrMissingMandatoryIeIsAnError) {
    Bytes cut(kReg.begin(), kReg.end() - 1);
    auto m = decode(cut);
    ASSERT_FALSE(m);
    EXPECT_EQ(m.error().code, Errc::truncated);
    EXPECT_FALSE(decode(hex("7e0041")));
    // mobile identity with 3 contents octets: the table allows 6-n with IEI-less LV-E, so 4 or more
    auto short_id = decode(hex("7e0041790003010203"));
    ASSERT_FALSE(short_id);
    EXPECT_EQ(short_id.error().code, Errc::malformed);
}

TEST(Nas, AnOptionalIeRunningPastTheEndIsAnError) {
    auto m = decode(cat(kReg, hex("100507")));
    ASSERT_FALSE(m);
    EXPECT_EQ(m.error().code, Errc::truncated);
}

TEST(Nas, AnUnknownMessageTypeOrProtocolIsRejected) {
    auto t = decode(hex("7e00ff"));
    ASSERT_FALSE(t);
    EXPECT_EQ(t.error().code, Errc::unsupported);
    auto p = decode(hex("074100"));
    ASSERT_FALSE(p);
    EXPECT_EQ(p.error().code, Errc::malformed);
}

// The 5GSM header (TS 24.501 9.1.1, 9.4, 9.6): PDU session ID and PTI octets.
TEST(Nas, The5gsmHeaderAndType1OptionalIes) {
    // PDU SESSION ESTABLISHMENT REQUEST (8.3.1): PSI 5, PTI 1, integrity
    // protection maximum data rate ffff, PDU session type IPv4 (9-), SSC mode 1 (A-)
    const Bytes in = hex("2e0501c1ffff91a1");
    auto m = decode(in);
    ASSERT_TRUE(m) << m.error().what;
    EXPECT_STREQ(m->desc->name, "PDU SESSION ESTABLISHMENT REQUEST");
    EXPECT_EQ(m->find("PDU session ID")->value, Bytes{0x05});
    EXPECT_EQ(m->find("PTI")->value, Bytes{0x01});
    EXPECT_EQ(m->find("Integrity protection maximum data rate")->value, hex("ffff"));
    EXPECT_EQ(m->find("PDU session type")->value, Bytes{0x1});
    EXPECT_EQ(m->find("SSC mode")->value, Bytes{0x1});
    EXPECT_EQ(*encode(*m), in);
}

// TS 24.501 8.2.28 and 9.3: security header type, MAC, sequence number, then
// the plain (or ciphered) message.
TEST(Nas, TheSecurityProtectedHeader) {
    const Bytes in = cat(hex("7e021122334405"), kReg);
    ASSERT_TRUE(is_protected(in));
    EXPECT_FALSE(is_protected(kReg));
    auto p = decode_protected(in);
    ASSERT_TRUE(p);
    EXPECT_EQ(p->security_header_type, 2);
    EXPECT_EQ(p->mac, 0x11223344U);
    EXPECT_EQ(p->sequence_number, 5);
    EXPECT_EQ(p->payload, kReg);
    EXPECT_EQ(encode_protected(*p), in);
    EXPECT_FALSE(decode_protected(hex("7e0211223344")));
    // the spare half octet is kept as received (found by the M14 fuzz smoke)
    const Bytes spare = cat(hex("7ef1a701b0c6ee"), hex("43"));
    auto q = decode_protected(spare);
    ASSERT_TRUE(q);
    EXPECT_EQ(q->spare, 0xF);
    EXPECT_EQ(encode_protected(*q), spare);
}

// Every message table: the mandatory IEs at their minimum length, then every
// optional IE at its minimum, encode and decode back to the same IEs.
TEST(Nas, EveryMessageTableRoundTrips) {
    ASSERT_EQ(messages().size(), 58U);
    for (const MsgDesc& md : messages()) {
        if (std::string_view(md.key) == "8.2.28") {
            continue;   // the security protected message: TheSecurityProtectedHeader
        }
        Message m;
        m.desc = &md;
        std::size_t optional = 0;
        std::size_t v_seen = 0;
        for (const IeDesc& d : md.table()) {
            Ie ie;
            ie.desc = &d;
            if (d.iei_kind == IeiKind::none) {
                if (d.half_octet()) {
                    ie.value = {0};
                } else if (d.format == Format::v) {
                    ie.value.assign(d.min_len, 0);
                    if (v_seen == 0) {
                        ie.value = {static_cast<std::uint8_t>(md.epd)};
                    } else if (std::string_view(d.type_name) == "Message type") {
                        ie.value = {md.type};
                    }
                    ++v_seen;
                } else {
                    ie.value.assign(d.min_len - (d.format == Format::lv ? 1 : 2), 0);
                }
            } else {
                ++optional;
                ie.iei = d.iei_kind == IeiKind::full ? d.iei : 0;
                switch (d.format) {
                case Format::t: break;
                case Format::tv: ie.value.assign(d.iei_kind == IeiKind::half ? 1 : d.min_len - 1, 0); break;
                case Format::tlv: ie.value.assign(d.min_len - 2, 0); break;
                case Format::tlv_e: ie.value.assign(d.min_len - 3, 0); break;
                default: FAIL() << md.key << " " << d.name << ": IEI with an imperative format";
                }
            }
            m.ies.push_back(std::move(ie));
        }
        auto bytes = encode(m);
        ASSERT_TRUE(bytes) << md.key << ": " << bytes.error().what;
        auto back = decode(*bytes);
        ASSERT_TRUE(back) << md.key << " " << md.name << ": " << back.error().what;
        EXPECT_EQ(back->desc, &md) << md.key;
        ASSERT_EQ(back->ies.size(), m.ies.size()) << md.key;
        EXPECT_EQ(back->unknown_count(), 0U) << md.key;
        for (std::size_t i = 0; i < m.ies.size(); ++i) {
            EXPECT_EQ(back->ies[i].desc, m.ies[i].desc) << md.key << " IE " << i;
            EXPECT_EQ(back->ies[i].value, m.ies[i].value) << md.key << " " << m.ies[i].desc->name;
            EXPECT_FALSE(back->ies[i].out_of_range) << md.key << " " << m.ies[i].desc->name;
            EXPECT_FALSE(back->ies[i].repeated) << md.key << " " << m.ies[i].desc->name;
        }
        EXPECT_EQ(*encode(*back), *bytes) << md.key;
        (void)optional;
    }
}

// TS 24.008 10.5.6.3 (the ePCO of TS 24.501 9.11.4.6 from octet 3): the NOTE to
// figure 10.5.136 gives a two-octet length to eight containers network to MS
// and three MS to network; every other unit has a one-octet length.
TEST(Epco, TheTwoOctetLengthsFollowTheDirection) {
    std::size_t ul = 0;
    std::size_t dl = 0;
    for (const EpcoDesc& d : epco_containers()) {
        if (d.length_octets == 2) {
            ++(d.direction == Direction::ul ? ul : dl);
        }
    }
    EXPECT_EQ(ul, 3U);
    EXPECT_EQ(dl, 8U);
    ASSERT_NE(find_epco(0x0023, Direction::ul), nullptr);
    EXPECT_EQ(find_epco(0x0023, Direction::ul)->length_octets, 1);   // the support indicator
    EXPECT_EQ(find_epco(0x0023, Direction::dl)->length_octets, 2);   // the QoS rules themselves
    EXPECT_EQ(find_epco(0x8021, Direction::ul), nullptr);           // IPCP: a protocol identifier
}

TEST(Epco, UnitsOfBothDirections) {
    // MS to network: IPCP with 4 octets, 0023H (one-octet length), 0041H (two-octet length)
    const Bytes up = hex("80" "80210410010000" "002300" "00410002abcd");
    auto u = decode_epco(up, Direction::ul);
    ASSERT_TRUE(u) << u.error().what;
    ASSERT_EQ(u->units.size(), 3U);
    EXPECT_EQ(u->units[0].id, 0x8021);
    EXPECT_EQ(u->units[0].contents, hex("10010000"));
    EXPECT_TRUE(u->units[1].contents.empty());
    EXPECT_EQ(u->units[2].contents, hex("abcd"));
    EXPECT_EQ(u->units[2].offset, 11U);
    EXPECT_EQ(*encode_epco(*u, Direction::ul), up);
    // network to MS: 0023H with a two-octet length, then DNS server IPv4 (000DH)
    const Bytes down = hex("80" "00230003010203" "000d0408080808");
    auto d = decode_epco(down, Direction::dl);
    ASSERT_TRUE(d) << d.error().what;
    ASSERT_EQ(d->units.size(), 2U);
    EXPECT_EQ(d->units[0].contents, hex("010203"));
    EXPECT_EQ(d->units[1].contents, hex("08080808"));
    EXPECT_EQ(*encode_epco(*d, Direction::dl), down);
    // the same octets read MS to network take 0023H's length as one octet and fail
    EXPECT_FALSE(decode_epco(down, Direction::ul));
}

TEST(Epco, ShortContentsAreErrors) {
    EXPECT_FALSE(decode_epco({}, Direction::ul));
    EXPECT_FALSE(decode_epco(hex("80000d"), Direction::ul));
    EXPECT_FALSE(decode_epco(hex("80000d0408"), Direction::dl));
    EXPECT_FALSE(decode_epco(hex("800023"), Direction::dl));
    Epco big;
    big.units.push_back({0x000d, Bytes(256, 0), 0});
    EXPECT_FALSE(encode_epco(big, Direction::dl));
}

TEST(Nas, JsonEscapesAndCarriesOffsets) {
    auto m = decode(cat(kReg, hex("5a02aabb")));
    ASSERT_TRUE(m);
    const std::string j = to_json(*m);
    EXPECT_NE(j.find("\"message\":\"REGISTRATION REQUEST\""), std::string::npos);
    EXPECT_NE(j.find("{\"unknown\":\"5a02aabb\",\"at\":19}"), std::string::npos) << j;
    EXPECT_NE(j.find("\"half\":true"), std::string::npos);
}

} // namespace
} // namespace ksim::nas
