// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The EAP packet codec (P1 N12 follow-up): the RFC 3748 header, the EAP-AKA'
// header and attributes of RFC 4187 §8 and RFC 5448 §3, and where AT_MAC sits.

#include <gtest/gtest.h>

#include "codec/nas/eap.hpp"

namespace ksim::eap {
namespace {

Bytes hex(std::string_view h) { return *from_hex(h); }

TEST(Eap, Rfc3748_SuccessAndFailureAreFourOctets) {
    auto s = decode(hex("03070004"));
    ASSERT_TRUE(s);
    EXPECT_EQ(s->code, Code::success);
    EXPECT_EQ(s->id, 7);
    EXPECT_EQ(to_hex(*encode(Packet{Code::failure, 9, kTypeAkaPrime, Subtype::challenge, {}})), "04090004");
    EXPECT_FALSE(decode(hex("0307000500")));   // a success with data
    EXPECT_FALSE(decode(hex("03070005")));     // the length disagrees
    EXPECT_FALSE(decode(hex("0507000400")));   // no such code
}

TEST(Eap, Rfc5448_AChallengeEncodesAndDecodes) {
    const Bytes rand = hex("81e92b6c0ee0e12ebceba8d92a99dfa5");
    const Bytes autn = hex("bb52e91c747ac3ab2a5c23d15ee351d5");
    Packet p{Code::request, 1, kTypeAkaPrime, Subtype::challenge,
             {at_rand(rand), at_autn(autn), at_kdf(1), at_kdf_input("5G:mnc001.mcc001.3gppnetwork.org"), at_mac_zero()}};
    auto w = encode(p);
    ASSERT_TRUE(w);
    // Header 01 01 len, type 50, subtype 1, reserved; AT_RAND 01 05 0000 <16>.
    EXPECT_EQ(to_hex(Bytes(w->begin(), w->begin() + 12)), "0101" + to_hex(Bytes{(*w)[2], (*w)[3]}) + "3201000001050000");
    EXPECT_EQ((*w)[2] << 8 | (*w)[3], static_cast<int>(w->size()));
    auto back = decode(*w);
    ASSERT_TRUE(back);
    EXPECT_EQ(back->subtype, Subtype::challenge);
    ASSERT_EQ(back->attrs.size(), 5u);
    EXPECT_EQ(*value16(*back->find(Attr::rand)), rand);
    EXPECT_EQ(*value16(*back->find(Attr::autn)), autn);
    EXPECT_EQ(*kdf_of(*back->find(Attr::kdf)), 1);
    EXPECT_EQ(*network_name_of(*back->find(Attr::kdf_input)), "5G:mnc001.mcc001.3gppnetwork.org");
    // AT_MAC is the last attribute: its value is the packet's last 16 octets.
    ASSERT_TRUE(mac_offset(*w));
    EXPECT_EQ(*mac_offset(*w), w->size() - 16);
}

TEST(Eap, Rfc4187_10_8_AtResCarriesItsLengthInBits) {
    const Bytes res = hex("28d7b0f2a2ec3de5");
    const Attribute a = at_res(res);
    EXPECT_EQ(a.value.size() + 2, 12u);    // type, length, 2-octet bit length, 8 octets
    EXPECT_EQ(a.value[0], 0x00);
    EXPECT_EQ(a.value[1], 0x40);           // 64 bits
    EXPECT_EQ(*res_of(a), res);
    Attribute bad{static_cast<std::uint8_t>(Attr::res), hex("0010aabb")};   // 16 bits: under RFC 4187's 32
    EXPECT_FALSE(res_of(bad));
}

TEST(Eap, Rfc4187_8_1_AttributesThatOverrunOrHaveNoLengthAreMalformed) {
    EXPECT_FALSE(decode(hex("0201000c3201000001000000")));   // AT_RAND of length 0
    EXPECT_FALSE(decode(hex("0201000c3201000001050000")));   // AT_RAND claims 20 octets in 4
    EXPECT_FALSE(decode(hex("020100073201")));               // shorter than the AKA' header
    auto other = decode(hex("0201000601aa"));                // EAP-Response/Identity: no AKA' parsing
    ASSERT_TRUE(other);
    EXPECT_EQ(other->type, 1);
    EXPECT_TRUE(other->attrs.empty());
}

TEST(Eap, Rfc5448_3_2_AtAutsAndAClientErrorCode) {
    const Bytes auts = hex("0102030405060708090a0b0c0d0e");
    Packet p{Code::response, 3, kTypeAkaPrime, Subtype::synchronization_failure, {at_auts(auts), at_kdf(1)}};
    auto w = encode(p);
    ASSERT_TRUE(w);
    auto back = decode(*w);
    ASSERT_TRUE(back);
    EXPECT_EQ(*auts_of(*back->find(Attr::auts)), auts);
    EXPECT_FALSE(mac_offset(*w));   // no AT_MAC
    EXPECT_EQ(to_hex(at_client_error_code(0).value), "0000");
}

} // namespace
} // namespace ksim::eap
