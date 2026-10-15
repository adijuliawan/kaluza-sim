// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The USIM layouts of what the UE keeps across power cycles (P1 N12; TS 31.102
// j60 4.4.11.2, 4.4.11.4, 4.4.11.6): EF.5GS3GPPLOCI byte for byte, a fresh
// card's contents, and a NAS security context stored and read back with its
// keys, COUNTs and algorithms.

#include <gtest/gtest.h>

#include "proc/ue/nas_sec/persist.hpp"

namespace ksim::proc::ue {
namespace {

namespace ie = nas::ie;

Bytes hex(std::string_view h) { return *from_hex(h); }

ie::MobileIdentity guti() {
    ie::MobileIdentity g;
    g.type = ie::MobileIdentity::Type::guti;
    g.plmn = {"001", "01"};
    g.amf_region = 0xCA;
    g.amf_set = 1;
    g.amf_pointer = 1;
    g.tmsi = 0x00000001;
    return g;
}

TEST(Persist, Ts31102_4_4_11_2_Loci) {
    persist::Loci l{guti(), ie::Tai{{"001", "01"}, 1}, 0};
    const Bytes b = persist::encode_loci(l);
    ASSERT_EQ(b.size(), 20u);
    // Bytes 1-13: the 5GS mobile identity IE from its length (000B), F2 for a 5G-GUTI, the PLMN 00F110,
    // region CA, set 1 and pointer 1 (0041), 5G-TMSI 00000001; bytes 14-19 the TAI; byte 20 5U1.
    EXPECT_EQ(to_hex(b), "000bf200f110ca00410000000100f11000000100");
    auto back = persist::decode_loci(b);
    ASSERT_TRUE(back);
    ASSERT_TRUE(back->guti.has_value());
    EXPECT_EQ(back->guti->tmsi, 1u);
    EXPECT_EQ(back->guti->amf_region, 0xCA);
    ASSERT_TRUE(back->tai.has_value());
    EXPECT_EQ(back->tai->tac, 1u);
    EXPECT_EQ(back->update_status, 0);
    // A fresh card (cards/usim-5g.yaml): no 5G-GUTI, a deleted TAI, 5U2 NOT UPDATED.
    auto fresh = persist::decode_loci(hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000001"));
    ASSERT_TRUE(fresh);
    EXPECT_FALSE(fresh->guti.has_value());
    EXPECT_FALSE(fresh->tai.has_value());
    EXPECT_EQ(fresh->update_status, 1);
    EXPECT_EQ(to_hex(persist::encode_loci(persist::Loci{})), "ffffffffffffffffffffffffffffffffffffff01");
    EXPECT_FALSE(persist::decode_loci(hex("00")));
}

TEST(Persist, Ts31102_4_4_11_4_AContextIsStoredAndReadBack) {
    auto kamf = SecretBytes::from_hex(std::string(64, 'a'));
    ASSERT_TRUE(kamf);
    auto ctx = NasSecurityContext::derive(ie::NgKsi{false, 3}, std::move(*kamf), 2, 2);
    ASSERT_TRUE(ctx);
    ctx->restore_counts(0x123, 0x45);
    const SecretBytes rec = persist::encode_nsc(&*ctx, 62);
    ASSERT_EQ(rec.size(), 62u);
    const ByteView r = rec.expose();
    EXPECT_EQ(r[0], 0xA0);
    EXPECT_EQ(r[2], 0x80);   // ngKSI
    EXPECT_EQ(r[4], 0x03);
    EXPECT_EQ(r[5], 0x81);   // K_AMF, 32 octets
    EXPECT_EQ(r[6], 32);
    EXPECT_EQ(r[61], 0xFF);  // padding
    auto back = persist::decode_nsc(r);
    ASSERT_TRUE(back);
    ASSERT_TRUE(back->has_value());
    EXPECT_EQ((*back)->ngksi().value, 3);
    EXPECT_EQ((*back)->ul_count(), 0x123u);
    EXPECT_EQ((*back)->dl_count(), 0x45u);
    EXPECT_EQ((*back)->ea(), 2);
    EXPECT_EQ((*back)->ia(), 2);
    EXPECT_TRUE(ct_equal((*back)->kamf(), ctx->kamf()));
    // Marked invalid (§4.4.2.1.2), or a fresh card's record: no context.
    const SecretBytes none = persist::encode_nsc(nullptr, 62);
    auto empty = persist::decode_nsc(none.expose());
    ASSERT_TRUE(empty);
    EXPECT_FALSE(empty->has_value());
    auto fresh = persist::decode_nsc(hex("A000" + std::string(120, 'F')));
    ASSERT_TRUE(fresh);
    EXPECT_FALSE(fresh->has_value());
    EXPECT_FALSE(persist::decode_nsc(hex("B000")));            // not the context's tag
    EXPECT_FALSE(persist::decode_nsc(hex("A0108001")));        // a length past the record
}

TEST(Persist, Ts31102_4_4_11_6_AuthKeys) {
    auto kausf = SecretBytes::from_hex(std::string(64, '1'));
    auto kseaf = SecretBytes::from_hex(std::string(64, '2'));
    ASSERT_TRUE(kausf && kseaf);
    const SecretBytes b = persist::encode_auth_keys(&*kausf, &*kseaf, 68);   // octets 0 to 67
    ASSERT_EQ(b.size(), 68u);
    const ByteView v = b.expose();
    EXPECT_EQ(v[0], 0x80);
    EXPECT_EQ(v[1], 32);
    EXPECT_EQ(v[34], 0x81);
    EXPECT_EQ(v[35], 32);
    EXPECT_EQ(v[67], 0x22);
}

} // namespace
} // namespace ksim::proc::ue
