// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Spec-row tests for the USIM's AUTHENTICATE (P1 N3; TS 31.102 §7.1.2.1;
// TS 33.102 §6.3.3, §6.3.5, Annex C): the TS 35.208 and TS 35.233 test sets
// run through APDUs, the MAC failure, and the SQN check with its resync.

#include <gtest/gtest.h>

#include "../crypto/kat_file.hpp"
#include "codec/uicc/apdu.hpp"
#include "crypto/milenage.hpp"
#include "crypto/tuak.hpp"
#include "fixture.hpp"

namespace ksim::uicc::test {
namespace {

Bytes autn_of(ByteView sqn, ByteView ak, ByteView amf, ByteView mac) {
    Bytes a(16);
    for (std::size_t i = 0; i < 6; ++i) {
        a[i] = static_cast<std::uint8_t>(sqn[i] ^ ak[i]);
    }
    a[6] = amf[0];
    a[7] = amf[1];
    std::copy(mac.begin(), mac.end(), a.begin() + 8);
    return a;
}

std::string auth_apdu(ByteView rand, ByteView autn) {
    return "0088008122" + to_hex(encode_auth_challenge(AuthChallenge{Bytes(rand.begin(), rand.end()), Bytes(autn.begin(), autn.end())},
                                                      AuthContext::umts));
}

/// The test sets' SQNs are arbitrary 48-bit values, far above a fresh card's
/// zero: the Δ check (TS 33.102 Annex C.2.2) would rightly refuse them, so the
/// KAT runs switch it off in EF.USIM_SQN's first flag octet.
void no_delta_check(os::Card& card) {
    os::File& sqn = at(usim(card), 0xAF30);
    sqn.data.at(0) = static_cast<std::uint8_t>(sqn.data.at(0) & ~0x40);
}

/// Selects the USIM and runs one AUTHENTICATE with Le (no T=0 detour).
std::string authenticate(os::Card& card, ByteView rand, ByteView autn) {
    EXPECT_EQ(sw_of(apdu(card, "00A4040C07A0000000871002")), "9000");
    return apdu(card, auth_apdu(rand, autn) + "00");
}

TEST(Usim, Clause7_1_2_1_AuthenticateAnswersEveryTs35208MilenageSet) {
    const auto sets = kat::load("milenage");
    ASSERT_EQ(sets.size(), 20u);
    for (const auto& [name, s] : sets) {
        const SecretBytes k = s.secret("K");
        auto opc = crypto::milenage::opc(k, s.secret("OP"));
        ASSERT_TRUE(opc);
        auto card = make_card(test_secrets(k, *opc));
        no_delta_check(*card);
        const Bytes rand = s.bytes("RAND");
        const Bytes autn = autn_of(s.bytes("SQN"), s.bytes("f5"), s.bytes("AMF"), s.bytes("f1"));
        const std::string r = authenticate(*card, rand, autn);
        ASSERT_EQ(sw_of(r), "9000") << "set " << name;
        auto res = decode_auth_result(*from_hex(data_of(r)), AuthContext::umts);
        ASSERT_TRUE(res) << "set " << name;
        ASSERT_EQ(res->kind, AuthResult::Kind::success);
        const Bytes data = *from_hex(data_of(r));
        EXPECT_EQ(to_hex(res->res), s.hex("f2")) << "set " << name;
        EXPECT_EQ(to_hex(res->ck.in(data)), s.hex("f3")) << "set " << name;
        EXPECT_EQ(to_hex(res->ik.in(data)), s.hex("f4")) << "set " << name;
        EXPECT_EQ(res->kc.len, 0u) << "no GSM access (service 27): no Kc";
    }
}

TEST(Usim, Clause7_1_2_1_AWrongMacIs9862) {
    const auto sets = kat::load("milenage");
    const auto& s = sets.front().second;
    const SecretBytes k = s.secret("K");
    auto opc = crypto::milenage::opc(k, s.secret("OP"));
    auto card = make_card(test_secrets(k, *opc));
    Bytes mac = s.bytes("f1");
    mac[0] ^= 0x01;
    EXPECT_EQ(authenticate(*card, s.bytes("RAND"), autn_of(s.bytes("SQN"), s.bytes("f5"), s.bytes("AMF"), mac)), "9862");
}

// The SQN check: a test K and OPc, and AUTNs built with our Milenage for
// chosen SQNs (TS 33.102 Annex C.1: SQN = SEQ ‖ IND, IND five bits here).
struct SqnBench {
    SecretBytes k = sb("000102030405060708090a0b0c0d0e0f");
    SecretBytes opc = sb("f0e0d0c0b0a090807060504030201000");
    std::unique_ptr<os::Card> card = make_card(test_secrets(k, opc));
    Bytes rand = *from_hex("00112233445566778899aabbccddeeff");
    Bytes amf = *from_hex("8000");   // the separation bit set, as for 5G (TS 33.501 Annex A.2)

    static Bytes sqn48(std::uint64_t seq, std::uint64_t ind) {
        const std::uint64_t v = (seq << 5) | ind;
        Bytes b(6);
        for (int i = 5; i >= 0; --i) {
            b[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>((v >> (8 * (5 - i))) & 0xFF);
        }
        return b;
    }
    std::string run(std::uint64_t seq, std::uint64_t ind) {
        const Bytes sqn = sqn48(seq, ind);
        auto o = crypto::milenage::compute(k, opc, rand, sqn, amf);
        return authenticate(*card, rand, autn_of(sqn, o->ak.expose(), amf, o->mac_a));
    }
};

TEST(Usim, Annex_C_AReplayedSqnGivesAutsThatVerifies) {
    SqnBench b;
    ASSERT_EQ(sw_of(b.run(5, 3)), "9000");
    const std::string r = b.run(5, 3);   // the same SQN again: not fresh
    ASSERT_EQ(sw_of(r), "9000");
    auto res = decode_auth_result(*from_hex(data_of(r)), AuthContext::umts);
    ASSERT_TRUE(res);
    ASSERT_EQ(res->kind, AuthResult::Kind::sync_failure);
    ASSERT_EQ(res->auts.size(), 14u);
    // AUTS = SQN_MS ⊕ AK* ‖ MAC-S, with AK* = f5*(RAND) and MAC-S = f1*(SQN_MS, RAND, AMF = 0).
    auto star = crypto::milenage::compute(b.k, b.opc, b.rand, Bytes(6, 0), Bytes(2, 0));
    Bytes sqn_ms(6);
    for (std::size_t i = 0; i < 6; ++i) {
        sqn_ms[i] = static_cast<std::uint8_t>(res->auts[i] ^ star->ak_star.expose()[i]);
    }
    EXPECT_EQ(sqn_ms, SqnBench::sqn48(5, 3));
    auto check = crypto::milenage::compute(b.k, b.opc, b.rand, sqn_ms, Bytes(2, 0));
    EXPECT_EQ(Bytes(res->auts.begin() + 6, res->auts.end()), check->mac_s);
}

TEST(Usim, Annex_C_EachIndKeepsItsOwnHighestSeq) {
    SqnBench b;
    EXPECT_EQ(sw_of(b.run(10, 1)), "9000");
    EXPECT_EQ(data_of(b.run(9, 1)).substr(0, 2), "DC");   // lower SEQ, same IND: resync
    EXPECT_EQ(data_of(b.run(9, 2)).substr(0, 2), "DB");   // lower SEQ, another IND: fresh
    EXPECT_EQ(data_of(b.run(11, 1)).substr(0, 2), "DB");
}

TEST(Usim, Annex_C_2_TheDeltaCheckRefusesASqnTooFarAhead) {
    SqnBench b;
    ASSERT_EQ(data_of(b.run(100, 0)).substr(0, 2), "DB");
    // Δ is 2^28 in the template; SEQ is SQN >> 5.
    EXPECT_EQ(data_of(b.run(100 + (std::uint64_t{1} << 23) + 1, 4)).substr(0, 2), "DC");
    EXPECT_EQ(data_of(b.run(100 + (std::uint64_t{1} << 23) - 1, 4)).substr(0, 2), "DB");
}

TEST(Usim, Clause7_1_1_AuthenticateNeedsPin1WhenEnabledAndThe3gContext) {
    SqnBench b;
    ASSERT_EQ(sw_of(apdu(*b.card, "00A4040C07A0000000871002")), "9000");
    EXPECT_EQ(sw_of(apdu(*b.card, "0088008022" + std::string(68, '0'))), "6A86");   // the GSM context
    ASSERT_EQ(sw_of(apdu(*b.card, "0028000108" + pin_hex("1234"))), "9000");         // enable PIN1
    b.card->reset();
    EXPECT_EQ(sw_of(b.run(1, 0)), "6982");
    ASSERT_EQ(sw_of(apdu(*b.card, "0020000108" + pin_hex("1234"))), "9000");
    EXPECT_EQ(sw_of(apdu(*b.card, auth_apdu(b.rand, Bytes(16, 0)) + "00")), "9862");
}

TEST(Usim, Clause7_5_GetIdentityIs6985WhenTheMeComputesTheSuci) {
    auto card = make_card();
    ASSERT_EQ(sw_of(apdu(*card, "00A4040C07A0000000871002")), "9000");
    EXPECT_EQ(sw_of(apdu(*card, "8078000100")), "6985");   // service 125 is off in the template
}

TEST(Usim, Clause7_1_2_1_AuthenticateWithATuakKeyFile) {
    // TS 35.233 set 1 in an AF20 of the TUAK layout: config byte (TUAK, OP not
    // OPc, key length), TUAK config (CK/IK size, MAC size, RES size), Keccak
    // iterations, TOP, K.
    const auto sets = kat::load("tuak");
    const auto& s = sets.front().second;
    const auto bits = [&](const char* f) { return std::stoul(s.hex(f), nullptr, 16); };
    const unsigned klen = static_cast<unsigned>(bits("Klength"));
    const unsigned maclen = static_cast<unsigned>(bits("MAClength"));
    const unsigned reslen = static_cast<unsigned>(bits("RESLength"));
    const unsigned cklen = static_cast<unsigned>(bits("CKlength"));
    const std::uint8_t mac_code = maclen == 64 ? 0 : maclen == 128 ? 1 : 2;
    const std::uint8_t res_code = reslen == 32 ? 0 : reslen == 64 ? 1 : reslen == 128 ? 2 : 3;
    Bytes af20{static_cast<std::uint8_t>(0x06 | (klen == 256 ? 0x40 : 0x00)),
               static_cast<std::uint8_t>((cklen == 256 ? 0x40 : 0x00) | (mac_code << 3) | res_code),
               static_cast<std::uint8_t>(bits("KeccakIterations"))};
    const Bytes top = s.bytes("TOP");
    const Bytes key = s.bytes("K");
    af20.insert(af20.end(), top.begin(), top.end());
    af20.insert(af20.end(), key.begin(), key.end());
    auto sec = test_secrets(SecretBytes(16), SecretBytes(16));
    sec.set("ef.AF20", SecretBytes::copy_of(af20));
    auto card = make_card(sec);
    no_delta_check(*card);
    const Bytes autn = autn_of(s.bytes("SQN"), s.bytes("f5"), s.bytes("AMF"), s.bytes("f1"));
    // The template's AF20 is 33 octets; a TUAK set needs more, so this card's key file is sized by its secret.
    const std::string r = authenticate(*card, s.bytes("RAND"), autn);
    ASSERT_EQ(sw_of(r), "9000");
    const Bytes data = *from_hex(data_of(r));
    auto res = decode_auth_result(data, AuthContext::umts);
    ASSERT_TRUE(res);
    ASSERT_EQ(res->kind, AuthResult::Kind::success);
    EXPECT_EQ(to_hex(res->res), s.hex("f2"));
    EXPECT_EQ(to_hex(res->ck.in(data)), s.hex("f3"));
    EXPECT_EQ(to_hex(res->ik.in(data)), s.hex("f4"));
}

} // namespace
} // namespace ksim::uicc::test
