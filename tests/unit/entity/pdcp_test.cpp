// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The PDCP entity (P1 N6; TS 38.323 j10 §5.2, §5.8, §5.9). Known answers:
// the six 128-EEA2 sets of TS 33.401 Annex C (= 128-NEA2, TS 33.501 D.4) go
// through a DRB entity with TX_NEXT at the set's COUNT, compared over the
// whole octets of each set's LENGTH; the SRB and SDAP vectors were made outside this code with the Python
// cryptography package (AES-CMAC for 128-NIA2, AES-CTR for 128-NEA2): keys
// 000102…0f (integrity) and f0e0…00 (ciphering).

#include <gtest/gtest.h>

#include <vector>

#include "../crypto/kat_file.hpp"
#include "entity/pdcp/pdcp.hpp"
#include "platform/mutation.hpp"
#include "platform/sim_loop.hpp"

namespace ksim::entity {
namespace {

Bytes h(const char* s) { return *from_hex(s); }
SecretBytes kint() { return SecretBytes::from_hex("000102030405060708090a0b0c0d0e0f").value(); }
SecretBytes kenc() { return SecretBytes::from_hex("f0e0d0c0b0a090807060504030201000").value(); }

struct Wire {
    std::vector<Bytes> down;   // to the lower layer
    std::vector<Bytes> up;     // delivered to the upper layer
    std::vector<std::uint32_t> failures;
};

Pdcp make(SimLoop& loop, Wire& w, PdcpConfig c) {
    return Pdcp(loop, c, [&w](Bytes b) { w.down.push_back(std::move(b)); }, [&w](Bytes b) { w.up.push_back(std::move(b)); });
}

TEST(Pdcp, Clause5_8_The128Eea2SetsCipherADrbByteForByte) {
    int checked = 0;
    for (const auto& [name, s] : kat::load("eea2")) {
        // A PDCP SDU is whole octets: the set's octets go through, and the
        // ciphertext is compared over the octets its LENGTH fills.
        const Bytes plain = s.bytes("Plaintext");
        const std::size_t whole = s.num("Length") / 8;
        const auto count = static_cast<std::uint32_t>(s.num("Count"));
        const auto bearer = static_cast<std::uint8_t>(s.num("Bearer"));
        const bool downlink = s.num("Direction") == 1;
        SimLoop loop;
        Wire tx_w;
        Wire rx_w;
        PdcpConfig c;
        c.srb = false;
        c.rb_id = static_cast<std::uint8_t>(bearer + 1);
        c.sn_tx = c.sn_rx = pdcp::SnSize::len18;
        c.side = downlink ? PdcpSide::gnb : PdcpSide::ue;
        Pdcp tx = make(loop, tx_w, c);
        c.side = downlink ? PdcpSide::ue : PdcpSide::gnb;
        Pdcp rx = make(loop, rx_w, c);
        ASSERT_TRUE(tx.set_keys(crypto::Nia::nia0, {}, crypto::Nea::nea2, s.secret("Key")));
        ASSERT_TRUE(rx.set_keys(crypto::Nia::nia0, {}, crypto::Nea::nea2, s.secret("Key")));
        tx.set_ciphering(true, true);
        rx.set_ciphering(true, true);
        tx.set_state(count, 0, 0);
        rx.set_state(0, count, count);
        tx.write_sdu(plain);
        ASSERT_EQ(tx_w.down.size(), 1u) << name;
        const Bytes& pdu = tx_w.down[0];
        EXPECT_EQ(to_hex(ByteView(pdu).subspan(3, whole)), to_hex(ByteView(s.bytes("Ciphertext")).subspan(0, whole)))
            << "set " << name;
        EXPECT_EQ(to_hex(ByteView(pdu).subspan(0, 3)), to_hex(pdcp::data_header(false, pdcp::SnSize::len18, count)));
        rx.on_pdu(pdu);
        ASSERT_EQ(rx_w.up.size(), 1u) << name;
        EXPECT_EQ(rx_w.up[0], plain);
        ++checked;
    }
    EXPECT_EQ(checked, 6);
}

// P2 Q8: 128-NEA1 through the entity, from the five SAGE UEA2 sets (128-EEA1 is UEA2,
// TS 33.401 B.1.2, C.3), compared over the whole octets of each set's LENGTH.
TEST(Pdcp, Clause5_8_The128Eea1SetsCipherADrbByteForByte) {
    int checked = 0;
    for (const auto& [name, s] : kat::load("uea2")) {
        const Bytes plain = s.bytes("Plaintext");
        const std::size_t whole = s.num("Length") / 8;
        const auto count = static_cast<std::uint32_t>(s.num("Count-C"));
        const auto bearer = static_cast<std::uint8_t>(s.num("Bearer"));
        const bool downlink = s.num("Direction") == 1;
        SimLoop loop;
        Wire tx_w;
        Wire rx_w;
        PdcpConfig c;
        c.srb = false;
        c.rb_id = static_cast<std::uint8_t>(bearer + 1);
        c.sn_tx = c.sn_rx = pdcp::SnSize::len18;
        c.side = downlink ? PdcpSide::gnb : PdcpSide::ue;
        Pdcp tx = make(loop, tx_w, c);
        c.side = downlink ? PdcpSide::ue : PdcpSide::gnb;
        Pdcp rx = make(loop, rx_w, c);
        ASSERT_TRUE(tx.set_keys(crypto::Nia::nia0, {}, crypto::Nea::nea1, s.secret("CK")));
        ASSERT_TRUE(rx.set_keys(crypto::Nia::nia0, {}, crypto::Nea::nea1, s.secret("CK")));
        tx.set_ciphering(true, true);
        rx.set_ciphering(true, true);
        tx.set_state(count, 0, 0);
        rx.set_state(0, count, count);
        tx.write_sdu(plain);
        ASSERT_EQ(tx_w.down.size(), 1u) << name;
        const Bytes& pdu = tx_w.down[0];
        EXPECT_EQ(to_hex(ByteView(pdu).subspan(3, whole)), to_hex(ByteView(s.bytes("Ciphertext")).subspan(0, whole)))
            << "set " << name;
        rx.on_pdu(pdu);
        ASSERT_EQ(rx_w.up.size(), 1u) << name;
        EXPECT_EQ(rx_w.up[0], plain);
        ++checked;
    }
    EXPECT_EQ(checked, 5);
}

// P2 Q8: the MAC-I is 128-NIA1's or NIA2's (their known-answer sets: tests/unit/crypto Kat.*)
// over the PDU's header and data with the entity's COUNT, BEARER and DIRECTION, from either
// side, and the peer verifies it; with ciphering, over the deciphered octets.
TEST(Pdcp, Clause5_9_TheMacIIsTheKatCheckedAlgorithmOverHeaderAndData) {
    for (const auto nia : {crypto::Nia::nia1, crypto::Nia::nia2}) {
        for (const auto side : {PdcpSide::ue, PdcpSide::gnb}) {
            SimLoop loop;
            Wire tx_w;
            Wire rx_w;
            PdcpConfig c;
            c.rb_id = 2;   // SRB2: BEARER 1
            c.side = side;
            Pdcp tx = make(loop, tx_w, c);
            c.side = side == PdcpSide::ue ? PdcpSide::gnb : PdcpSide::ue;
            Pdcp rx = make(loop, rx_w, c);
            const auto nea = nia == crypto::Nia::nia1 ? crypto::Nea::nea1 : crypto::Nea::nea2;
            ASSERT_TRUE(tx.set_keys(nia, kint(), nea, kenc()));
            ASSERT_TRUE(rx.set_keys(nia, kint(), nea, kenc()));
            tx.set_integrity(true, true);
            rx.set_integrity(true, true);
            tx.set_state(77, 0, 0);
            rx.set_state(0, 77, 77);
            const Bytes sdu = h("0102030405060708090a0b0c0d0e0f");
            tx.write_sdu(sdu);
            ASSERT_EQ(tx_w.down.size(), 1u);
            const Bytes& pdu = tx_w.down[0];
            const ByteView body(pdu.data(), pdu.size() - 4);
            const auto want = crypto::nia(nia, kint(), {77, 1, static_cast<std::uint8_t>(side == PdcpSide::ue ? 0 : 1)}, body);
            ASSERT_TRUE(want);
            EXPECT_EQ(to_hex(ByteView(pdu).subspan(pdu.size() - 4)), to_hex(ByteView(want->data(), 4)));
            rx.on_pdu(pdu);
            ASSERT_EQ(rx_w.up.size(), 1u);
            EXPECT_EQ(rx_w.up[0], sdu);
            tx.set_ciphering(true, true);
            rx.set_ciphering(true, true);
            tx.write_sdu(sdu);
            rx.on_pdu(tx_w.down.back());
            ASSERT_EQ(rx_w.up.size(), 2u);
            EXPECT_EQ(rx_w.up[1], sdu);
            EXPECT_EQ(rx.stats().integrity_failures, 0u);
        }
    }
}

// P2 Q8, mutant nia1_wrong_fresh (row ksim-p2.as-nea1-nia1): the UE side's 128-NIA1 with
// FRESH = BEARER unshifted no longer matches the network side's, which the row then sees.
TEST(Pdcp, Mutant_nia1_wrong_fresh_TheNetworkSideFindsTheUeMacWrong) {
    if (!kMutationsBuild) {
        GTEST_SKIP() << "a mutant build's test";
    }
    testing::MutantScope m("nia1_wrong_fresh");
    SimLoop loop;
    Wire ue_w;
    Wire gnb_w;
    PdcpConfig c;
    c.rb_id = 2;
    Pdcp ue = make(loop, ue_w, c);
    c.side = PdcpSide::gnb;
    Pdcp gnb = make(loop, gnb_w, c);
    ASSERT_TRUE(ue.set_keys(crypto::Nia::nia1, kint(), crypto::Nea::nea1, kenc()));
    ASSERT_TRUE(gnb.set_keys(crypto::Nia::nia1, kint(), crypto::Nea::nea1, kenc()));
    ue.set_integrity(true, true);
    gnb.set_integrity(true, true);
    ue.write_sdu(h("0102030405"));
    gnb.on_pdu(ue_w.down.at(0));
    EXPECT_EQ(gnb.stats().integrity_failures, 1u);
    EXPECT_TRUE(gnb_w.up.empty());
}

// P2 Q8: a PDU in order with nothing buffered is delivered straight away and leaves the
// reordering state as §5.2.2.1 would.
TEST(Pdcp, Clause5_2_2_1_InOrderPdusGoStraightUp) {
    SimLoop loop;
    Wire tx_w;
    Wire rx_w;
    PdcpConfig c;
    c.srb = false;
    c.sn_tx = c.sn_rx = pdcp::SnSize::len12;
    c.t_reordering = Millis{50};
    Pdcp tx = make(loop, tx_w, c);
    c.side = PdcpSide::gnb;
    Pdcp rx = make(loop, rx_w, c);
    for (int i = 0; i < 3; ++i) {
        tx.write_sdu(h("aa"));
        rx.on_pdu(tx_w.down.back());
    }
    EXPECT_EQ(rx_w.up.size(), 3u);
    EXPECT_EQ(rx.rx_deliv(), 3u);
    EXPECT_EQ(rx.rx_next(), 3u);
    EXPECT_FALSE(rx.t_reordering_running());
    tx.write_sdu(h("bb"));   // COUNT 3, lost
    tx.write_sdu(h("cc"));   // COUNT 4: waits for 3
    rx.on_pdu(tx_w.down.back());
    EXPECT_EQ(rx_w.up.size(), 3u);
    EXPECT_TRUE(rx.t_reordering_running());
    rx.on_pdu(tx_w.down[3]);
    EXPECT_EQ(rx_w.up.size(), 5u);
    EXPECT_EQ(rx_w.up[3], h("bb"));
    EXPECT_FALSE(rx.t_reordering_running());
}

TEST(Pdcp, Clause5_9_AnSrbPduMatchesTheIndependentVectors) {
    SimLoop loop;
    Wire w;
    PdcpConfig c;   // SRB1, the UE
    Pdcp p = make(loop, w, c);
    ASSERT_TRUE(p.set_keys(crypto::Nia::nia2, kint(), crypto::Nea::nea2, kenc()));
    p.set_state(5, 0, 0);
    p.set_integrity(true, true);
    p.write_sdu(h("2a2b2c2d2e2f303132"));
    p.set_ciphering(true, true);
    p.set_state(5, 0, 0);
    p.write_sdu(h("2a2b2c2d2e2f303132"));
    ASSERT_EQ(w.down.size(), 2u);
    EXPECT_EQ(to_hex(w.down[0]), "00052a2b2c2d2e2f3031327ecb3537");   // integrity only
    EXPECT_EQ(to_hex(w.down[1]), "0005e3540eb5e9a2ec15689d750790");   // and ciphered (data and MAC-I)
    EXPECT_EQ(p.tx_next(), 6u);
}

TEST(Pdcp, Clause6_3_4_AnSrbWithoutIntegrityCarriesAZeroMacI) {
    SimLoop loop;
    Wire w;
    Pdcp p = make(loop, w, PdcpConfig{});
    p.write_sdu(h("10"));
    ASSERT_EQ(w.down.size(), 1u);
    EXPECT_EQ(to_hex(w.down[0]), "00001000000000");
}

TEST(Pdcp, Clause5_9Note1_TheSecurityModeCommandIsCheckedOnceItsKeysAreKnown) {
    // The UE's SRB1 receives the command before integrity is on; RRC then sets
    // the keys and has its MAC-I checked (TS 38.331 §5.3.4.3).
    SimLoop loop;
    Wire w;
    Pdcp p = make(loop, w, PdcpConfig{});
    p.on_pdu(h("000022091000af3926bd"));
    ASSERT_EQ(w.up.size(), 1u);
    EXPECT_EQ(to_hex(w.up[0]), "22091000");
    ASSERT_TRUE(p.set_keys(crypto::Nia::nia2, kint(), crypto::Nea::nea2, kenc()));
    auto ok = p.verify_last_unprotected();
    ASSERT_TRUE(ok);
    EXPECT_TRUE(*ok);
    // A command with a forged MAC-I fails the same check.
    Pdcp q = make(loop, w, PdcpConfig{});
    q.on_pdu(h("000022091000af3926be"));
    ASSERT_TRUE(q.set_keys(crypto::Nia::nia2, kint(), crypto::Nea::nea2, kenc()));
    EXPECT_FALSE(*q.verify_last_unprotected());
}

TEST(Pdcp, Clause5_8_TheSdapHeaderIsNotCiphered) {
    SimLoop loop;
    Wire w;
    PdcpConfig c;
    c.srb = false;
    c.rb_id = 1;
    c.side = PdcpSide::gnb;
    c.sn_tx = c.sn_rx = pdcp::SnSize::len18;
    c.sdap_header_tx = true;
    Pdcp p = make(loop, w, c);
    ASSERT_TRUE(p.set_keys(crypto::Nia::nia0, {}, crypto::Nea::nea2, kenc()));
    p.set_ciphering(true, true);
    p.set_state(0x12345, 0, 0);
    p.write_sdu(h("014500001c0000"));
    ASSERT_EQ(w.down.size(), 1u);
    EXPECT_EQ(to_hex(w.down[0]), "812345018163554388f4");
}

TEST(Pdcp, Clause5_2_2_1_AFailedIntegrityCheckIsIndicatedAndNothingDelivered) {
    SimLoop loop;
    Wire w;
    PdcpConfig c;
    c.side = PdcpSide::gnb;   // receives the UE's uplink
    Pdcp p = make(loop, w, c);
    p.on_integrity_failure([&w](std::uint32_t count) { w.failures.push_back(count); });
    ASSERT_TRUE(p.set_keys(crypto::Nia::nia2, kint(), crypto::Nea::nea2, kenc()));
    p.set_integrity(true, true);
    p.set_ciphering(true, true);
    p.set_state(0, 5, 5);
    Bytes pdu = h("0005e3540eb5e9a2ec15689d750790");
    pdu[4] ^= 0x01;
    p.on_pdu(pdu);
    EXPECT_TRUE(w.up.empty());
    EXPECT_EQ(w.failures, std::vector<std::uint32_t>{5});
    p.on_pdu(h("0005e3540eb5e9a2ec15689d750790"));
    ASSERT_EQ(w.up.size(), 1u);
    EXPECT_EQ(to_hex(w.up[0]), "2a2b2c2d2e2f303132");
    p.on_pdu(h("0005e3540eb5e9a2ec15689d750790"));   // the same COUNT again: a duplicate
    EXPECT_EQ(w.up.size(), 1u);
    EXPECT_EQ(p.stats().discarded, 1u);
}

PdcpConfig drb12(Millis reordering) {
    PdcpConfig c;
    c.srb = false;
    c.rb_id = 1;
    c.side = PdcpSide::ue;
    c.t_reordering = reordering;
    return c;
}

Bytes dl(std::uint32_t sn, std::uint8_t payload) {
    Bytes p = pdcp::data_header(false, pdcp::SnSize::len12, sn);
    p.push_back(payload);
    return p;
}

TEST(Pdcp, Clause5_2_2_InOrderDeliveryWaitsForAGapUntilTReorderingExpires) {
    SimLoop loop;
    Wire w;
    Pdcp p = make(loop, w, drb12(100));
    p.on_pdu(dl(0, 0xA0));
    p.on_pdu(dl(2, 0xA2));   // SN 1 is missing
    p.on_pdu(dl(3, 0xA3));
    ASSERT_EQ(w.up.size(), 1u);
    EXPECT_TRUE(p.t_reordering_running());
    EXPECT_EQ(p.rx_deliv(), 1u);
    EXPECT_EQ(p.rx_next(), 4u);
    loop.run_for(99);
    EXPECT_EQ(w.up.size(), 1u);
    loop.run_for(1);   // §5.2.2.2: everything below RX_REORD (4) goes up
    ASSERT_EQ(w.up.size(), 3u);
    EXPECT_EQ(w.up[1], Bytes{0xA2});
    EXPECT_EQ(w.up[2], Bytes{0xA3});
    EXPECT_EQ(p.rx_deliv(), 4u);
    EXPECT_FALSE(p.t_reordering_running());
    p.on_pdu(dl(1, 0xA1));   // too late: below RX_DELIV
    EXPECT_EQ(w.up.size(), 3u);
}

TEST(Pdcp, Clause5_2_2_TheGapFilledInTimeDeliversTheRunAndStopsTheTimer) {
    SimLoop loop;
    Wire w;
    Pdcp p = make(loop, w, drb12(100));
    p.on_pdu(dl(1, 0xA1));
    EXPECT_TRUE(p.t_reordering_running());
    p.on_pdu(dl(0, 0xA0));
    ASSERT_EQ(w.up.size(), 2u);
    EXPECT_EQ(w.up[0], Bytes{0xA0});
    EXPECT_FALSE(p.t_reordering_running());
}

TEST(Pdcp, Clause5_2_2_1_TheHfnAdvancesAcrossTheSnWrap) {
    SimLoop loop;
    Wire w;
    Pdcp p = make(loop, w, drb12(100));
    p.set_state(0, 4095, 4095);
    p.on_pdu(dl(4095, 0x01));
    p.on_pdu(dl(0, 0x02));   // COUNT 4096: HFN 1
    ASSERT_EQ(w.up.size(), 2u);
    EXPECT_EQ(p.rx_deliv(), 4097u);
    p.on_pdu(dl(4095, 0x03));   // SN 4095 now reads as COUNT 4095: stale
    EXPECT_EQ(w.up.size(), 2u);
}

TEST(Pdcp, Clause5_2_2_1_OutOfOrderDeliveryDoesNotWait) {
    SimLoop loop;
    Wire w;
    PdcpConfig c = drb12(100);
    c.out_of_order = true;
    Pdcp p = make(loop, w, c);
    p.on_pdu(dl(2, 0xA2));
    p.on_pdu(dl(0, 0xA0));
    p.on_pdu(dl(2, 0xA2));   // a duplicate is still discarded
    ASSERT_EQ(w.up.size(), 2u);
    EXPECT_EQ(w.up[0], Bytes{0xA2});
    EXPECT_EQ(p.rx_deliv(), 1u);
}

} // namespace
} // namespace ksim::entity
