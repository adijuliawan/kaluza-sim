// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Spec-row tests for the typed NAS IEs (P1 N4; TS 24.501 j80 §9.11): values
// read and written back, and a corpus of contents each clause makes invalid
// (§7: what the entity then does is its own business; the codec refuses).

#include <gtest/gtest.h>

#include <functional>
#include <string>
#include <vector>

#include "codec/nas/ie/ie.hpp"

namespace ksim::nas::ie {
namespace {

Bytes h(const char* s) { return *from_hex(s); }

template <class T>
T ok(const char* hex) {
    auto r = T::decode(h(hex));
    EXPECT_TRUE(r) << T::kRef << " " << hex;
    return r ? *r : T{};
}

TEST(NasIe, Clause9_11_3_4_MobileIdentityNullSuciGutiStmsiImeisv) {
    // A null-scheme SUCI of 001/01 with routing indicator 0 and MSIN 0000300001.
    auto suci = MobileIdentity::null_suci(Plmn{"001", "01"}, "0000300001");
    auto enc = suci.encode();
    ASSERT_TRUE(enc);
    EXPECT_EQ(to_hex(*enc), "0100f110f0ff00000000030010");
    EXPECT_EQ(MobileIdentity::decode(*enc)->null_scheme_msin(), "0000300001");
    EXPECT_EQ(MobileIdentity::decode(*enc)->routing_indicator, "0");
    // 5G-GUTI 00101, AMF region 0xCA, set 0x3FE, pointer 1, 5G-TMSI 0x40C0DE17.
    const auto g = ok<MobileIdentity>("f200f110cafF8140c0de17");
    EXPECT_EQ(g.type, MobileIdentity::Type::guti);
    EXPECT_EQ(g.amf_region, 0xCA);
    EXPECT_EQ(g.amf_set, 0x3FE);
    EXPECT_EQ(g.amf_pointer, 1);
    EXPECT_EQ(g.tmsi, 0x40C0DE17u);
    EXPECT_EQ(to_hex(*g.encode()), "f200f110caff8140c0de17");
    const auto s = ok<MobileIdentity>("f4ff8140c0de17");
    EXPECT_EQ(s.type, MobileIdentity::Type::s_tmsi);
    EXPECT_EQ(s.amf_set, 0x3FE);
    MobileIdentity sv;
    sv.type = MobileIdentity::Type::imeisv;
    sv.digits = "3534901234567801";   // 16 digits: even, 'F' end mark
    EXPECT_EQ(to_hex(*sv.encode()), "3535941032547608f1");
    EXPECT_EQ(MobileIdentity::decode(*sv.encode())->digits, "3534901234567801");
}

TEST(NasIe, Clause9_11_3_9_TaiListAllThreeTypes) {
    // Type 00: 001/01 with TACs 1 and 7; type 01: 3 consecutive from 0x10; type 10: two TAIs.
    const auto l = ok<TaiList>("0100f110000001000007" "2200f110000010" "4100f11000000299f907000003");
    ASSERT_EQ(l.tais.size(), 7u);
    EXPECT_TRUE(l.contains(Tai{Plmn{"001", "01"}, 7}));
    EXPECT_TRUE(l.contains(Tai{Plmn{"001", "01"}, 0x12}));
    EXPECT_TRUE(l.contains(Tai{Plmn{"999", "70"}, 3}));
    EXPECT_FALSE(l.contains(Tai{Plmn{"001", "01"}, 0x13}));
    TaiList one;
    one.tais = {Tai{Plmn{"001", "01"}, 1}};
    EXPECT_EQ(to_hex(*one.encode()), "0000f110000001");
}

TEST(NasIe, Clause9_11_3_37_NssaiAndSnssai) {
    const auto n = ok<Nssai>("0101" "0401000001" "0501000001ff");
    ASSERT_EQ(n.list.size(), 3u);
    EXPECT_EQ(n.list[0].sst, 1);
    EXPECT_FALSE(n.list[0].sd);
    EXPECT_EQ(n.list[1].sd, 1u);
    EXPECT_EQ(n.list[2].mapped_sst, 0xFF);
    EXPECT_EQ(to_hex(*n.encode()), "010104010000010501000001ff");
    Nssai one;
    one.list = {Snssai{1, 0x000001, std::nullopt, std::nullopt}};
    EXPECT_EQ(to_hex(*one.encode()), "0401000001");
}

TEST(NasIe, Clause9_11_3_6_And_9A_RegistrationResultAndUpdateType) {
    const auto r = ok<RegistrationResult>("09");
    EXPECT_EQ(r.access, 1);
    EXPECT_TRUE(r.sms_allowed);
    EXPECT_EQ(ok<RegistrationResult>("05").access, 1);   // unused values read as 3GPP access
    UpdateType u;
    u.sms_requested = true;
    EXPECT_EQ(to_hex(u.encode()), "01");
}

TEST(NasIe, Clause9_11_2_TimersInMilliseconds) {
    EXPECT_EQ(ok<GprsTimer2>("2a").ms(), 10 * 60'000);          // unit 1 min, 10
    EXPECT_EQ(ok<GprsTimer3>("06").ms(), 6 * 600'000);          // unit 10 min, 6: one hour
    EXPECT_EQ(ok<GprsTimer3>("62").ms(), 2 * 2'000);            // unit 2 s
    EXPECT_FALSE(ok<GprsTimer3>("e0").ms());                    // deactivated
    EXPECT_EQ(ok<GprsTimer>("1f").ms(), 31 * 2'000);
}

TEST(NasIe, Clause9_11_4_13_QosRulesTheDefaultRuleWithMatchAll) {
    // Rule 1, create, DQR, one bidirectional filter (id 1, match-all), precedence 255, QFI 9.
    const auto q = ok<QosRules>("010006" "31" "3101" "01" "ff" "09");
    ASSERT_EQ(q.list.size(), 1u);
    const auto& r = q.list[0];
    EXPECT_EQ(r.id, 1);
    EXPECT_EQ(r.operation, 1);
    EXPECT_TRUE(r.default_rule);
    ASSERT_EQ(r.filters.size(), 1u);
    EXPECT_EQ(r.filters[0].direction, 3);
    EXPECT_EQ(r.filters[0].components[0].type, 0x01);
    EXPECT_EQ(r.precedence, 0xFF);
    EXPECT_EQ(r.qfi, 9);
    EXPECT_EQ(to_hex(*q.encode()), "01000631310101ff09");
    // An uplink filter with an IPv4 remote address and a remote port range.
    const auto q2 = ok<QosRules>("020013" "21" "22" "0e" "10" "c0a80000ffff0000" "51" "13881393" "0a" "05");
    EXPECT_EQ(q2.list[0].filters[0].components.size(), 2u);
    EXPECT_EQ(q2.list[0].filters[0].components[1].type, 0x51);
}

TEST(NasIe, Clause9_11_4_12_QosFlowDescriptionWith5qi) {
    // QFI 9, create, E bit, one parameter: 5QI 9.
    const auto d = ok<QosFlowDescriptions>("09" "20" "41" "010109");
    ASSERT_EQ(d.list.size(), 1u);
    EXPECT_EQ(d.list[0].qfi, 9);
    EXPECT_EQ(d.list[0].five_qi(), 9);
    EXPECT_EQ(to_hex(*d.encode()), "092041010109");
}

TEST(NasIe, Clause9_11_4_10_And_14_PduAddressAndSessionAmbr) {
    const auto a = ok<PduAddress>("010a2d0003");
    EXPECT_EQ(a.ipv4_text(), "10.45.0.3");
    EXPECT_EQ(to_hex(a.encode()), "010a2d0003");
    const auto v4v6 = ok<PduAddress>("0300000000000000010a2d0003");
    EXPECT_TRUE(v4v6.ipv6_iid);
    EXPECT_EQ(v4v6.ipv4_text(), "10.45.0.3");
    const auto ambr = ok<SessionAmbr>("060001" "0b0001");   // 1 Mbps down, 1 Gbps up
    EXPECT_EQ(ambr.dl_bps(), 1'000'000u);
    EXPECT_EQ(ambr.ul_bps(), 1'000'000'000u);
    EXPECT_EQ(ok<SessionAmbr>("020003" "070002").dl_bps(), 12'000u);   // 3 × 4 kbps
    EXPECT_EQ(ok<SessionAmbr>("020003" "070002").ul_bps(), 8'000'000u); // 2 × 4 Mbps
}

TEST(NasIe, Clause9_11_3_54_UeSecurityCapabilityAndAlgorithms) {
    const auto c = ok<UeSecurityCapability>("e0e0");
    EXPECT_TRUE(c.supports_ea(0));
    EXPECT_TRUE(c.supports_ea(2));
    EXPECT_FALSE(c.supports_ea(3));
    EXPECT_EQ(to_hex(c.encode()), "e0e0");
    const auto a = ok<NasSecurityAlgorithms>("22");
    EXPECT_EQ(a.ciphering, 2);
    EXPECT_EQ(a.integrity, 2);
    const auto k = ok<NgKsi>("09");
    EXPECT_TRUE(k.mapped);
    EXPECT_EQ(k.value, 1);
    EXPECT_TRUE(ok<NgKsi>("07").none());
}

TEST(NasIe, Clause9_11_2_1B_DnnLabels) {
    EXPECT_EQ(ok<Dnn>("08696e7465726e6574").name, "internet");
    Dnn d{"ims.mnc001.mcc001.gprs"};
    EXPECT_EQ(Dnn::decode(*d.encode())->name, "ims.mnc001.mcc001.gprs");
}

TEST(NasIe, Clause9_11_3_44_PsiBitmaps) {
    const auto b = ok<PsiBitmap>("2000");   // PSI 5
    EXPECT_TRUE(b.has(5));
    EXPECT_FALSE(b.has(1));
    PsiBitmap s;
    s.set(1);
    s.set(15);
    EXPECT_EQ(to_hex(s.encode()), "0280");
    s.set(0);   // PSI 0 is spare: never sent
    EXPECT_EQ(to_hex(s.encode()), "0280");
}

// §7: contents a clause makes impossible are refused.
TEST(NasIe, Clause7_ContentsTheClausesMakeImpossibleAreRefused) {
    struct Case {
        const char* what;
        std::function<bool()> refused;
    };
    const auto no = [](const auto& r) { return !r.has_value(); };
    const std::vector<Case> corpus = {
        {"S-NSSAI of 3 octets", [&] { return no(Snssai::decode(h("010000"))); }},
        {"NSSAI entry overruns", [&] { return no(Nssai::decode(h("0501000001"))); }},
        {"TAI list type 11", [&] { return no(TaiList::decode(h("6000f110000001"))); }},
        {"TAI list cut", [&] { return no(TaiList::decode(h("0100f110000001"))); }},
        {"5G-GUTI of 10 octets", [&] { return no(MobileIdentity::decode(h("f200f110caff8140c0de"))); }},
        {"SUCI cut before the scheme output", [&] { return no(MobileIdentity::decode(h("0100f110"))); }},
        {"PLMN digit A", [&] { return no(Plmn::decode(h("0af110"))); }},
        {"RAND of 15 octets", [&] { return no(Rand::decode(Bytes(15))); }},
        {"AUTN of 17 octets", [&] { return no(Autn::decode(Bytes(17))); }},
        {"RES* of 8 octets", [&] { return no(AuthenticationResponseParameter::decode(Bytes(8))); }},
        {"AUTS of 13 octets", [&] { return no(AuthenticationFailureParameter::decode(Bytes(13))); }},
        {"ABBA of one octet", [&] { return no(Abba::decode(h("00"))); }},
        {"registration type 000", [&] { return no(RegistrationType::decode(h("00"))); }},
        {"registration type 111", [&] { return no(RegistrationType::decode(h("07"))); }},
        {"de-registration access 00", [&] { return no(DeregistrationType::decode(h("08"))); }},
        {"NAS security algorithm 8", [&] { return no(NasSecurityAlgorithms::decode(h("82"))); }},
        {"UE security capability of 1 octet", [&] { return no(UeSecurityCapability::decode(h("e0"))); }},
        {"identity type 000", [&] { return no(IdentityType::decode(h("00"))); }},
        {"payload container type 0", [&] { return no(PayloadContainerType::decode(h("00"))); }},
        {"request type 111", [&] { return no(RequestType::decode(h("07"))); }},
        {"PDU session type 000", [&] { return no(PduSessionType::decode(h("00"))); }},
        {"SSC mode 111", [&] { return no(SscMode::decode(h("07"))); }},
        {"PDU address IPv4 of 3 octets", [&] { return no(PduAddress::decode(h("010a2d00"))); }},
        {"PDU address type unstructured", [&] { return no(PduAddress::decode(h("040a2d0003"))); }},
        {"session-AMBR unit 0", [&] { return no(SessionAmbr::decode(h("000001060001"))); }},
        {"session-AMBR of 5 octets", [&] { return no(SessionAmbr::decode(h("0600010600"))); }},
        {"QoS rule operation 0", [&] { return no(QosRules::decode(h("010006113101" "01ff09"))); }},
        {"QoS rule overruns", [&] { return no(QosRules::decode(h("010009313101" "01ff09"))); }},
        {"QoS rule without QFI", [&] { return no(QosRules::decode(h("010005313101" "01ff"))); }},
        {"packet filter component cut", [&] { return no(QosRules::decode(h("01000831" "310310c0a8" "ff09"))); }},
        {"QoS flow operation 0", [&] { return no(QosFlowDescriptions::decode(h("090041010109"))); }},
        {"QoS flow parameter overruns", [&] { return no(QosFlowDescriptions::decode(h("092041010209"))); }},
        {"max packet filters 16", [&] { return no(MaxPacketFilters::decode(h("0200"))); }},
        {"PLMN list of 4 octets", [&] { return no(PlmnList::decode(h("00f11000"))); }},
        {"rejected S-NSSAI of length 2", [&] { return no(RejectedNssai::decode(h("200101"))); }},
        {"DNN label overruns", [&] { return no(Dnn::decode(h("09696e7465726e6574"))); }},
        {"DNN label of 64 octets (found by fuzz_nas_ies)", [&] { Bytes b(65, 0x61); b[0] = 64; return no(Dnn::decode(b)); }},
        {"DNN label holding a dot", [&] { return no(Dnn::decode(h("03612e62"))); }},
        {"EAP shorter than its header", [&] { return no(EapMessage::decode(h("0101"))); }},
        {"access type 3", [&] { return no(AccessType::decode(h("03"))); }},
        {"ePCO DNS of 6 octets", [&] { return no(EpcoIpv4Dns::decode(h("080808080000"))); }},
    };
    for (const auto& c : corpus) {
        EXPECT_TRUE(c.refused()) << c.what;
    }
}

} // namespace
} // namespace ksim::nas::ie
