// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The C++ face of the asn1c libraries (codec/asn1/asn1.hpp, registry.hpp),
// on NGAP. The expected octets are pycrate 0.8.1's encoding of the same value
// (an independent encoder), computed once and written here.

#include <gtest/gtest.h>

#include <cstring>

#include "codec/asn1/asn1.hpp"
#include "codec/asn1/registry.hpp"

extern "C" {
#include "NGAP_BroadcastPLMNItem.h"
#include "NGAP_GlobalGNB-ID.h"
#include "NGAP_InitiatingMessage.h"
#include "NGAP_NGAP-PDU.h"
#include "NGAP_NGSetupRequest.h"
#include "NGAP_ProcedureCode.h"
#include "NGAP_ProtocolIE-Field.h"
#include "NGAP_ProtocolIE-ID.h"
#include "NGAP_SliceSupportItem.h"
#include "NGAP_SupportedTAItem.h"
}

namespace ksim::asn1 {
namespace {

// pycrate 0.8.1, APER: NGSetupRequest {GlobalRANNodeID gNB 00f110/1 (32 bits),
// RANNodeName "gnb1", SupportedTAList [TAC 000075, PLMN 00f110, SST 1], PagingDRX v128}
constexpr const char* kNgSetupHex =
    "00150030000004001b00090000f1105000000001005240060180676e62310066000d00000000750000f110"
    "000000080015400140";

void set_octets(OCTET_STRING_t& s, std::initializer_list<std::uint8_t> v) {
    ASSERT_EQ(OCTET_STRING_fromBuf(&s, reinterpret_cast<const char*>(std::data(v)), static_cast<int>(v.size())), 0);
}

Owned<NGAP_NGAP_PDU_t> build_ng_setup() {
    auto pdu = Owned<NGAP_NGAP_PDU_t>::make(asn_DEF_NGAP_NGAP_PDU);
    pdu->present = NGAP_NGAP_PDU_PR_initiatingMessage;
    auto* im = static_cast<NGAP_InitiatingMessage_t*>(std::calloc(1, sizeof(NGAP_InitiatingMessage_t)));
    pdu->choice.initiatingMessage = im;
    im->procedureCode = NGAP_ProcedureCode_id_NGSetup;
    im->criticality = NGAP_Criticality_reject;
    im->value.present = NGAP_InitiatingMessage__value_PR_NGSetupRequest;
    auto& ies = im->value.choice.NGSetupRequest.protocolIEs;

    auto& g = push_ie(ies, NGAP_ProtocolIE_ID_id_GlobalRANNodeID, NGAP_Criticality_reject,
                      NGAP_NGSetupRequestIEs__value_PR_GlobalRANNodeID);
    g.choice.GlobalRANNodeID.present = NGAP_GlobalRANNodeID_PR_globalGNB_ID;
    auto* gnb = static_cast<NGAP_GlobalGNB_ID_t*>(std::calloc(1, sizeof(NGAP_GlobalGNB_ID_t)));
    g.choice.GlobalRANNodeID.choice.globalGNB_ID = gnb;
    set_octets(gnb->pLMNIdentity, {0x00, 0xf1, 0x10});
    gnb->gNB_ID.present = NGAP_GNB_ID_PR_gNB_ID;
    auto& bits = gnb->gNB_ID.choice.gNB_ID;
    bits.buf = static_cast<std::uint8_t*>(std::calloc(1, 4));
    bits.size = 4;
    bits.buf[3] = 1;

    auto& n = push_ie(ies, NGAP_ProtocolIE_ID_id_RANNodeName, NGAP_Criticality_ignore,
                      NGAP_NGSetupRequestIEs__value_PR_RANNodeName);
    set_octets(n.choice.RANNodeName, {'g', 'n', 'b', '1'});

    auto& t = push_ie(ies, NGAP_ProtocolIE_ID_id_SupportedTAList, NGAP_Criticality_reject,
                      NGAP_NGSetupRequestIEs__value_PR_SupportedTAList);
    auto* ta = static_cast<NGAP_SupportedTAItem_t*>(std::calloc(1, sizeof(NGAP_SupportedTAItem_t)));
    set_octets(ta->tAC, {0x00, 0x00, 0x75});
    auto* bp = static_cast<NGAP_BroadcastPLMNItem_t*>(std::calloc(1, sizeof(NGAP_BroadcastPLMNItem_t)));
    set_octets(bp->pLMNIdentity, {0x00, 0xf1, 0x10});
    auto* sl = static_cast<NGAP_SliceSupportItem_t*>(std::calloc(1, sizeof(NGAP_SliceSupportItem_t)));
    set_octets(sl->s_NSSAI.sST, {0x01});
    EXPECT_EQ(asn_sequence_add(&bp->tAISliceSupportList.list, sl), 0);
    EXPECT_EQ(asn_sequence_add(&ta->broadcastPLMNList.list, bp), 0);
    EXPECT_EQ(asn_sequence_add(&t.choice.SupportedTAList.list, ta), 0);

    auto& d = push_ie(ies, NGAP_ProtocolIE_ID_id_DefaultPagingDRX, NGAP_Criticality_ignore,
                      NGAP_NGSetupRequestIEs__value_PR_PagingDRX);
    d.choice.PagingDRX = NGAP_PagingDRX_v128;
    return pdu;
}

TEST(Asn1Wrapper, PushIeBuildsWhatPycrateEncodes) {
    const auto pdu = build_ng_setup();
    auto bytes = encode(pdu, Rules::aper);
    ASSERT_TRUE(bytes) << bytes.error().what;
    EXPECT_EQ(to_hex(*bytes), kNgSetupHex);
}

TEST(Asn1Wrapper, DecodeEncodeJerRoundTrip) {
    const Bytes in = *from_hex(kNgSetupHex);
    auto v = decode(asn_DEF_NGAP_NGAP_PDU, Rules::aper, in);
    ASSERT_TRUE(v) << v.error().what;
    auto again = encode(*v, Rules::aper);
    ASSERT_TRUE(again);
    EXPECT_EQ(*again, in);
    auto jer = to_jer(*v);
    ASSERT_TRUE(jer);
    EXPECT_NE(jer->find("\"RANNodeName\":\"gnb1\""), std::string::npos) << *jer;
    auto back = from_jer(asn_DEF_NGAP_NGAP_PDU, *jer);
    ASSERT_TRUE(back) << back.error().what;
    auto again2 = encode(*back, Rules::aper);
    ASSERT_TRUE(again2);
    EXPECT_EQ(*again2, in);
}

TEST(Asn1Wrapper, RejectsTrailingAndTruncatedInput) {
    Bytes in = *from_hex(kNgSetupHex);
    Bytes longer = in;
    longer.push_back(0x00);
    auto t = decode(asn_DEF_NGAP_NGAP_PDU, Rules::aper, longer);
    ASSERT_FALSE(t);
    EXPECT_EQ(t.error().code, Errc::malformed);
    Bytes shorter(in.begin(), in.end() - 5);
    auto s = decode(asn_DEF_NGAP_NGAP_PDU, Rules::aper, shorter);
    ASSERT_FALSE(s);
    auto e = decode(asn_DEF_NGAP_NGAP_PDU, Rules::aper, ByteView{});
    EXPECT_FALSE(e);
}

TEST(Asn1Wrapper, StrictRefusesAnExtensionValueRelayCarriesIt) {
    // BitRate ::= INTEGER (0..4000000000000, ...): 4000000000001 is an extension value.
    const asn_TYPE_descriptor_t* br = find_type("ngap", "BitRate");
    ASSERT_NE(br, nullptr);
    auto v = from_jer(*br, "4000000000001");
    ASSERT_TRUE(v) << v.error().what;
    EXPECT_FALSE(encode(*v, Rules::aper, Check::strict));
    auto relayed = encode(*v, Rules::aper, Check::relay);
    ASSERT_TRUE(relayed);
    auto back = decode(*br, Rules::aper, *relayed);
    ASSERT_TRUE(back);
    EXPECT_EQ(*to_jer(*back), "4000000000001");
    // A non-extensible bound still refuses in relay: ProcedureCode is (0..255).
    const asn_TYPE_descriptor_t* pc = find_type("ngap", "ProcedureCode");
    ASSERT_NE(pc, nullptr);
    auto big = from_jer(*pc, "256");
    ASSERT_TRUE(big);
    EXPECT_FALSE(encode(*big, Rules::aper, Check::relay));
}

TEST(Asn1Registry, FindsTypesByEitherSpelling) {
    EXPECT_EQ(find_type("ngap", "NGAP-PDU"), &asn_DEF_NGAP_NGAP_PDU);
    EXPECT_EQ(find_type("ngap", "NGAP_PDU"), &asn_DEF_NGAP_NGAP_PDU);
    EXPECT_EQ(find_type("ngap", "No-Such-Type"), nullptr);
    EXPECT_EQ(find_type("nope", "NGAP-PDU"), nullptr);
    EXPECT_NE(find_type("rrc", "UL-DCCH-Message"), nullptr);
    EXPECT_EQ(rules_for("rrc"), Rules::uper);
    EXPECT_EQ(rules_for("xnap"), Rules::aper);
    EXPECT_GT(types("f1ap").size(), 1000U);
}

} // namespace
} // namespace ksim::asn1
