// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// One sample of every NGAP builder (P1 N7), shared by the round-trip tests and
// msg_builders_dump, whose output the oracle checks with tshark and pycrate.

#pragma once

#include <string>
#include <vector>

#include "codec/asn1/msg/ngap.hpp"
#include "codec/asn1/msg/rrc.hpp"

namespace ksim::ngap::samples {

struct Sample {
    std::string name;
    Pdu pdu;
};

inline const PlmnId kPlmn = plmn_id("001", "01");

inline std::vector<Sample> all() {
    const Guami guami{kPlmn, 0xCA, 1, 1};
    const NrCgi cgi{kPlmn, 0x1A0000001};
    const Tai tai{kPlmn, 1};
    const Bytes nas = *from_hex("7e004179000d0100f110000000000000000001");
    std::vector<Sample> s;
    NgSetupRequest setup;
    setup.plmn = kPlmn;
    setup.gnb_id = 0x1A0;
    setup.name = "ksim-gnb1";
    setup.tas = {{1, {{kPlmn, {Snssai{1, std::nullopt}}}}}};
    s.push_back({"NGSetupRequest", setup});
    s.push_back({"NGSetupResponse", NgSetupResponse{"ksim-stub-amf", {guami}, 255, {{kPlmn, {Snssai{1, std::nullopt}}}}}});
    s.push_back({"NGSetupFailure", NgSetupFailure{Cause{"misc", "unspecified"}, "v10s"}});
    s.push_back({"NGReset", NgReset{Cause{"misc", "om-intervention"}, true, {}}});
    s.push_back({"NGReset.partial", NgReset{Cause{"radioNetwork", "unspecified"}, false, {UeIds{7, 1}, UeIds{std::nullopt, 2}}}});
    s.push_back({"NGResetAcknowledge", NgResetAcknowledge{{UeIds{7, 1}}}});
    s.push_back({"ErrorIndication", ErrorIndication{UeIds{7, 1}, Cause{"protocol", "abstract-syntax-error-reject"}}});
    s.push_back({"AMFStatusIndication", AmfStatusIndication{{guami}}});
    s.push_back({"AMFConfigurationUpdate", AmfConfigurationUpdate{"ksim-stub-amf"}});
    s.push_back({"AMFConfigurationUpdateAcknowledge", AmfConfigurationUpdateAcknowledge{}});
    s.push_back({"Paging", Paging{FiveGSTmsi{1, 1, 1}, {tai}, "v128"}});
    s.push_back({"InitialUEMessage", InitialUeMessage{1, nas, cgi, tai, "mo-Signalling", std::nullopt, true}});
    s.push_back({"InitialUEMessage.s-tmsi", InitialUeMessage{2, nas, cgi, tai, "mt-Access", FiveGSTmsi{1, 1, 1}, false}});
    s.push_back({"DownlinkNASTransport", DownlinkNasTransport{7, 1, *from_hex("7e005b01")}});
    s.push_back({"UplinkNASTransport", UplinkNasTransport{7, 1, *from_hex("7e0043"), cgi, tai}});
    s.push_back({"NASNonDeliveryIndication", NasNonDeliveryIndication{7, 1, *from_hex("7e0043"), Cause{"radioNetwork", "unspecified"}}});
    InitialContextSetupRequest ics;
    ics.amf = 7;
    ics.ran = 1;
    ics.guami = guami;
    ics.allowed_nssai = {Snssai{1, std::nullopt}};
    ics.nr_enc = 0xE000;
    ics.nr_int = 0xE000;
    ics.security_key = Bytes(32, 0xA5);   // a placeholder, not a derived key
    ics.nas = *from_hex("7e00420101");   // REGISTRATION ACCEPT: 3GPP access
    s.push_back({"InitialContextSetupRequest", ics});
    // P1 N10: sessions. The NAS PDUs are protected and ciphered, as an AMF sends
    // them, so the oracles see an opaque payload.
    const Bytes protected_nas = *from_hex("7e0212345678030102030405060708");
    SetupRequestTransfer st;
    st.session_ambr = Ambr{1'000'000'000, 1'000'000'000};
    st.ul = GtpTunnel{{172, 30, 50, 2}, 0x00000101};
    st.type = "ipv4";
    st.security = SecurityIndication{"preferred", "required", "maximum-UE-rate", std::nullopt};   // UL as the encoder fills it
    st.flows = {QosFlowRequest{1, 9, Arp{8, false, true}}};
    SessionSetupItem item{1, protected_nas, Snssai{1, 0x000001}, st};
    InitialContextSetupRequest ics_s = ics;
    ics_s.ue_ambr = Ambr{2'000'000'000, 1'000'000'000};
    ics_s.sessions = {SessionSetupItem{1, std::nullopt, Snssai{1, 0x000001}, st}};
    s.push_back({"InitialContextSetupRequest.sessions", ics_s});
    const SetupResponseTransfer rt{GtpTunnel{{172, 30, 30, 31}, 0x10000001}, {1}, SecurityResult{false, true}};
    s.push_back({"InitialContextSetupResponse", InitialContextSetupResponse{7, 1, {}, {}}});
    s.push_back({"InitialContextSetupResponse.sessions",
                 InitialContextSetupResponse{7, 1, {SessionSetupOk{1, rt}}, {SessionCause{2, Cause{"radioNetwork", "unspecified"}}}}});
    s.push_back({"PDUSessionResourceSetupRequest",
                 PduSessionResourceSetupRequest{7, 1, std::nullopt, {item}, Ambr{2'000'000'000, 1'000'000'000}}});
    // P2 Q9: integrity required at 64 kbit/s both ways (the DL rate in the IE's extension).
    SessionSetupItem rated = item;
    rated.transfer.security = SecurityIndication{"required", "not-needed", "bitrate64kbs", "bitrate64kbs"};
    s.push_back({"PDUSessionResourceSetupRequest.up-rates",
                 PduSessionResourceSetupRequest{7, 1, std::nullopt, {rated}, std::nullopt}});
    s.push_back({"PDUSessionResourceSetupResponse", PduSessionResourceSetupResponse{7, 1, {SessionSetupOk{1, rt}}, {}}});
    s.push_back({"PDUSessionResourceSetupResponse.failed",
                 PduSessionResourceSetupResponse{7, 1, {}, {SessionCause{5, Cause{"radioNetwork", "multiple-PDU-session-ID-instances"}}}}});
    s.push_back({"PDUSessionResourceReleaseCommand",
                 PduSessionResourceReleaseCommand{7, 1, protected_nas, {SessionCause{1, Cause{"nas", "normal-release"}}}}});
    s.push_back({"PDUSessionResourceReleaseResponse", PduSessionResourceReleaseResponse{7, 1, {1}}});
    ModifyRequestTransfer mt;
    mt.session_ambr = Ambr{500'000'000, 250'000'000};
    mt.add_or_modify = {QosFlowRequest{2, 7, Arp{9, false, true}}};
    mt.release = {3};
    s.push_back({"PDUSessionResourceModifyRequest",
                 PduSessionResourceModifyRequest{7, 1, {SessionModifyItem{1, protected_nas, mt}}}});
    s.push_back({"PDUSessionResourceModifyResponse",
                 PduSessionResourceModifyResponse{7, 1, {SessionModifyOk{1, ModifyResponseTransfer{{2}}}}, {}}});
    s.push_back({"InitialContextSetupFailure", InitialContextSetupFailure{7, 1, Cause{"radioNetwork", "unspecified"}}});
    s.push_back({"UEContextReleaseRequest", UeContextReleaseRequest{7, 1, Cause{"radioNetwork", "user-inactivity"}}});
    s.push_back({"UEContextReleaseCommand", UeContextReleaseCommand{7, 1, Cause{"nas", "normal-release"}}});
    s.push_back({"UEContextReleaseCommand.amf-only", UeContextReleaseCommand{7, std::nullopt, Cause{"nas", "deregister"}}});
    s.push_back({"UEContextReleaseComplete", UeContextReleaseComplete{7, 1}});
    s.push_back({"UEContextModificationRequest", UeContextModificationRequest{7, 1, std::nullopt}});
    s.push_back({"UEContextModificationResponse", UeContextModificationResponse{7, 1}});
    s.push_back({"UERadioCapabilityInfoIndication",
                 UeRadioCapabilityInfoIndication{7, 1, *rrc::radio_access_capability(*rrc::generic_nr_capability())}});
    return s;
}

} // namespace ksim::ngap::samples
