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
    s.push_back({"InitialContextSetupResponse", InitialContextSetupResponse{7, 1}});
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
