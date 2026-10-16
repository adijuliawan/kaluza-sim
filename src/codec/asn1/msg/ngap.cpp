// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "codec/asn1/msg/ngap.hpp"

#include <algorithm>
#include <map>

#include "codec/asn1/msg/jer.hpp"

extern "C" {
#include "NGAP_NGAP-PDU.h"
#include "NGAP_PDUSessionResourceModifyRequestTransfer.h"
#include "NGAP_PDUSessionResourceModifyResponseTransfer.h"
#include "NGAP_PDUSessionResourceModifyUnsuccessfulTransfer.h"
#include "NGAP_PDUSessionResourceNotifyReleasedTransfer.h"
#include "NGAP_PDUSessionResourceNotifyTransfer.h"
#include "NGAP_PDUSessionResourceReleaseCommandTransfer.h"
#include "NGAP_PDUSessionResourceReleaseResponseTransfer.h"
#include "NGAP_PDUSessionResourceSetupRequestTransfer.h"
#include "NGAP_PDUSessionResourceSetupResponseTransfer.h"
#include "NGAP_PDUSessionResourceSetupUnsuccessfulTransfer.h"
}

namespace ksim::ngap {

namespace {

using jer::arm;
using jer::bad;
using jer::bits;
using jer::guarded;
using jer::hex;
using jer::json;
using jer::read_bits;
using jer::read_octets;

// Procedure codes (NGAP-Constants).
constexpr int kAmfConfigurationUpdate = 0;
constexpr int kAmfStatusIndication = 1;
constexpr int kDownlinkNasTransport = 4;
constexpr int kErrorIndication = 9;
constexpr int kInitialContextSetup = 14;
constexpr int kInitialUeMessage = 15;
constexpr int kNasNonDeliveryIndication = 19;
constexpr int kNgReset = 20;
constexpr int kNgSetup = 21;
constexpr int kPaging = 24;
constexpr int kUeContextModification = 40;
constexpr int kUeContextRelease = 41;
constexpr int kUeContextReleaseRequest = 42;
constexpr int kUeRadioCapabilityInfoIndication = 44;
constexpr int kUplinkNasTransport = 46;
constexpr int kPduSessionResourceModify = 26;
constexpr int kPduSessionResourceNotify = 30;   // P2 Q10
constexpr int kPduSessionResourceRelease = 28;
constexpr int kPduSessionResourceSetup = 29;

// Protocol IE identifiers.
constexpr int kAllowedNssai = 0;
constexpr int kAmfName = 1;
constexpr int kAmfUeNgapId = 10;
constexpr int kCause = 15;
constexpr int kDefaultPagingDrx = 21;
constexpr int kFiveGSTmsi = 26;
constexpr int kGlobalRanNodeId = 27;
constexpr int kGuami = 28;
constexpr int kMaskedImeisv = 34;
constexpr int kNasPdu = 38;
constexpr int kPagingDrx = 50;
constexpr int kPlmnSupportList = 80;
constexpr int kRanNodeName = 82;
constexpr int kRanUeNgapId = 85;
constexpr int kRelativeAmfCapacity = 86;
constexpr int kResetType = 88;
constexpr int kRrcEstablishmentCause = 90;
constexpr int kSecurityKey = 94;
constexpr int kServedGuamiList = 96;
constexpr int kSupportedTaList = 102;
constexpr int kTaiListForPaging = 103;
constexpr int kTimeToWait = 107;
constexpr int kUeAssociatedConnectionList = 111;
constexpr int kUeContextRequest = 112;
constexpr int kUeNgapIds = 114;
constexpr int kFailedToModifyListModRes = 54;
constexpr int kFailedToSetupListCxtRes = 55;
constexpr int kFailedToSetupListSuRes = 58;
constexpr int kModifyListModReq = 64;
constexpr int kModifyListModRes = 65;
constexpr int kReleasedListRelRes = 70;
constexpr int kSetupListCxtReq = 71;
constexpr int kSetupListCxtRes = 72;
constexpr int kSetupListSuReq = 74;
constexpr int kSetupListSuRes = 75;
constexpr int kToReleaseListRelCmd = 79;
constexpr int kUeAmbr = 110;
constexpr int kSessionAmbr = 130;
constexpr int kPduSessionType = 134;
constexpr int kQosFlowAddOrModifyRequestList = 135;
constexpr int kQosFlowSetupRequestList = 136;
constexpr int kQosFlowToReleaseList = 137;
constexpr int kSecurityIndication = 138;
constexpr int kMaxIntegrityRateDl = 151;   // id-MaximumIntegrityProtectedDataRate-DL (P2 Q9)
constexpr int kUlNguUpTnlInformation = 139;
constexpr int kUePagingIdentity = 115;
constexpr int kUeRadioCapability = 117;
constexpr int kUeSecurityCapabilities = 119;
constexpr int kUnavailableGuamiList = 120;
constexpr int kUserLocationInformation = 121;
constexpr int kNotifyList = 66;                  // P2 Q10: PDUSessionResourceNotifyList
constexpr int kReleasedListNot = 67;             // PDUSessionResourceReleasedListNot

constexpr std::uint64_t kMaxAmfUeId = (std::uint64_t{1} << 40) - 1;

// ---- IE values ----------------------------------------------------------------------

json plmn(const PlmnId& p) { return hex(p); }

PlmnId read_plmn(const json& j) {
    const Bytes b = read_octets(j);
    if (b.size() != 3) {
        throw json::other_error::create(501, "PLMN identity is three octets", &j);
    }
    return {b[0], b[1], b[2]};
}

std::string octets(std::uint64_t v, unsigned n) {
    Bytes b(n);
    for (unsigned i = 0; i < n; ++i) {
        b[i] = static_cast<std::uint8_t>(v >> (8 * (n - 1 - i)));
    }
    return hex(b);
}

std::uint64_t read_number(const json& j) {
    std::uint64_t v = 0;
    for (std::uint8_t o : read_octets(j)) {
        v = (v << 8) | o;
    }
    return v;
}

json snssai(const Snssai& s) {
    json j = {{"sST", octets(s.sst, 1)}};
    if (s.sd) {
        j["sD"] = octets(*s.sd, 3);
    }
    return j;
}

Snssai read_snssai(const json& j) {
    Snssai s;
    s.sst = static_cast<std::uint8_t>(read_number(j.at("sST")));
    if (j.contains("sD")) {
        s.sd = static_cast<std::uint32_t>(read_number(j.at("sD")));
    }
    return s;
}

json slice_list(const std::vector<Snssai>& l) {
    json out = json::array();
    for (const auto& s : l) {
        out.push_back({{"s-NSSAI", snssai(s)}});
    }
    return out;
}

std::vector<Snssai> read_slice_list(const json& j) {
    std::vector<Snssai> out;
    for (const auto& e : j) {
        out.push_back(read_snssai(e.at("s-NSSAI")));
    }
    return out;
}

json tai(const Tai& t) { return {{"pLMNIdentity", plmn(t.plmn)}, {"tAC", octets(t.tac, 3)}}; }
Tai read_tai(const json& j) { return {read_plmn(j.at("pLMNIdentity")), static_cast<std::uint32_t>(read_number(j.at("tAC")))}; }

json nr_cgi(const NrCgi& c) { return {{"pLMNIdentity", plmn(c.plmn)}, {"nRCellIdentity", bits(c.nci, 36)}}; }
NrCgi read_nr_cgi(const json& j) { return {read_plmn(j.at("pLMNIdentity")), read_bits(j.at("nRCellIdentity"), 36)}; }

json guami(const Guami& g) {
    return {{"pLMNIdentity", plmn(g.plmn)},
            {"aMFRegionID", bits(g.region, 8)},
            {"aMFSetID", bits(g.set, 10)},
            {"aMFPointer", bits(g.pointer, 6)}};
}

Guami read_guami(const json& j) {
    return {read_plmn(j.at("pLMNIdentity")), static_cast<std::uint8_t>(read_bits(j.at("aMFRegionID"), 8)),
            static_cast<std::uint16_t>(read_bits(j.at("aMFSetID"), 10)),
            static_cast<std::uint8_t>(read_bits(j.at("aMFPointer"), 6))};
}

json s_tmsi(const FiveGSTmsi& s) {
    return {{"aMFSetID", bits(s.set, 10)}, {"aMFPointer", bits(s.pointer, 6)}, {"fiveG-TMSI", octets(s.tmsi, 4)}};
}

FiveGSTmsi read_s_tmsi(const json& j) {
    return {static_cast<std::uint16_t>(read_bits(j.at("aMFSetID"), 10)),
            static_cast<std::uint8_t>(read_bits(j.at("aMFPointer"), 6)),
            static_cast<std::uint32_t>(read_number(j.at("fiveG-TMSI")))};
}

json cause(const Cause& c) { return {{c.group, c.value}}; }
Cause read_cause(const json& j) {
    auto [g, v] = arm(j);
    return {g, v->get<std::string>()};
}

json uli(const NrCgi& c, const Tai& t) {
    return {{"userLocationInformationNR", {{"nR-CGI", nr_cgi(c)}, {"tAI", tai(t)}}}};
}

json connections(const std::vector<UeIds>& l) {
    json out = json::array();
    for (const auto& c : l) {
        json e = json::object();
        if (c.amf) {
            e["aMF-UE-NGAP-ID"] = *c.amf;
        }
        if (c.ran) {
            e["rAN-UE-NGAP-ID"] = *c.ran;
        }
        out.push_back(e);
    }
    return out;
}

std::vector<UeIds> read_connections(const json& j) {
    std::vector<UeIds> out;
    for (const auto& e : j) {
        UeIds ids;
        if (e.contains("aMF-UE-NGAP-ID")) {
            ids.amf = e.at("aMF-UE-NGAP-ID").get<std::uint64_t>();
        }
        if (e.contains("rAN-UE-NGAP-ID")) {
            ids.ran = e.at("rAN-UE-NGAP-ID").get<std::uint32_t>();
        }
        out.push_back(ids);
    }
    return out;
}

bool plmns_ok(const std::vector<PlmnSlices>& l) {
    return !l.empty() && std::all_of(l.begin(), l.end(), [](const PlmnSlices& p) { return !p.slices.empty(); });
}

// ---- PDU frame ------------------------------------------------------------------------

json ie(int id, const char* criticality, const char* type, json value) {
    return {{"id", id}, {"criticality", criticality}, {"value", {{type, std::move(value)}}}};
}

json pdu(const char* kind, int code, const char* criticality, const char* message, json ies) {
    return {{kind,
             {{"procedureCode", code},
              {"criticality", criticality},
              {"value", {{message, {{"protocolIEs", std::move(ies)}}}}}}}};
}

json initiating(int code, const char* crit, const char* message, json ies) {
    return pdu("initiatingMessage", code, crit, message, std::move(ies));
}
json successful(int code, const char* crit, const char* message, json ies) {
    return pdu("successfulOutcome", code, crit, message, std::move(ies));
}
json unsuccessful(int code, const char* crit, const char* message, json ies) {
    return pdu("unsuccessfulOutcome", code, crit, message, std::move(ies));
}

json ids(std::uint64_t amf, std::uint32_t ran, const char* crit = "reject") {
    return json::array({ie(kAmfUeNgapId, crit, "AMF-UE-NGAP-ID", amf), ie(kRanUeNgapId, crit, "RAN-UE-NGAP-ID", ran)});
}

Result<Bytes> per(const json& j) { return jer::encode(asn_DEF_NGAP_NGAP_PDU, j, asn1::Rules::aper); }

// ---- builders ---------------------------------------------------------------------------

Result<Bytes> build(const NgSetupRequest& m) {
    if (m.gnb_id_bits < 22 || m.gnb_id_bits > 32 || (m.gnb_id_bits < 32 && m.gnb_id >> m.gnb_id_bits != 0) ||
        m.tas.empty()) {
        return bad("NGAP: a gNB ID of 22..32 bits and at least one TA");
    }
    json tas = json::array();
    for (const auto& t : m.tas) {
        if (!plmns_ok(t.plmns) || t.tac >> 24 != 0) {
            return bad("NGAP: each TA needs a 24-bit TAC and PLMNs with slices");
        }
        json plmns = json::array();
        for (const auto& p : t.plmns) {
            plmns.push_back({{"pLMNIdentity", plmn(p.plmn)}, {"tAISliceSupportList", slice_list(p.slices)}});
        }
        tas.push_back({{"tAC", octets(t.tac, 3)}, {"broadcastPLMNList", plmns}});
    }
    json ies = json::array();
    ies.push_back(ie(kGlobalRanNodeId, "reject", "GlobalRANNodeID",
                     {{"globalGNB-ID",
                       {{"pLMNIdentity", plmn(m.plmn)}, {"gNB-ID", {{"gNB-ID", jer::var_bits(m.gnb_id, m.gnb_id_bits)}}}}}}));
    if (!m.name.empty()) {
        ies.push_back(ie(kRanNodeName, "ignore", "RANNodeName", m.name));
    }
    ies.push_back(ie(kSupportedTaList, "reject", "SupportedTAList", tas));
    ies.push_back(ie(kDefaultPagingDrx, "ignore", "PagingDRX", m.paging_drx));
    return per(initiating(kNgSetup, "reject", "NGSetupRequest", ies));
}

json plmn_support(const std::vector<PlmnSlices>& l) {
    json out = json::array();
    for (const auto& p : l) {
        out.push_back({{"pLMNIdentity", plmn(p.plmn)}, {"sliceSupportList", slice_list(p.slices)}});
    }
    return out;
}

Result<Bytes> build(const NgSetupResponse& m) {
    if (m.amf_name.empty() || m.guamis.empty() || !plmns_ok(m.plmns)) {
        return bad("NGAP: NG SETUP RESPONSE needs an AMF name, GUAMIs and PLMNs with slices");
    }
    json guamis = json::array();
    for (const auto& g : m.guamis) {
        guamis.push_back({{"gUAMI", guami(g)}});
    }
    json ies = json::array({ie(kAmfName, "reject", "AMFName", m.amf_name),
                            ie(kServedGuamiList, "reject", "ServedGUAMIList", guamis),
                            ie(kRelativeAmfCapacity, "ignore", "RelativeAMFCapacity", m.capacity),
                            ie(kPlmnSupportList, "reject", "PLMNSupportList", plmn_support(m.plmns))});
    return per(successful(kNgSetup, "reject", "NGSetupResponse", ies));
}

Result<Bytes> build(const NgSetupFailure& m) {
    json ies = json::array({ie(kCause, "ignore", "Cause", cause(m.cause))});
    if (m.time_to_wait) {
        ies.push_back(ie(kTimeToWait, "ignore", "TimeToWait", *m.time_to_wait));
    }
    return per(unsuccessful(kNgSetup, "reject", "NGSetupFailure", ies));
}

Result<Bytes> build(const NgReset& m) {
    if (!m.all && m.connections.empty()) {
        return bad("NGAP: a partial NG RESET lists its connections");
    }
    json reset = m.all ? json{{"nG-Interface", "reset-all"}} : json{{"partOfNG-Interface", connections(m.connections)}};
    json ies = json::array({ie(kCause, "ignore", "Cause", cause(m.cause)), ie(kResetType, "reject", "ResetType", reset)});
    return per(initiating(kNgReset, "reject", "NGReset", ies));
}

Result<Bytes> build(const NgResetAcknowledge& m) {
    json ies = json::array();
    if (!m.connections.empty()) {
        ies.push_back(ie(kUeAssociatedConnectionList, "ignore", "UE-associatedLogicalNG-connectionList",
                         connections(m.connections)));
    }
    return per(successful(kNgReset, "reject", "NGResetAcknowledge", ies));
}

Result<Bytes> build(const ErrorIndication& m) {
    json ies = json::array();
    if (m.ids.amf) {
        ies.push_back(ie(kAmfUeNgapId, "ignore", "AMF-UE-NGAP-ID", *m.ids.amf));
    }
    if (m.ids.ran) {
        ies.push_back(ie(kRanUeNgapId, "ignore", "RAN-UE-NGAP-ID", *m.ids.ran));
    }
    if (m.cause) {
        ies.push_back(ie(kCause, "ignore", "Cause", cause(*m.cause)));
    }
    return per(initiating(kErrorIndication, "ignore", "ErrorIndication", ies));
}

Result<Bytes> build(const AmfStatusIndication& m) {
    if (m.unavailable.empty()) {
        return bad("NGAP: AMF STATUS INDICATION lists GUAMIs");
    }
    json l = json::array();
    for (const auto& g : m.unavailable) {
        l.push_back({{"gUAMI", guami(g)}});
    }
    return per(initiating(kAmfStatusIndication, "ignore", "AMFStatusIndication",
                          json::array({ie(kUnavailableGuamiList, "reject", "UnavailableGUAMIList", l)})));
}

Result<Bytes> build(const AmfConfigurationUpdate& m) {
    json ies = json::array();
    if (m.amf_name) {
        ies.push_back(ie(kAmfName, "reject", "AMFName", *m.amf_name));
    }
    return per(initiating(kAmfConfigurationUpdate, "reject", "AMFConfigurationUpdate", ies));
}

Result<Bytes> build(const AmfConfigurationUpdateAcknowledge&) {
    return per(successful(kAmfConfigurationUpdate, "reject", "AMFConfigurationUpdateAcknowledge", json::array()));
}

Result<Bytes> build(const Paging& m) {
    if (m.tais.empty()) {
        return bad("NGAP: PAGING lists TAIs");
    }
    json l = json::array();
    for (const auto& t : m.tais) {
        l.push_back({{"tAI", tai(t)}});
    }
    json ies = json::array({ie(kUePagingIdentity, "ignore", "UEPagingIdentity", {{"fiveG-S-TMSI", s_tmsi(m.s_tmsi)}})});
    if (m.drx) {
        ies.push_back(ie(kPagingDrx, "ignore", "PagingDRX", *m.drx));
    }
    ies.push_back(ie(kTaiListForPaging, "ignore", "TAIListForPaging", l));
    return per(initiating(kPaging, "ignore", "Paging", ies));
}

Result<Bytes> build(const InitialUeMessage& m) {
    if (m.nas.empty()) {
        return bad("NGAP: INITIAL UE MESSAGE carries a NAS PDU");
    }
    json ies = json::array({ie(kRanUeNgapId, "reject", "RAN-UE-NGAP-ID", m.ran),
                            ie(kNasPdu, "reject", "NAS-PDU", hex(m.nas)),
                            ie(kUserLocationInformation, "reject", "UserLocationInformation", uli(m.cgi, m.tai)),
                            ie(kRrcEstablishmentCause, "ignore", "RRCEstablishmentCause", m.cause)});
    if (m.s_tmsi) {
        ies.push_back(ie(kFiveGSTmsi, "reject", "FiveG-S-TMSI", s_tmsi(*m.s_tmsi)));
    }
    if (m.context_requested) {
        ies.push_back(ie(kUeContextRequest, "ignore", "UEContextRequest", "requested"));
    }
    return per(initiating(kInitialUeMessage, "ignore", "InitialUEMessage", ies));
}

bool ids_ok(std::uint64_t amf) { return amf <= kMaxAmfUeId; }

Result<Bytes> build(const DownlinkNasTransport& m) {
    if (!ids_ok(m.amf) || m.nas.empty()) {
        return bad("NGAP: an AMF UE NGAP ID over 40 bits, or no NAS PDU");
    }
    json ies = ids(m.amf, m.ran);
    ies.push_back(ie(kNasPdu, "reject", "NAS-PDU", hex(m.nas)));
    return per(initiating(kDownlinkNasTransport, "ignore", "DownlinkNASTransport", ies));
}

Result<Bytes> build(const UplinkNasTransport& m) {
    if (!ids_ok(m.amf) || m.nas.empty()) {
        return bad("NGAP: an AMF UE NGAP ID over 40 bits, or no NAS PDU");
    }
    json ies = ids(m.amf, m.ran);
    ies.push_back(ie(kNasPdu, "reject", "NAS-PDU", hex(m.nas)));
    ies.push_back(ie(kUserLocationInformation, "ignore", "UserLocationInformation", uli(m.cgi, m.tai)));
    return per(initiating(kUplinkNasTransport, "ignore", "UplinkNASTransport", ies));
}

Result<Bytes> build(const NasNonDeliveryIndication& m) {
    json ies = ids(m.amf, m.ran);
    ies.push_back(ie(kNasPdu, "ignore", "NAS-PDU", hex(m.nas)));
    ies.push_back(ie(kCause, "ignore", "Cause", cause(m.cause)));
    return per(initiating(kNasNonDeliveryIndication, "ignore", "NASNonDeliveryIndication", ies));
}

// ---- PDU sessions (P1 N10) ------------------------------------------------------------------

bool psi_ok(std::uint8_t psi) { return psi >= 1 && psi <= 15; }

json gtp_tunnel(const GtpTunnel& t) {
    const std::uint64_t a = (std::uint64_t{t.addr[0]} << 24) | (std::uint64_t{t.addr[1]} << 16) |
                            (std::uint64_t{t.addr[2]} << 8) | t.addr[3];
    return {{"gTPTunnel", {{"transportLayerAddress", jer::var_bits(a, 32)}, {"gTP-TEID", octets(t.teid, 4)}}}};
}

GtpTunnel read_gtp_tunnel(const json& j) {
    const json& g = j.at("gTPTunnel");
    if (jer::bits_length(g.at("transportLayerAddress")) != 32) {
        throw jer::NotP1("an IPv6 or dual transport address");
    }
    const auto a = read_bits(g.at("transportLayerAddress"), 32);
    GtpTunnel t;
    t.addr = {static_cast<std::uint8_t>(a >> 24), static_cast<std::uint8_t>(a >> 16), static_cast<std::uint8_t>(a >> 8),
              static_cast<std::uint8_t>(a)};
    t.teid = static_cast<std::uint32_t>(read_number(g.at("gTP-TEID")));
    return t;
}

json qos_params(const QosFlowRequest& f) {
    json j = {{"qosCharacteristics", {{"nonDynamic5QI", {{"fiveQI", f.five_qi}}}}},
              {"allocationAndRetentionPriority",
               {{"priorityLevelARP", f.arp.priority},
                {"pre-emptionCapability", f.arp.may_preempt ? "may-trigger-pre-emption" : "shall-not-trigger-pre-emption"},
                {"pre-emptionVulnerability", f.arp.preemptable ? "pre-emptable" : "not-pre-emptable"}}}};
    if (const auto& g = f.gbr) {
        // P2 Q11 (TS 38.413 9.3.1.10), in ASN.1 order.
        json gbr = {{"maximumFlowBitRateDL", g->mfbr_dl},
                    {"maximumFlowBitRateUL", g->mfbr_ul},
                    {"guaranteedFlowBitRateDL", g->gfbr_dl},
                    {"guaranteedFlowBitRateUL", g->gfbr_ul}};
        if (g->notification_control) {
            gbr["notificationControl"] = "notification-requested";
        }
        j["gBR-QosInformation"] = gbr;
    }
    if (f.reflective) {
        j["reflectiveQosAttribute"] = "subject-to";
    }
    return j;
}

QosFlowRequest read_qos_flow(const json& j) {
    QosFlowRequest f;
    f.qfi = j.at("qosFlowIdentifier").get<std::uint8_t>();
    const json& p = j.at("qosFlowLevelQosParameters");
    const json& c = p.at("qosCharacteristics");
    if (!c.contains("nonDynamic5QI")) {
        throw jer::NotP1("a dynamic 5QI");
    }
    if (p.contains("gBR-QosInformation")) {
        const json& g = p.at("gBR-QosInformation");   // P2 Q11
        f.gbr = Gbr{g.at("maximumFlowBitRateDL").get<std::uint64_t>(), g.at("maximumFlowBitRateUL").get<std::uint64_t>(),
                    g.at("guaranteedFlowBitRateDL").get<std::uint64_t>(), g.at("guaranteedFlowBitRateUL").get<std::uint64_t>(),
                    g.contains("notificationControl")};
    }
    f.reflective = p.contains("reflectiveQosAttribute");
    f.five_qi = c.at("nonDynamic5QI").at("fiveQI").get<std::uint16_t>();
    const json& arp = p.at("allocationAndRetentionPriority");
    f.arp.priority = arp.at("priorityLevelARP").get<std::uint8_t>();
    f.arp.may_preempt = arp.at("pre-emptionCapability").get<std::string>() == "may-trigger-pre-emption";
    f.arp.preemptable = arp.at("pre-emptionVulnerability").get<std::string>() == "pre-emptable";
    return f;
}

bool flows_ok(const std::vector<QosFlowRequest>& l) {
    return std::all_of(l.begin(), l.end(), [](const QosFlowRequest& f) {
        // A GBR flow's guaranteed rate is at most its maximum (TS 23.501 5.7.2.5).
        const bool gbr_ok = !f.gbr || (f.gbr->gfbr_dl <= f.gbr->mfbr_dl && f.gbr->gfbr_ul <= f.gbr->mfbr_ul);
        return f.qfi <= 63 && f.five_qi <= 255 && f.arp.priority >= 1 && f.arp.priority <= 15 && gbr_ok;
    });
}

json ambr(const Ambr& a, const char* dl, const char* ul) { return {{dl, a.dl}, {ul, a.ul}}; }
Ambr read_ambr(const json& j, const char* dl, const char* ul) { return {j.at(dl).get<std::uint64_t>(), j.at(ul).get<std::uint64_t>()}; }

template <class T>
Result<Bytes> per_of(const asn_TYPE_descriptor_t& td, const json& j) {
    return jer::encode(td, j, asn1::Rules::aper);
}

Result<json> jer_of(const asn_TYPE_descriptor_t& td, ByteView in) { return jer::decode(td, in, asn1::Rules::aper); }

Result<Bytes> encode_transfer(const SetupRequestTransfer& t) {
    if (t.flows.empty() || !flows_ok(t.flows)) {
        return bad("NGAP: a session needs QoS flows with QFI 0..63 and ARP priority 1..15");
    }
    json ies = json::array();
    if (t.session_ambr) {
        ies.push_back(ie(kSessionAmbr, "reject", "PDUSessionAggregateMaximumBitRate",
                         ambr(*t.session_ambr, "pDUSessionAggregateMaximumBitRateDL", "pDUSessionAggregateMaximumBitRateUL")));
    }
    ies.push_back(ie(kUlNguUpTnlInformation, "reject", "UPTransportLayerInformation", gtp_tunnel(t.ul)));
    ies.push_back(ie(kPduSessionType, "reject", "PDUSessionType", t.type));
    if (t.security) {
        json s = {{"integrityProtectionIndication", t.security->integrity},
                  {"confidentialityProtectionIndication", t.security->confidentiality}};
        if (t.security->integrity != "not-needed") {
            s["maximumIntegrityProtectedDataRate-UL"] = t.security->max_rate_ul.value_or("maximum-UE-rate");
        }
        if (t.security->max_rate_dl) {
            s["iE-Extensions"] = json::array({{{"id", kMaxIntegrityRateDl}, {"criticality", "ignore"},
                                               {"extensionValue", {{"MaximumIntegrityProtectedDataRate", *t.security->max_rate_dl}}}}});
        }
        ies.push_back(ie(kSecurityIndication, "reject", "SecurityIndication", s));
    }
    json flows = json::array();
    for (const auto& f : t.flows) {
        flows.push_back({{"qosFlowIdentifier", f.qfi}, {"qosFlowLevelQosParameters", qos_params(f)}});
    }
    ies.push_back(ie(kQosFlowSetupRequestList, "reject", "QosFlowSetupRequestList", flows));
    return per_of<SetupRequestTransfer>(asn_DEF_NGAP_PDUSessionResourceSetupRequestTransfer, {{"protocolIEs", ies}});
}

json flows_with_cause(const std::vector<QosFlowCause>& l) {
    json flows = json::array();
    for (const auto& f : l) {
        flows.push_back({{"qosFlowIdentifier", f.qfi}, {"cause", cause(f.cause)}});
    }
    return flows;
}
std::vector<QosFlowCause> read_flows_with_cause(const json& l) {
    std::vector<QosFlowCause> out;
    for (const auto& f : l) {
        out.push_back(QosFlowCause{f.at("qosFlowIdentifier").get<std::uint8_t>(), read_cause(f.at("cause"))});
    }
    return out;
}
bool qfis_ok(const std::vector<QosFlowCause>& l) {
    return std::all_of(l.begin(), l.end(), [](const QosFlowCause& f) { return f.qfi <= 63; });
}

Result<Bytes> encode_transfer(const SetupResponseTransfer& t) {
    if (t.qfis.empty()) {
        return bad("NGAP: a set-up session names its QoS flows");
    }
    json flows = json::array();
    for (std::uint8_t q : t.qfis) {
        flows.push_back({{"qosFlowIdentifier", q}});
    }
    json j = {{"dLQosFlowPerTNLInformation", {{"uPTransportLayerInformation", gtp_tunnel(t.dl)}, {"associatedQosFlowList", flows}}}};
    if (t.security) {
        j["securityResult"] = {{"integrityProtectionResult", t.security->integrity ? "performed" : "not-performed"},
                               {"confidentialityProtectionResult", t.security->confidentiality ? "performed" : "not-performed"}};
    }
    if (!t.failed.empty()) {
        j["qosFlowFailedToSetupList"] = flows_with_cause(t.failed);   // P2 Q11
    }
    return per_of<SetupResponseTransfer>(asn_DEF_NGAP_PDUSessionResourceSetupResponseTransfer, j);
}

Result<Bytes> encode_transfer(const ModifyRequestTransfer& t) {
    if (!flows_ok(t.add_or_modify)) {
        return bad("NGAP: QoS flows with QFI 0..63 and ARP priority 1..15");
    }
    json ies = json::array();
    if (t.session_ambr) {
        ies.push_back(ie(kSessionAmbr, "reject", "PDUSessionAggregateMaximumBitRate",
                         ambr(*t.session_ambr, "pDUSessionAggregateMaximumBitRateDL", "pDUSessionAggregateMaximumBitRateUL")));
    }
    if (!t.add_or_modify.empty()) {
        json flows = json::array();
        for (const auto& f : t.add_or_modify) {
            flows.push_back({{"qosFlowIdentifier", f.qfi}, {"qosFlowLevelQosParameters", qos_params(f)}});
        }
        ies.push_back(ie(kQosFlowAddOrModifyRequestList, "reject", "QosFlowAddOrModifyRequestList", flows));
    }
    if (!t.release.empty()) {
        json flows = json::array();
        for (std::uint8_t q : t.release) {
            flows.push_back({{"qosFlowIdentifier", q}, {"cause", cause(Cause{"nas", "normal-release"})}});
        }
        ies.push_back(ie(kQosFlowToReleaseList, "reject", "QosFlowListWithCause", flows));
    }
    return per_of<ModifyRequestTransfer>(asn_DEF_NGAP_PDUSessionResourceModifyRequestTransfer, {{"protocolIEs", ies}});
}

Result<Bytes> encode_transfer(const ModifyResponseTransfer& t) {
    if (!qfis_ok(t.failed)) {
        return bad("NGAP: a QFI is 0..63");
    }
    json j = json::object();
    if (!t.added_or_modified.empty()) {
        json flows = json::array();
        for (std::uint8_t q : t.added_or_modified) {
            flows.push_back({{"qosFlowIdentifier", q}});
        }
        j["qosFlowAddOrModifyResponseList"] = flows;
    }
    if (!t.failed.empty()) {
        j["qosFlowFailedToAddOrModifyList"] = flows_with_cause(t.failed);
    }
    return per_of<ModifyResponseTransfer>(asn_DEF_NGAP_PDUSessionResourceModifyResponseTransfer, j);
}

Result<Bytes> encode_transfer(const NotifyTransfer& t) {
    if (!qfis_ok(t.released) ||
        !std::all_of(t.notify.begin(), t.notify.end(), [](const NotifyTransfer::Notify& n) { return n.qfi <= 63; })) {
        return bad("NGAP: a QFI is 0..63");
    }
    if (t.notify.empty() && t.released.empty()) {
        return bad("NGAP: a PDU session resource notify names a QoS flow");
    }
    json j = json::object();
    if (!t.notify.empty()) {
        json l = json::array();
        for (const auto& n : t.notify) {
            l.push_back({{"qosFlowIdentifier", n.qfi}, {"notificationCause", n.fulfilled ? "fulfilled" : "not-fulfilled"}});
        }
        j["qosFlowNotifyList"] = l;
    }
    if (!t.released.empty()) {
        j["qosFlowReleasedList"] = flows_with_cause(t.released);
    }
    return per_of<NotifyTransfer>(asn_DEF_NGAP_PDUSessionResourceNotifyTransfer, j);
}

Result<Bytes> cause_transfer(const asn_TYPE_descriptor_t& td, const Cause& c) { return jer::encode(td, json{{"cause", cause(c)}}, asn1::Rules::aper); }

/// The IEs of a transfer's protocolIEs, by id.
std::map<int, json> transfer_ies(const json& j) {
    std::map<int, json> out;
    for (const auto& e : j.at("protocolIEs")) {
        auto [type, value] = arm(e.at("value"));
        (void)type;
        out.emplace(e.at("id").get<int>(), *value);
    }
    return out;
}

Result<SetupRequestTransfer> decode_setup_request_transfer(ByteView in) {
    auto j = jer_of(asn_DEF_NGAP_PDUSessionResourceSetupRequestTransfer, in);
    if (!j) {
        return j.error();
    }
    return guarded([&]() -> Result<SetupRequestTransfer> {
        auto ies = transfer_ies(*j);
        SetupRequestTransfer t;
        if (auto it = ies.find(kSessionAmbr); it != ies.end()) {
            t.session_ambr = read_ambr(it->second, "pDUSessionAggregateMaximumBitRateDL", "pDUSessionAggregateMaximumBitRateUL");
        }
        t.ul = read_gtp_tunnel(ies.at(kUlNguUpTnlInformation));
        t.type = ies.at(kPduSessionType).get<std::string>();
        if (auto it = ies.find(kSecurityIndication); it != ies.end()) {
            const json& s = it->second;
            SecurityIndication si;
            si.integrity = s.at("integrityProtectionIndication").get<std::string>();
            si.confidentiality = s.at("confidentialityProtectionIndication").get<std::string>();
            if (s.contains("maximumIntegrityProtectedDataRate-UL")) {
                si.max_rate_ul = s.at("maximumIntegrityProtectedDataRate-UL").get<std::string>();
            }
            if (s.contains("iE-Extensions")) {
                for (const auto& e : s.at("iE-Extensions")) {
                    if (e.at("id").get<int>() == kMaxIntegrityRateDl) {
                        si.max_rate_dl = e.at("extensionValue").at("MaximumIntegrityProtectedDataRate").get<std::string>();
                    }
                }
            }
            t.security = si;
        }
        for (const auto& f : ies.at(kQosFlowSetupRequestList)) {
            t.flows.push_back(read_qos_flow(f));
        }
        return t;
    });
}

Result<SetupResponseTransfer> decode_setup_response_transfer(ByteView in) {
    auto j = jer_of(asn_DEF_NGAP_PDUSessionResourceSetupResponseTransfer, in);
    if (!j) {
        return j.error();
    }
    return guarded([&]() -> Result<SetupResponseTransfer> {
        SetupResponseTransfer t;
        const json& d = j->at("dLQosFlowPerTNLInformation");
        t.dl = read_gtp_tunnel(d.at("uPTransportLayerInformation"));
        for (const auto& f : d.at("associatedQosFlowList")) {
            t.qfis.push_back(f.at("qosFlowIdentifier").get<std::uint8_t>());
        }
        if (j->contains("securityResult")) {
            const json& s = j->at("securityResult");
            t.security = SecurityResult{s.at("integrityProtectionResult").get<std::string>() == "performed",
                                        s.at("confidentialityProtectionResult").get<std::string>() == "performed"};
        }
        if (j->contains("qosFlowFailedToSetupList")) {
            t.failed = read_flows_with_cause(j->at("qosFlowFailedToSetupList"));
        }
        return t;
    });
}

Result<ModifyRequestTransfer> decode_modify_request_transfer(ByteView in) {
    auto j = jer_of(asn_DEF_NGAP_PDUSessionResourceModifyRequestTransfer, in);
    if (!j) {
        return j.error();
    }
    return guarded([&]() -> Result<ModifyRequestTransfer> {
        auto ies = transfer_ies(*j);
        ModifyRequestTransfer t;
        if (auto it = ies.find(kSessionAmbr); it != ies.end()) {
            t.session_ambr = read_ambr(it->second, "pDUSessionAggregateMaximumBitRateDL", "pDUSessionAggregateMaximumBitRateUL");
        }
        if (auto it = ies.find(kQosFlowAddOrModifyRequestList); it != ies.end()) {
            for (const auto& f : it->second) {
                t.add_or_modify.push_back(read_qos_flow(f));
            }
        }
        if (auto it = ies.find(kQosFlowToReleaseList); it != ies.end()) {
            for (const auto& f : it->second) {
                t.release.push_back(f.at("qosFlowIdentifier").get<std::uint8_t>());
            }
        }
        return t;
    });
}

Result<ModifyResponseTransfer> decode_modify_response_transfer(ByteView in) {
    auto j = jer_of(asn_DEF_NGAP_PDUSessionResourceModifyResponseTransfer, in);
    if (!j) {
        return j.error();
    }
    return guarded([&]() -> Result<ModifyResponseTransfer> {
        ModifyResponseTransfer t;
        if (j->contains("qosFlowAddOrModifyResponseList")) {
            for (const auto& f : j->at("qosFlowAddOrModifyResponseList")) {
                t.added_or_modified.push_back(f.at("qosFlowIdentifier").get<std::uint8_t>());
            }
        }
        if (j->contains("qosFlowFailedToAddOrModifyList")) {
            t.failed = read_flows_with_cause(j->at("qosFlowFailedToAddOrModifyList"));
        }
        return t;
    });
}

Result<NotifyTransfer> decode_notify_transfer(ByteView in) {
    auto j = jer_of(asn_DEF_NGAP_PDUSessionResourceNotifyTransfer, in);
    if (!j) {
        return j.error();
    }
    return guarded([&]() -> Result<NotifyTransfer> {
        NotifyTransfer t;
        if (j->contains("qosFlowNotifyList")) {
            for (const auto& n : j->at("qosFlowNotifyList")) {
                t.notify.push_back({n.at("qosFlowIdentifier").get<std::uint8_t>(),
                                    n.at("notificationCause").get<std::string>() == "fulfilled"});
            }
        }
        if (j->contains("qosFlowReleasedList")) {
            t.released = read_flows_with_cause(j->at("qosFlowReleasedList"));
        }
        return t;
    });
}

Result<Cause> decode_cause_transfer(const asn_TYPE_descriptor_t& td, ByteView in) {
    auto j = jer_of(td, in);
    if (!j) {
        return j.error();
    }
    return guarded([&]() -> Result<Cause> { return read_cause(j->at("cause")); });
}

/// The setup items of a request (SUReq or CxtReq: their NAS field's name differs).
Result<json> setup_items(const std::vector<SessionSetupItem>& l, const char* nas_field) {
    json items = json::array();
    for (const auto& s : l) {
        if (!psi_ok(s.psi)) {
            return bad("NGAP: a PDU session ID is 1..15");
        }
        auto t = encode_transfer(s.transfer);
        if (!t) {
            return t.error();
        }
        json item = {{"pDUSessionID", s.psi}};
        if (s.nas) {
            item[nas_field] = hex(*s.nas);
        }
        item["s-NSSAI"] = snssai(s.snssai);
        item["pDUSessionResourceSetupRequestTransfer"] = hex(*t);
        items.push_back(item);
    }
    return items;
}

Result<json> setup_ok_items(const std::vector<SessionSetupOk>& l) {
    json items = json::array();
    for (const auto& s : l) {
        auto t = encode_transfer(s.transfer);
        if (!t || !psi_ok(s.psi)) {
            return t ? Result<json>(bad("NGAP: a PDU session ID is 1..15")) : Result<json>(t.error());
        }
        items.push_back({{"pDUSessionID", s.psi}, {"pDUSessionResourceSetupResponseTransfer", hex(*t)}});
    }
    return items;
}

Result<json> cause_items(const std::vector<SessionCause>& l, const asn_TYPE_descriptor_t& td, const char* field) {
    json items = json::array();
    for (const auto& s : l) {
        auto t = cause_transfer(td, s.cause);
        if (!t || !psi_ok(s.psi)) {
            return t ? Result<json>(bad("NGAP: a PDU session ID is 1..15")) : Result<json>(t.error());
        }
        items.push_back({{"pDUSessionID", s.psi}, {field, hex(*t)}});
    }
    return items;
}

Result<std::vector<SessionSetupItem>> read_setup_items(const json& l, const char* nas_field) {
    std::vector<SessionSetupItem> out;
    for (const auto& i : l) {
        SessionSetupItem s;
        s.psi = i.at("pDUSessionID").get<std::uint8_t>();
        if (i.contains(nas_field)) {
            s.nas = read_octets(i.at(nas_field));
        }
        s.snssai = read_snssai(i.at("s-NSSAI"));
        auto t = decode_setup_request_transfer(read_octets(i.at("pDUSessionResourceSetupRequestTransfer")));
        if (!t) {
            return t.error();
        }
        s.transfer = std::move(*t);
        out.push_back(std::move(s));
    }
    return out;
}

Result<std::vector<SessionSetupOk>> read_setup_ok_items(const json& l) {
    std::vector<SessionSetupOk> out;
    for (const auto& i : l) {
        auto t = decode_setup_response_transfer(read_octets(i.at("pDUSessionResourceSetupResponseTransfer")));
        if (!t) {
            return t.error();
        }
        out.push_back({i.at("pDUSessionID").get<std::uint8_t>(), std::move(*t)});
    }
    return out;
}

Result<std::vector<SessionCause>> read_cause_items(const json& l, const asn_TYPE_descriptor_t& td, const char* field) {
    std::vector<SessionCause> out;
    for (const auto& i : l) {
        auto c = decode_cause_transfer(td, read_octets(i.at(field)));
        if (!c) {
            return c.error();
        }
        out.push_back({i.at("pDUSessionID").get<std::uint8_t>(), std::move(*c)});
    }
    return out;
}

json ue_ambr(const Ambr& a) { return ambr(a, "uEAggregateMaximumBitRateDL", "uEAggregateMaximumBitRateUL"); }

Result<Bytes> build(const PduSessionResourceSetupRequest& m) {
    if (!ids_ok(m.amf) || m.sessions.empty() || m.sessions.size() > 256) {
        return bad("NGAP: PDU SESSION RESOURCE SETUP REQUEST needs 1..256 sessions");
    }
    auto items = setup_items(m.sessions, "pDUSessionNAS-PDU");
    if (!items) {
        return items.error();
    }
    json ies = ids(m.amf, m.ran);
    if (m.nas) {
        ies.push_back(ie(kNasPdu, "reject", "NAS-PDU", hex(*m.nas)));
    }
    ies.push_back(ie(kSetupListSuReq, "reject", "PDUSessionResourceSetupListSUReq", *items));
    if (m.ue_ambr) {
        ies.push_back(ie(kUeAmbr, "ignore", "UEAggregateMaximumBitRate", ue_ambr(*m.ue_ambr)));
    }
    return per(initiating(kPduSessionResourceSetup, "reject", "PDUSessionResourceSetupRequest", ies));
}

Result<Bytes> build(const PduSessionResourceSetupResponse& m) {
    json ies = ids(m.amf, m.ran, "ignore");
    if (!m.sessions.empty()) {
        auto items = setup_ok_items(m.sessions);
        if (!items) {
            return items.error();
        }
        ies.push_back(ie(kSetupListSuRes, "ignore", "PDUSessionResourceSetupListSURes", *items));
    }
    if (!m.failed.empty()) {
        auto items = cause_items(m.failed, asn_DEF_NGAP_PDUSessionResourceSetupUnsuccessfulTransfer,
                                 "pDUSessionResourceSetupUnsuccessfulTransfer");
        if (!items) {
            return items.error();
        }
        ies.push_back(ie(kFailedToSetupListSuRes, "ignore", "PDUSessionResourceFailedToSetupListSURes", *items));
    }
    return per(successful(kPduSessionResourceSetup, "reject", "PDUSessionResourceSetupResponse", ies));
}

Result<Bytes> build(const PduSessionResourceReleaseCommand& m) {
    if (!ids_ok(m.amf) || m.sessions.empty()) {
        return bad("NGAP: PDU SESSION RESOURCE RELEASE COMMAND needs sessions");
    }
    auto items = cause_items(m.sessions, asn_DEF_NGAP_PDUSessionResourceReleaseCommandTransfer,
                             "pDUSessionResourceReleaseCommandTransfer");
    if (!items) {
        return items.error();
    }
    json ies = ids(m.amf, m.ran);
    if (m.nas) {
        ies.push_back(ie(kNasPdu, "ignore", "NAS-PDU", hex(*m.nas)));
    }
    ies.push_back(ie(kToReleaseListRelCmd, "reject", "PDUSessionResourceToReleaseListRelCmd", *items));
    return per(initiating(kPduSessionResourceRelease, "reject", "PDUSessionResourceReleaseCommand", ies));
}

Result<Bytes> build(const PduSessionResourceReleaseResponse& m) {
    if (m.released.empty()) {
        return bad("NGAP: PDU SESSION RESOURCE RELEASE RESPONSE lists the released sessions");
    }
    auto empty = jer::encode(asn_DEF_NGAP_PDUSessionResourceReleaseResponseTransfer, json::object(), asn1::Rules::aper);
    if (!empty) {
        return empty.error();
    }
    json items = json::array();
    for (std::uint8_t psi : m.released) {
        if (!psi_ok(psi)) {
            return bad("NGAP: a PDU session ID is 1..15");
        }
        items.push_back({{"pDUSessionID", psi}, {"pDUSessionResourceReleaseResponseTransfer", hex(*empty)}});
    }
    json ies = ids(m.amf, m.ran, "ignore");
    ies.push_back(ie(kReleasedListRelRes, "ignore", "PDUSessionResourceReleasedListRelRes", items));
    return per(successful(kPduSessionResourceRelease, "reject", "PDUSessionResourceReleaseResponse", ies));
}

Result<Bytes> build(const PduSessionResourceModifyRequest& m) {
    if (!ids_ok(m.amf) || m.sessions.empty()) {
        return bad("NGAP: PDU SESSION RESOURCE MODIFY REQUEST needs sessions");
    }
    json items = json::array();
    for (const auto& s : m.sessions) {
        auto t = encode_transfer(s.transfer);
        if (!t || !psi_ok(s.psi)) {
            return t ? Result<Bytes>(bad("NGAP: a PDU session ID is 1..15")) : Result<Bytes>(t.error());
        }
        json item = {{"pDUSessionID", s.psi}};
        if (s.nas) {
            item["nAS-PDU"] = hex(*s.nas);
        }
        item["pDUSessionResourceModifyRequestTransfer"] = hex(*t);
        items.push_back(item);
    }
    json ies = ids(m.amf, m.ran);
    ies.push_back(ie(kModifyListModReq, "reject", "PDUSessionResourceModifyListModReq", items));
    return per(initiating(kPduSessionResourceModify, "reject", "PDUSessionResourceModifyRequest", ies));
}

Result<Bytes> build(const PduSessionResourceModifyResponse& m) {
    json ies = ids(m.amf, m.ran, "ignore");
    if (!m.sessions.empty()) {
        json items = json::array();
        for (const auto& s : m.sessions) {
            auto t = encode_transfer(s.transfer);
            if (!t || !psi_ok(s.psi)) {
                return t ? Result<Bytes>(bad("NGAP: a PDU session ID is 1..15")) : Result<Bytes>(t.error());
            }
            items.push_back({{"pDUSessionID", s.psi}, {"pDUSessionResourceModifyResponseTransfer", hex(*t)}});
        }
        ies.push_back(ie(kModifyListModRes, "ignore", "PDUSessionResourceModifyListModRes", items));
    }
    if (!m.failed.empty()) {
        auto items = cause_items(m.failed, asn_DEF_NGAP_PDUSessionResourceModifyUnsuccessfulTransfer,
                                 "pDUSessionResourceModifyUnsuccessfulTransfer");
        if (!items) {
            return items.error();
        }
        ies.push_back(ie(kFailedToModifyListModRes, "ignore", "PDUSessionResourceFailedToModifyListModRes", *items));
    }
    return per(successful(kPduSessionResourceModify, "reject", "PDUSessionResourceModifyResponse", ies));
}

Result<Bytes> build(const PduSessionResourceNotify& m) {
    if (m.sessions.empty() && m.released.empty()) {
        return bad("NGAP: PDU SESSION RESOURCE NOTIFY names a session");
    }
    json ies = ids(m.amf, m.ran);
    if (!m.sessions.empty()) {
        json items = json::array();
        for (const auto& s : m.sessions) {
            auto t = encode_transfer(s.transfer);
            if (!t || !psi_ok(s.psi)) {
                return t ? Result<Bytes>(bad("NGAP: a PDU session ID is 1..15")) : Result<Bytes>(t.error());
            }
            items.push_back({{"pDUSessionID", s.psi}, {"pDUSessionResourceNotifyTransfer", hex(*t)}});
        }
        ies.push_back(ie(kNotifyList, "reject", "PDUSessionResourceNotifyList", items));
    }
    if (!m.released.empty()) {
        auto items = cause_items(m.released, asn_DEF_NGAP_PDUSessionResourceNotifyReleasedTransfer,
                                 "pDUSessionResourceNotifyReleasedTransfer");
        if (!items) {
            return items.error();
        }
        ies.push_back(ie(kReleasedListNot, "ignore", "PDUSessionResourceReleasedListNot", *items));
    }
    return per(initiating(kPduSessionResourceNotify, "ignore", "PDUSessionResourceNotify", ies));
}

json sec_caps(const InitialContextSetupRequest& m) {
    return {{"nRencryptionAlgorithms", jer::var_bits(m.nr_enc, 16)},
            {"nRintegrityProtectionAlgorithms", jer::var_bits(m.nr_int, 16)},
            {"eUTRAencryptionAlgorithms", jer::var_bits(m.eutra_enc, 16)},
            {"eUTRAintegrityProtectionAlgorithms", jer::var_bits(m.eutra_int, 16)}};
}

Result<Bytes> build(const InitialContextSetupRequest& m) {
    if (!ids_ok(m.amf) || m.security_key.size() != 32 || m.allowed_nssai.empty()) {
        return bad("NGAP: INITIAL CONTEXT SETUP REQUEST needs a 256-bit key and an allowed NSSAI");
    }
    if (!m.sessions.empty() && !m.ue_ambr) {
        return bad("NGAP: an INITIAL CONTEXT SETUP REQUEST with sessions carries the UE-AMBR (9.2.2.1)");
    }
    json ies = ids(m.amf, m.ran);
    if (m.ue_ambr) {
        ies.push_back(ie(kUeAmbr, "reject", "UEAggregateMaximumBitRate", ue_ambr(*m.ue_ambr)));
    }
    ies.push_back(ie(kGuami, "reject", "GUAMI", guami(m.guami)));
    if (!m.sessions.empty()) {
        auto items = setup_items(m.sessions, "nAS-PDU");
        if (!items) {
            return items.error();
        }
        ies.push_back(ie(kSetupListCxtReq, "reject", "PDUSessionResourceSetupListCxtReq", *items));
    }
    ies.push_back(ie(kAllowedNssai, "reject", "AllowedNSSAI", slice_list(m.allowed_nssai)));
    ies.push_back(ie(kUeSecurityCapabilities, "reject", "UESecurityCapabilities", sec_caps(m)));
    ies.push_back(ie(kSecurityKey, "reject", "SecurityKey", hex(m.security_key)));
    if (m.ue_radio_capability) {
        ies.push_back(ie(kUeRadioCapability, "ignore", "UERadioCapability", hex(*m.ue_radio_capability)));
    }
    if (m.masked_imeisv) {
        ies.push_back(ie(kMaskedImeisv, "ignore", "MaskedIMEISV", bits(*m.masked_imeisv, 64)));
    }
    if (m.nas) {
        ies.push_back(ie(kNasPdu, "ignore", "NAS-PDU", hex(*m.nas)));
    }
    return per(initiating(kInitialContextSetup, "reject", "InitialContextSetupRequest", ies));
}

Result<Bytes> build(const InitialContextSetupResponse& m) {
    json ies = ids(m.amf, m.ran, "ignore");
    if (!m.sessions.empty()) {
        auto items = setup_ok_items(m.sessions);
        if (!items) {
            return items.error();
        }
        ies.push_back(ie(kSetupListCxtRes, "ignore", "PDUSessionResourceSetupListCxtRes", *items));
    }
    if (!m.failed.empty()) {
        auto items = cause_items(m.failed, asn_DEF_NGAP_PDUSessionResourceSetupUnsuccessfulTransfer,
                                 "pDUSessionResourceSetupUnsuccessfulTransfer");
        if (!items) {
            return items.error();
        }
        ies.push_back(ie(kFailedToSetupListCxtRes, "ignore", "PDUSessionResourceFailedToSetupListCxtRes", *items));
    }
    return per(successful(kInitialContextSetup, "reject", "InitialContextSetupResponse", ies));
}

Result<Bytes> build(const InitialContextSetupFailure& m) {
    json ies = ids(m.amf, m.ran, "ignore");
    ies.push_back(ie(kCause, "ignore", "Cause", cause(m.cause)));
    return per(unsuccessful(kInitialContextSetup, "reject", "InitialContextSetupFailure", ies));
}

Result<Bytes> build(const UeContextReleaseRequest& m) {
    json ies = ids(m.amf, m.ran);
    ies.push_back(ie(kCause, "ignore", "Cause", cause(m.cause)));
    return per(initiating(kUeContextReleaseRequest, "ignore", "UEContextReleaseRequest", ies));
}

Result<Bytes> build(const UeContextReleaseCommand& m) {
    json ue_ids = m.ran ? json{{"uE-NGAP-ID-pair", {{"aMF-UE-NGAP-ID", m.amf}, {"rAN-UE-NGAP-ID", *m.ran}}}}
                        : json{{"aMF-UE-NGAP-ID", m.amf}};
    json ies = json::array({ie(kUeNgapIds, "reject", "UE-NGAP-IDs", ue_ids), ie(kCause, "ignore", "Cause", cause(m.cause))});
    return per(initiating(kUeContextRelease, "reject", "UEContextReleaseCommand", ies));
}

Result<Bytes> build(const UeContextReleaseComplete& m) {
    return per(successful(kUeContextRelease, "reject", "UEContextReleaseComplete", ids(m.amf, m.ran, "ignore")));
}

Result<Bytes> build(const UeContextModificationRequest& m) {
    json ies = ids(m.amf, m.ran);
    if (m.security_key) {
        if (m.security_key->size() != 32) {
            return bad("NGAP: a Security Key is 256 bits");
        }
        ies.push_back(ie(kSecurityKey, "reject", "SecurityKey", hex(*m.security_key)));
    }
    return per(initiating(kUeContextModification, "reject", "UEContextModificationRequest", ies));
}

Result<Bytes> build(const UeContextModificationResponse& m) {
    return per(successful(kUeContextModification, "reject", "UEContextModificationResponse", ids(m.amf, m.ran, "ignore")));
}

Result<Bytes> build(const UeRadioCapabilityInfoIndication& m) {
    if (m.capability.empty()) {
        return bad("NGAP: no UE radio capability");
    }
    json ies = ids(m.amf, m.ran);
    ies.push_back(ie(kUeRadioCapability, "ignore", "UERadioCapability", hex(m.capability)));
    return per(initiating(kUeRadioCapabilityInfoIndication, "ignore", "UERadioCapabilityInfoIndication", ies));
}

// ---- readers -----------------------------------------------------------------------------

/// The IEs of a message by id: the value inside its open type.
using Ies = std::map<int, const json*>;

const json& need(const Ies& ies, int id) {
    auto it = ies.find(id);
    if (it == ies.end()) {
        throw std::out_of_range("a mandatory IE is missing");
    }
    return *it->second;
}

const json* maybe(const Ies& ies, int id) {
    auto it = ies.find(id);
    return it == ies.end() ? nullptr : it->second;
}

std::uint64_t amf_id(const Ies& ies) { return need(ies, kAmfUeNgapId).get<std::uint64_t>(); }
std::uint32_t ran_id(const Ies& ies) { return need(ies, kRanUeNgapId).get<std::uint32_t>(); }

/// NR location; another access's (N3IWF, E-UTRA …) leaves the cell and TAI unset.
void read_uli(const json& j, NrCgi& cgi, Tai& t) {
    if (!j.contains("userLocationInformationNR")) {
        return;
    }
    const json& nr = j.at("userLocationInformationNR");
    cgi = read_nr_cgi(nr.at("nR-CGI"));
    t = read_tai(nr.at("tAI"));
}

std::vector<PlmnSlices> read_plmn_support(const json& j) {
    std::vector<PlmnSlices> out;
    for (const auto& p : j) {
        out.push_back({read_plmn(p.at("pLMNIdentity")), read_slice_list(p.at("sliceSupportList"))});
    }
    return out;
}

Result<Pdu> read(Header::Kind kind, int code, const Ies& ies) {
    using K = Header::Kind;
    switch (code) {
    case kNgSetup:
        if (kind == K::initiating) {
            NgSetupRequest m;
            if (!need(ies, kGlobalRanNodeId).contains("globalGNB-ID")) {
                return Error{Errc::unsupported, kNgSetup, "NGAP: an NG SETUP REQUEST from a RAN node other than a gNB"};
            }
            const json& g = need(ies, kGlobalRanNodeId).at("globalGNB-ID");
            m.plmn = read_plmn(g.at("pLMNIdentity"));
            const json& id = g.at("gNB-ID").at("gNB-ID");
            m.gnb_id_bits = static_cast<std::uint8_t>(jer::bits_length(id));
            m.gnb_id = static_cast<std::uint32_t>(read_bits(id));
            if (const json* n = maybe(ies, kRanNodeName)) {
                m.name = n->get<std::string>();
            }
            for (const auto& t : need(ies, kSupportedTaList)) {
                NgSetupRequest::Ta ta;
                ta.tac = static_cast<std::uint32_t>(read_number(t.at("tAC")));
                for (const auto& p : t.at("broadcastPLMNList")) {
                    ta.plmns.push_back({read_plmn(p.at("pLMNIdentity")), read_slice_list(p.at("tAISliceSupportList"))});
                }
                m.tas.push_back(std::move(ta));
            }
            m.paging_drx = need(ies, kDefaultPagingDrx).get<std::string>();
            return Pdu{m};
        }
        if (kind == K::successful) {
            NgSetupResponse m;
            m.amf_name = need(ies, kAmfName).get<std::string>();
            for (const auto& g : need(ies, kServedGuamiList)) {
                m.guamis.push_back(read_guami(g.at("gUAMI")));
            }
            m.capacity = need(ies, kRelativeAmfCapacity).get<std::uint8_t>();
            m.plmns = read_plmn_support(need(ies, kPlmnSupportList));
            return Pdu{m};
        }
        {
            NgSetupFailure m;
            m.cause = read_cause(need(ies, kCause));
            if (const json* t = maybe(ies, kTimeToWait)) {
                m.time_to_wait = t->get<std::string>();
            }
            return Pdu{m};
        }
    case kNgReset:
        if (kind == K::initiating) {
            NgReset m;
            m.cause = read_cause(need(ies, kCause));
            auto [k, v] = arm(need(ies, kResetType));
            m.all = k == "nG-Interface";
            if (!m.all) {
                m.connections = read_connections(*v);
            }
            return Pdu{m};
        } else {
            NgResetAcknowledge m;
            if (const json* l = maybe(ies, kUeAssociatedConnectionList)) {
                m.connections = read_connections(*l);
            }
            return Pdu{m};
        }
    case kErrorIndication: {
        ErrorIndication m;
        if (const json* a = maybe(ies, kAmfUeNgapId)) {
            m.ids.amf = a->get<std::uint64_t>();
        }
        if (const json* r = maybe(ies, kRanUeNgapId)) {
            m.ids.ran = r->get<std::uint32_t>();
        }
        if (const json* c = maybe(ies, kCause)) {
            m.cause = read_cause(*c);
        }
        return Pdu{m};
    }
    case kAmfStatusIndication: {
        AmfStatusIndication m;
        for (const auto& g : need(ies, kUnavailableGuamiList)) {
            m.unavailable.push_back(read_guami(g.at("gUAMI")));
        }
        return Pdu{m};
    }
    case kAmfConfigurationUpdate:
        if (kind == K::initiating) {
            AmfConfigurationUpdate m;
            if (const json* n = maybe(ies, kAmfName)) {
                m.amf_name = n->get<std::string>();
            }
            return Pdu{m};
        }
        if (kind == K::successful) {
            return Pdu{AmfConfigurationUpdateAcknowledge{}};
        }
        break;
    case kPaging: {
        Paging m;
        m.s_tmsi = read_s_tmsi(need(ies, kUePagingIdentity).at("fiveG-S-TMSI"));
        if (const json* d = maybe(ies, kPagingDrx)) {
            m.drx = d->get<std::string>();
        }
        for (const auto& t : need(ies, kTaiListForPaging)) {
            m.tais.push_back(read_tai(t.at("tAI")));
        }
        return Pdu{m};
    }
    case kInitialUeMessage: {
        InitialUeMessage m;
        m.ran = ran_id(ies);
        m.nas = read_octets(need(ies, kNasPdu));
        read_uli(need(ies, kUserLocationInformation), m.cgi, m.tai);
        m.cause = need(ies, kRrcEstablishmentCause).get<std::string>();
        if (const json* s = maybe(ies, kFiveGSTmsi)) {
            m.s_tmsi = read_s_tmsi(*s);
        }
        m.context_requested = maybe(ies, kUeContextRequest) != nullptr;
        return Pdu{m};
    }
    case kDownlinkNasTransport:
        return Pdu{DownlinkNasTransport{amf_id(ies), ran_id(ies), read_octets(need(ies, kNasPdu))}};
    case kUplinkNasTransport: {
        UplinkNasTransport m;
        m.amf = amf_id(ies);
        m.ran = ran_id(ies);
        m.nas = read_octets(need(ies, kNasPdu));
        read_uli(need(ies, kUserLocationInformation), m.cgi, m.tai);
        return Pdu{m};
    }
    case kNasNonDeliveryIndication:
        return Pdu{NasNonDeliveryIndication{amf_id(ies), ran_id(ies), read_octets(need(ies, kNasPdu)),
                                            read_cause(need(ies, kCause))}};
    case kInitialContextSetup:
        if (kind == K::initiating) {
            InitialContextSetupRequest m;
            m.amf = amf_id(ies);
            m.ran = ran_id(ies);
            m.guami = read_guami(need(ies, kGuami));
            m.allowed_nssai = read_slice_list(need(ies, kAllowedNssai));
            const json& caps = need(ies, kUeSecurityCapabilities);
            m.nr_enc = static_cast<std::uint16_t>(read_bits(caps.at("nRencryptionAlgorithms"), 16));
            m.nr_int = static_cast<std::uint16_t>(read_bits(caps.at("nRintegrityProtectionAlgorithms"), 16));
            m.eutra_enc = static_cast<std::uint16_t>(read_bits(caps.at("eUTRAencryptionAlgorithms"), 16));
            m.eutra_int = static_cast<std::uint16_t>(read_bits(caps.at("eUTRAintegrityProtectionAlgorithms"), 16));
            m.security_key = read_octets(need(ies, kSecurityKey));
            if (const json* c = maybe(ies, kUeRadioCapability)) {
                m.ue_radio_capability = read_octets(*c);
            }
            if (const json* i = maybe(ies, kMaskedImeisv)) {
                m.masked_imeisv = read_bits(*i, 64);
            }
            if (const json* n = maybe(ies, kNasPdu)) {
                m.nas = read_octets(*n);
            }
            if (const json* a = maybe(ies, kUeAmbr)) {
                m.ue_ambr = read_ambr(*a, "uEAggregateMaximumBitRateDL", "uEAggregateMaximumBitRateUL");
            }
            if (const json* l = maybe(ies, kSetupListCxtReq)) {
                auto s = read_setup_items(*l, "nAS-PDU");
                if (!s) {
                    return s.error();
                }
                m.sessions = std::move(*s);
            }
            return Pdu{std::move(m)};
        }
        if (kind == K::successful) {
            InitialContextSetupResponse m{amf_id(ies), ran_id(ies), {}, {}};
            if (const json* l = maybe(ies, kSetupListCxtRes)) {
                auto s = read_setup_ok_items(*l);
                if (!s) {
                    return s.error();
                }
                m.sessions = std::move(*s);
            }
            if (const json* l = maybe(ies, kFailedToSetupListCxtRes)) {
                auto f = read_cause_items(*l, asn_DEF_NGAP_PDUSessionResourceSetupUnsuccessfulTransfer,
                                          "pDUSessionResourceSetupUnsuccessfulTransfer");
                if (!f) {
                    return f.error();
                }
                m.failed = std::move(*f);
            }
            return Pdu{std::move(m)};
        }
        return Pdu{InitialContextSetupFailure{amf_id(ies), ran_id(ies), read_cause(need(ies, kCause))}};
    case kUeContextReleaseRequest:
        return Pdu{UeContextReleaseRequest{amf_id(ies), ran_id(ies), read_cause(need(ies, kCause))}};
    case kUeContextRelease:
        if (kind == K::initiating) {
            UeContextReleaseCommand m;
            auto [k, v] = arm(need(ies, kUeNgapIds));
            if (k == "uE-NGAP-ID-pair") {
                m.amf = v->at("aMF-UE-NGAP-ID").get<std::uint64_t>();
                m.ran = v->at("rAN-UE-NGAP-ID").get<std::uint32_t>();
            } else {
                m.amf = v->get<std::uint64_t>();
            }
            m.cause = read_cause(need(ies, kCause));
            return Pdu{m};
        }
        return Pdu{UeContextReleaseComplete{amf_id(ies), ran_id(ies)}};
    case kUeContextModification:
        if (kind == K::initiating) {
            UeContextModificationRequest m;
            m.amf = amf_id(ies);
            m.ran = ran_id(ies);
            if (const json* k = maybe(ies, kSecurityKey)) {
                m.security_key = read_octets(*k);
            }
            return Pdu{std::move(m)};
        }
        if (kind == K::successful) {
            return Pdu{UeContextModificationResponse{amf_id(ies), ran_id(ies)}};
        }
        break;
    case kUeRadioCapabilityInfoIndication:
        return Pdu{UeRadioCapabilityInfoIndication{amf_id(ies), ran_id(ies), read_octets(need(ies, kUeRadioCapability))}};
    case kPduSessionResourceSetup:
        if (kind == K::initiating) {
            PduSessionResourceSetupRequest m;
            m.amf = amf_id(ies);
            m.ran = ran_id(ies);
            if (const json* n = maybe(ies, kNasPdu)) {
                m.nas = read_octets(*n);
            }
            auto s = read_setup_items(need(ies, kSetupListSuReq), "pDUSessionNAS-PDU");
            if (!s) {
                return s.error();
            }
            m.sessions = std::move(*s);
            if (const json* a = maybe(ies, kUeAmbr)) {
                m.ue_ambr = read_ambr(*a, "uEAggregateMaximumBitRateDL", "uEAggregateMaximumBitRateUL");
            }
            return Pdu{std::move(m)};
        }
        if (kind == K::successful) {
            PduSessionResourceSetupResponse m;
            m.amf = amf_id(ies);
            m.ran = ran_id(ies);
            if (const json* l = maybe(ies, kSetupListSuRes)) {
                auto s = read_setup_ok_items(*l);
                if (!s) {
                    return s.error();
                }
                m.sessions = std::move(*s);
            }
            if (const json* l = maybe(ies, kFailedToSetupListSuRes)) {
                auto f = read_cause_items(*l, asn_DEF_NGAP_PDUSessionResourceSetupUnsuccessfulTransfer,
                                          "pDUSessionResourceSetupUnsuccessfulTransfer");
                if (!f) {
                    return f.error();
                }
                m.failed = std::move(*f);
            }
            return Pdu{std::move(m)};
        }
        break;
    case kPduSessionResourceRelease:
        if (kind == K::initiating) {
            PduSessionResourceReleaseCommand m;
            m.amf = amf_id(ies);
            m.ran = ran_id(ies);
            if (const json* n = maybe(ies, kNasPdu)) {
                m.nas = read_octets(*n);
            }
            auto s = read_cause_items(need(ies, kToReleaseListRelCmd), asn_DEF_NGAP_PDUSessionResourceReleaseCommandTransfer,
                                      "pDUSessionResourceReleaseCommandTransfer");
            if (!s) {
                return s.error();
            }
            m.sessions = std::move(*s);
            return Pdu{std::move(m)};
        }
        if (kind == K::successful) {
            PduSessionResourceReleaseResponse m;
            m.amf = amf_id(ies);
            m.ran = ran_id(ies);
            for (const auto& i : need(ies, kReleasedListRelRes)) {
                m.released.push_back(i.at("pDUSessionID").get<std::uint8_t>());
            }
            return Pdu{std::move(m)};
        }
        break;
    case kPduSessionResourceModify:
        if (kind == K::initiating) {
            PduSessionResourceModifyRequest m;
            m.amf = amf_id(ies);
            m.ran = ran_id(ies);
            for (const auto& i : need(ies, kModifyListModReq)) {
                SessionModifyItem s;
                s.psi = i.at("pDUSessionID").get<std::uint8_t>();
                if (i.contains("nAS-PDU")) {
                    s.nas = read_octets(i.at("nAS-PDU"));
                }
                auto t = decode_modify_request_transfer(read_octets(i.at("pDUSessionResourceModifyRequestTransfer")));
                if (!t) {
                    return t.error();
                }
                s.transfer = std::move(*t);
                m.sessions.push_back(std::move(s));
            }
            return Pdu{std::move(m)};
        }
        if (kind == K::successful) {
            PduSessionResourceModifyResponse m;
            m.amf = amf_id(ies);
            m.ran = ran_id(ies);
            if (const json* l = maybe(ies, kModifyListModRes)) {
                for (const auto& i : *l) {
                    auto t = decode_modify_response_transfer(read_octets(i.at("pDUSessionResourceModifyResponseTransfer")));
                    if (!t) {
                        return t.error();
                    }
                    m.sessions.push_back({i.at("pDUSessionID").get<std::uint8_t>(), std::move(*t)});
                }
            }
            if (const json* l = maybe(ies, kFailedToModifyListModRes)) {
                auto f = read_cause_items(*l, asn_DEF_NGAP_PDUSessionResourceModifyUnsuccessfulTransfer,
                                          "pDUSessionResourceModifyUnsuccessfulTransfer");
                if (!f) {
                    return f.error();
                }
                m.failed = std::move(*f);
            }
            return Pdu{std::move(m)};
        }
        break;
    case kPduSessionResourceNotify:
        if (kind == K::initiating) {
            PduSessionResourceNotify m;
            m.amf = amf_id(ies);
            m.ran = ran_id(ies);
            if (const json* l = maybe(ies, kNotifyList)) {
                for (const auto& i : *l) {
                    auto t = decode_notify_transfer(read_octets(i.at("pDUSessionResourceNotifyTransfer")));
                    if (!t) {
                        return t.error();
                    }
                    m.sessions.push_back({i.at("pDUSessionID").get<std::uint8_t>(), std::move(*t)});
                }
            }
            if (const json* l = maybe(ies, kReleasedListNot)) {
                auto f = read_cause_items(*l, asn_DEF_NGAP_PDUSessionResourceNotifyReleasedTransfer,
                                          "pDUSessionResourceNotifyReleasedTransfer");
                if (!f) {
                    return f.error();
                }
                m.released = std::move(*f);
            }
            return Pdu{std::move(m)};
        }
        break;
    default:
        break;
    }
    return Error{Errc::unsupported, static_cast<std::uint32_t>(code), "NGAP: a procedure outside the P1 set"};
}

struct Parsed {
    Header header;
    Ies ies;
};

Parsed parse(const json& j) {
    auto [kind_name, body] = arm(j);
    Parsed p;
    p.header.kind = kind_name == "initiatingMessage"   ? Header::Kind::initiating
                    : kind_name == "successfulOutcome" ? Header::Kind::successful
                                                       : Header::Kind::unsuccessful;
    p.header.procedure = body->at("procedureCode").get<std::uint8_t>();
    p.header.reject = body->at("criticality").get<std::string>() == "reject";
    auto [msg, content] = arm(body->at("value"));
    (void)msg;
    if (content->contains("protocolIEs")) {
        for (const auto& e : content->at("protocolIEs")) {
            const int id = e.at("id").get<int>();
            auto [type, value] = arm(e.at("value"));
            (void)type;
            p.ies.emplace(id, value);   // the first occurrence counts
        }
    }
    if (const json* a = maybe(p.ies, kAmfUeNgapId); a != nullptr && a->is_number_unsigned()) {
        p.header.ids.amf = a->get<std::uint64_t>();
    }
    if (const json* r = maybe(p.ies, kRanUeNgapId); r != nullptr && r->is_number_unsigned()) {
        p.header.ids.ran = r->get<std::uint32_t>();
    }
    if (const json* u = maybe(p.ies, kUeNgapIds); u != nullptr) {
        auto [k, v] = arm(*u);
        if (k == "uE-NGAP-ID-pair") {
            p.header.ids.amf = v->at("aMF-UE-NGAP-ID").get<std::uint64_t>();
            p.header.ids.ran = v->at("rAN-UE-NGAP-ID").get<std::uint32_t>();
        } else if (v->is_number_unsigned()) {
            p.header.ids.amf = v->get<std::uint64_t>();
        }
    }
    return p;
}

} // namespace

PlmnId plmn_id(std::string_view mcc, std::string_view mnc) {
    auto d = [](std::string_view s, std::size_t i) -> std::uint8_t {
        return i < s.size() ? static_cast<std::uint8_t>(s[i] - '0') : std::uint8_t{0x0F};
    };
    return {static_cast<std::uint8_t>(d(mcc, 1) << 4 | d(mcc, 0)), static_cast<std::uint8_t>(d(mnc, 2) << 4 | d(mcc, 2)),
            static_cast<std::uint8_t>(d(mnc, 1) << 4 | d(mnc, 0))};
}

Result<Bytes> encode(const Pdu& p) {
    return std::visit([](const auto& m) { return build(m); }, p);
}

Result<Header> peek(ByteView in) {
    auto j = jer::decode(asn_DEF_NGAP_NGAP_PDU, in, asn1::Rules::aper);
    if (!j) {
        return j.error();
    }
    return guarded([&]() -> Result<Header> { return parse(*j).header; });
}

namespace {

void zero_keys(jer::json& j, unsigned& n) {
    if (j.is_object()) {
        for (auto& [k, v] : j.items()) {
            if ((k == "SecurityKey" || k == "nextHopNH") && v.is_string()) {
                auto& s = v.get_ref<std::string&>();
                std::fill(s.begin(), s.end(), '0');
                ++n;
            } else {
                zero_keys(v, n);
            }
        }
    } else if (j.is_array()) {
        for (auto& v : j) {
            zero_keys(v, n);
        }
    }
}

} // namespace

Result<Redacted> redact_keys(ByteView in) {
    auto j = jer::decode(asn_DEF_NGAP_NGAP_PDU, in, asn1::Rules::aper);
    if (!j) {
        return j.error();
    }
    Redacted out;
    zero_keys(*j, out.keys);
    auto wire = jer::encode(asn_DEF_NGAP_NGAP_PDU, std::move(*j), asn1::Rules::aper);
    if (!wire) {
        return wire.error();
    }
    out.pdu = std::move(*wire);
    return out;
}

Result<Pdu> decode(ByteView in) {
    auto j = jer::decode(asn_DEF_NGAP_NGAP_PDU, in, asn1::Rules::aper);
    if (!j) {
        return j.error();
    }
    auto out = guarded([&]() -> Result<Pdu> {
        const Parsed p = parse(*j);
        return read(p.header.kind, p.header.procedure, p.ies);
    });
    jer::scrub(*j);
    return out;
}

} // namespace ksim::ngap
