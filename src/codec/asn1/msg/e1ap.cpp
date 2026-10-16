// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "codec/asn1/msg/e1ap.hpp"

#include <algorithm>
#include <map>

#include "codec/asn1/msg/jer.hpp"

extern "C" {
#include "E1AP_E1AP-PDU.h"
}

namespace ksim::e1ap {

namespace {

using jer::arm;
using jer::bad;
using jer::guarded;
using jer::hex;
using jer::json;
using jer::read_bits;
using jer::read_octets;

// Procedure codes (E1AP-Constants).
constexpr int kErrorIndication = 1;
constexpr int kE1Setup = 3;
constexpr int kBearerContextSetup = 8;
constexpr int kBearerContextModification = 9;
constexpr int kBearerContextRelease = 11;
constexpr int kBearerContextInactivityNotification = 13;

// Protocol IE identifiers.
constexpr int kCause = 0;
constexpr int kCuCpUeId = 2;
constexpr int kCuUpUeId = 3;
constexpr int kCuUpId = 7;
constexpr int kCuUpName = 8;
constexpr int kCuCpName = 9;
constexpr int kCnSupport = 10;
constexpr int kSupportedPlmns = 11;
constexpr int kSecurityInformation = 13;
constexpr int kUeDlAmbr = 14;
constexpr int kSystemBcSetupRequest = 15;
constexpr int kSystemBcSetupResponse = 16;
constexpr int kSystemBcModificationRequest = 18;
constexpr int kSystemBcModificationResponse = 19;
constexpr int kActivityNotificationLevel = 23;
constexpr int kActivityInformation = 24;
constexpr int kToSetupList = 42;
constexpr int kToModifyList = 43;
constexpr int kToRemoveList = 44;
constexpr int kSetupList = 46;
constexpr int kModifiedList = 48;
constexpr int kSetupModList = 54;
constexpr int kToSetupModList = 56;
constexpr int kTransactionId = 57;
constexpr int kServingPlmn = 58;
constexpr int kUeInactivityTimer = 59;

constexpr std::array<const char*, 4> kNea{"nEA0", "c-128-NEA1", "c-128-NEA2", "c-128-NEA3"};
constexpr std::array<const char*, 4> kNia{"nIA0", "i-128-NIA1", "i-128-NIA2", "i-128-NIA3"};

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

PlmnId read_plmn(const json& j) {
    const Bytes b = read_octets(j);
    if (b.size() != 3) {
        throw json::other_error::create(501, "PLMN identity is three octets", &j);
    }
    return {b[0], b[1], b[2]};
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

json tunnel(const GtpTunnel& t) {
    const std::uint64_t a = (std::uint64_t{t.addr[0]} << 24) | (std::uint64_t{t.addr[1]} << 16) |
                            (std::uint64_t{t.addr[2]} << 8) | t.addr[3];
    return {{"gTPTunnel", {{"transportLayerAddress", jer::var_bits(a, 32)}, {"gTP-TEID", octets(t.teid, 4)}}}};
}
GtpTunnel read_tunnel(const json& j) {
    const json& g = j.at("gTPTunnel");
    if (jer::bits_length(g.at("transportLayerAddress")) != 32) {
        throw jer::NotP1("an IPv6 or dual transport address");
    }
    const auto a = read_bits(g.at("transportLayerAddress"), 32);
    return {{static_cast<std::uint8_t>(a >> 24), static_cast<std::uint8_t>(a >> 16), static_cast<std::uint8_t>(a >> 8),
             static_cast<std::uint8_t>(a)},
            static_cast<std::uint32_t>(read_number(g.at("gTP-TEID")))};
}

json cause(const Cause& c) { return {{c.group, c.value}}; }
Cause read_cause(const json& j) {
    auto [g, v] = arm(j);
    return {g, v->get<std::string>()};
}

json security_indication(const SecurityIndication& s) {
    json j = {{"integrityProtectionIndication", s.integrity}, {"confidentialityProtectionIndication", s.confidentiality}};
    if (s.integrity != "not-needed") {
        j["maximumIPdatarate"] = {{"maxIPrate", "max-UErate"}};
    }
    return j;
}
SecurityIndication read_security_indication(const json& j) {
    return {j.at("integrityProtectionIndication").get<std::string>(), j.at("confidentialityProtectionIndication").get<std::string>()};
}
json security_result(const SecurityResult& r) {
    return {{"integrityProtectionResult", r.integrity ? "performed" : "not-performed"},
            {"confidentialityProtectionResult", r.confidentiality ? "performed" : "not-performed"}};
}
SecurityResult read_security_result(const json& j) {
    return {j.at("integrityProtectionResult").get<std::string>() == "performed",
            j.at("confidentialityProtectionResult").get<std::string>() == "performed"};
}

json flow(const QosFlow& f) {
    json p = {{"qoS-Characteristics", {{"non-Dynamic-5QI", {{"fiveQI", f.five_qi}}}}},
              {"nGRANallocationRetentionPriority",
               {{"priorityLevel", f.arp_priority},
                {"pre-emptionCapability", f.may_preempt ? "may-trigger-pre-emption" : "shall-not-trigger-pre-emption"},
                {"pre-emptionVulnerability", f.preemptable ? "pre-emptable" : "not-pre-emptable"}}}};
    if (const auto& g = f.gbr) {   // P2 Q11, in ASN.1 order
        p["gBR-QoS-Flow-Information"] = {{"maxFlowBitRateDownlink", g->mfbr_dl},
                                         {"maxFlowBitRateUplink", g->mfbr_ul},
                                         {"guaranteedFlowBitRateDownlink", g->gfbr_dl},
                                         {"guaranteedFlowBitRateUplink", g->gfbr_ul}};
    }
    if (f.reflective) {
        p["reflective-QoS-Attribute"] = "subject-to";
    }
    return {{"qoS-Flow-Identifier", f.qfi}, {"qoSFlowLevelQoSParameters", p}};
}
QosFlow read_flow(const json& j) {
    QosFlow f;
    f.qfi = j.at("qoS-Flow-Identifier").get<std::uint8_t>();
    const json& p = j.at("qoSFlowLevelQoSParameters");
    const json& c = p.at("qoS-Characteristics");
    if (!c.contains("non-Dynamic-5QI")) {
        throw jer::NotP1("a dynamic 5QI");
    }
    if (p.contains("gBR-QoS-Flow-Information")) {
        const json& g = p.at("gBR-QoS-Flow-Information");   // P2 Q11
        f.gbr = Gbr{g.at("maxFlowBitRateDownlink").get<std::uint64_t>(), g.at("maxFlowBitRateUplink").get<std::uint64_t>(),
                    g.at("guaranteedFlowBitRateDownlink").get<std::uint64_t>(),
                    g.at("guaranteedFlowBitRateUplink").get<std::uint64_t>()};
    }
    f.reflective = p.contains("reflective-QoS-Attribute");
    f.five_qi = c.at("non-Dynamic-5QI").at("fiveQI").get<std::uint16_t>();
    const json& arp = p.at("nGRANallocationRetentionPriority");
    f.arp_priority = arp.at("priorityLevel").get<std::uint8_t>();
    f.may_preempt = arp.at("pre-emptionCapability").get<std::string>() == "may-trigger-pre-emption";
    f.preemptable = arp.at("pre-emptionVulnerability").get<std::string>() == "pre-emptable";
    return f;
}

/// A DRB to set up; `flows_field` is qos-flow-Information-To-Be-Setup (setup) or
/// flow-Mapping-Information (setup in a modification).
json drb_to_setup(const DrbToSetup& d, const char* flows_field) {
    json flows = json::array();
    for (const auto& f : d.flows) {
        flows.push_back(flow(f));
    }
    const std::string sn = d.sn_bits == 12 ? "s-12" : "s-18";
    // In ASN.1 order: asn1c's JER decoder reads members in that order only (KS-PLAT-D10).
    json pdcp = {{"pDCP-SN-Size-UL", sn}, {"pDCP-SN-Size-DL", sn}, {"rLC-Mode", "rlc-am"}};
    if (d.t_reordering_ms) {
        pdcp["t-ReorderingTimer"] = {{"t-Reordering", "ms" + std::to_string(*d.t_reordering_ms)}};
    }
    pdcp["discardTimer"] = d.discard_timer;
    return {{"dRB-ID", d.drb_id},
            {"sDAP-Configuration",
             {{"defaultDRB", d.default_drb ? "true" : "false"},
              {"sDAP-Header-UL", d.sdap_ul ? "present" : "absent"},
              {"sDAP-Header-DL", d.sdap_dl ? "present" : "absent"}}},
            {"pDCP-Configuration", pdcp},
            {"cell-Group-Information", json::array({{{"cell-Group-ID", 0}}})},
            {flows_field, flows}};
}
DrbToSetup read_drb_to_setup(const json& j, const char* flows_field) {
    DrbToSetup d;
    d.drb_id = j.at("dRB-ID").get<std::uint8_t>();
    const json& s = j.at("sDAP-Configuration");
    d.default_drb = s.at("defaultDRB").get<std::string>() == "true";
    d.sdap_ul = s.at("sDAP-Header-UL").get<std::string>() == "present";
    d.sdap_dl = s.at("sDAP-Header-DL").get<std::string>() == "present";
    const std::string sn = j.at("pDCP-Configuration").at("pDCP-SN-Size-DL").get<std::string>();
    if (sn != "s-12" && sn != "s-18") {
        throw jer::NotP1("a PDCP SN size other than 12 or 18 bits");
    }
    d.sn_bits = sn == "s-12" ? 12 : 18;
    const json& pc = j.at("pDCP-Configuration");
    d.discard_timer = pc.value("discardTimer", std::string("infinity"));   // absent: no discard
    if (pc.contains("t-ReorderingTimer")) {
        d.t_reordering_ms = std::stoi(pc.at("t-ReorderingTimer").at("t-Reordering").get<std::string>().substr(2));
    }
    for (const auto& f : j.at(flows_field)) {
        d.flows.push_back(read_flow(f));
    }
    return d;
}

/// A session to set up; the setup and the setup-in-modification items differ
/// only in the DRB list's and DRB flows' field names.
json session_to_setup(const SessionToSetup& s, bool mod) {
    json drbs = json::array();
    for (const auto& d : s.drbs) {
        drbs.push_back(drb_to_setup(d, mod ? "flow-Mapping-Information" : "qos-flow-Information-To-Be-Setup"));
    }
    return {{"pDU-Session-ID", s.psi},
            {"pDU-Session-Type", s.type},
            {"sNSSAI", snssai(s.snssai)},
            {"securityIndication", security_indication(s.security)},
            {"nG-UL-UP-TNL-Information", tunnel(s.ng_ul)},
            {mod ? "dRB-To-Setup-Mod-List-NG-RAN" : "dRB-To-Setup-List-NG-RAN", drbs}};
}
SessionToSetup read_session_to_setup(const json& j, bool mod) {
    SessionToSetup s;
    s.psi = j.at("pDU-Session-ID").get<std::uint8_t>();
    s.type = j.at("pDU-Session-Type").get<std::string>();
    s.snssai = read_snssai(j.at("sNSSAI"));
    s.security = read_security_indication(j.at("securityIndication"));
    s.ng_ul = read_tunnel(j.at("nG-UL-UP-TNL-Information"));
    for (const auto& d : j.at(mod ? "dRB-To-Setup-Mod-List-NG-RAN" : "dRB-To-Setup-List-NG-RAN")) {
        s.drbs.push_back(read_drb_to_setup(d, mod ? "flow-Mapping-Information" : "qos-flow-Information-To-Be-Setup"));
    }
    return s;
}

/// DRB-Setup-Item-NG-RAN (and its -Mod twin, the same fields).
json drb_setup(const DrbSetup& d) {
    json flows = json::array();
    for (std::uint8_t q : d.qfis) {
        flows.push_back({{"qoS-Flow-Identifier", q}});
    }
    return {{"dRB-ID", d.drb_id},
            {"uL-UP-Transport-Parameters", json::array({{{"uP-TNL-Information", tunnel(d.f1u_ul)}, {"cell-Group-ID", 0}}})},
            {"flow-Setup-List", flows}};
}
DrbSetup read_drb_setup(const json& d) {
    DrbSetup x;
    x.drb_id = d.at("dRB-ID").get<std::uint8_t>();
    x.f1u_ul = read_tunnel(d.at("uL-UP-Transport-Parameters").at(0).at("uP-TNL-Information"));
    for (const auto& f : d.at("flow-Setup-List")) {
        x.qfis.push_back(f.at("qoS-Flow-Identifier").get<std::uint8_t>());
    }
    return x;
}

json session_setup(const SessionSetup& s, bool mod) {
    json drbs = json::array();
    for (const auto& d : s.drbs) {
        drbs.push_back(drb_setup(d));
    }
    json j = {{"pDU-Session-ID", s.psi}};
    if (s.security) {
        j["securityResult"] = security_result(*s.security);
    }
    j["nG-DL-UP-TNL-Information"] = tunnel(s.ng_dl);
    j[mod ? "dRB-Setup-Mod-List-NG-RAN" : "dRB-Setup-List-NG-RAN"] = drbs;
    return j;
}
SessionSetup read_session_setup(const json& j, bool mod) {
    SessionSetup s;
    s.psi = j.at("pDU-Session-ID").get<std::uint8_t>();
    if (j.contains("securityResult")) {
        s.security = read_security_result(j.at("securityResult"));
    }
    s.ng_dl = read_tunnel(j.at("nG-DL-UP-TNL-Information"));
    for (const auto& d : j.at(mod ? "dRB-Setup-Mod-List-NG-RAN" : "dRB-Setup-List-NG-RAN")) {
        s.drbs.push_back(read_drb_setup(d));
    }
    return s;
}

json ie(int id, const char* criticality, const char* type, json value) {
    return {{"id", id}, {"criticality", criticality}, {"value", {{type, std::move(value)}}}};
}

json pdu(const char* kind, int code, const char* criticality, const char* message, json ies) {
    return {{kind,
             {{"procedureCode", code},
              {"criticality", criticality},
              {"value", {{message, {{"protocolIEs", std::move(ies)}}}}}}}};
}

json ue_ids(std::uint32_t cp, std::uint32_t up, const char* crit = "reject") {
    return json::array({ie(kCuCpUeId, crit, "GNB-CU-CP-UE-E1AP-ID", cp), ie(kCuUpUeId, crit, "GNB-CU-UP-UE-E1AP-ID", up)});
}

bool sessions_ok(const std::vector<SessionToSetup>& l) {
    return std::all_of(l.begin(), l.end(), [](const SessionToSetup& s) {
        return !s.drbs.empty() && std::all_of(s.drbs.begin(), s.drbs.end(), [](const DrbToSetup& d) {
                   return d.drb_id >= 1 && d.drb_id <= 32 && !d.flows.empty() && (d.sn_bits == 12 || d.sn_bits == 18);
               });
    });
}

Result<Bytes> per(const json& j) { return jer::encode(asn_DEF_E1AP_E1AP_PDU, j, asn1::Rules::aper); }

// ---- builders ---------------------------------------------------------------------------

Result<Bytes> build(const E1SetupRequest& m) {
    if (m.cu_up_id > 68719476735ULL || m.plmns.empty()) {
        return bad("E1AP: a gNB-CU-UP ID of 36 bits and at least one PLMN");
    }
    json plmns = json::array();
    for (const auto& [p, slices] : m.plmns) {
        json item = {{"pLMN-Identity", hex(p)}};
        if (!slices.empty()) {
            json l = json::array();
            for (const auto& s : slices) {
                l.push_back({{"sNSSAI", snssai(s)}});
            }
            item["slice-Support-List"] = l;
        }
        plmns.push_back(item);
    }
    json ies = json::array({ie(kTransactionId, "reject", "TransactionID", m.transaction), ie(kCuUpId, "reject", "GNB-CU-UP-ID", m.cu_up_id)});
    if (!m.name.empty()) {
        ies.push_back(ie(kCuUpName, "ignore", "GNB-CU-UP-Name", m.name));
    }
    ies.push_back(ie(kCnSupport, "reject", "CNSupport", "c-5gc"));
    ies.push_back(ie(kSupportedPlmns, "reject", "SupportedPLMNs-List", plmns));
    return per(pdu("initiatingMessage", kE1Setup, "reject", "GNB-CU-UP-E1SetupRequest", ies));
}

Result<Bytes> build(const E1SetupResponse& m) {
    json ies = json::array({ie(kTransactionId, "reject", "TransactionID", m.transaction)});
    if (!m.cu_cp_name.empty()) {
        ies.push_back(ie(kCuCpName, "ignore", "GNB-CU-CP-Name", m.cu_cp_name));
    }
    return per(pdu("successfulOutcome", kE1Setup, "reject", "GNB-CU-UP-E1SetupResponse", ies));
}

Result<Bytes> build(const E1SetupFailure& m) {
    json ies = json::array({ie(kTransactionId, "reject", "TransactionID", m.transaction), ie(kCause, "ignore", "Cause", cause(m.cause))});
    return per(pdu("unsuccessfulOutcome", kE1Setup, "reject", "GNB-CU-UP-E1SetupFailure", ies));
}

Result<Bytes> build(const BearerContextSetupRequest& m) {
    if (m.sessions.empty() || !sessions_ok(m.sessions) || m.security.nea > 3 || m.security.enc_key.size() != 16 ||
        (m.security.nia && (*m.security.nia > 3 || !m.security.int_key || m.security.int_key->size() != 16))) {
        return bad("E1AP: BEARER CONTEXT SETUP REQUEST needs sessions with DRBs and flows, and 128-bit UP keys");
    }
    if ((m.activity_level != "drb" && m.activity_level != "pdu-session" && m.activity_level != "ue") ||
        (m.activity_level == "ue") != m.ue_inactivity_s.has_value() ||
        (m.ue_inactivity_s && (*m.ue_inactivity_s < 1 || *m.ue_inactivity_s > 7200))) {
        return bad("E1AP: the activity notification level is drb, pdu-session or ue, and ue comes with a "
                   "UE Inactivity Timer of 1..7200 s (TS 37.483 9.2.2.1)");
    }
    json alg = {{"cipheringAlgorithm", kNea[m.security.nea]}};
    if (m.security.nia) {
        alg["integrityProtectionAlgorithm"] = kNia[*m.security.nia];
    }
    json keys = {{"encryptionKey", hex(m.security.enc_key)}};
    if (m.security.int_key) {
        keys["integrityProtectionKey"] = hex(*m.security.int_key);
    }
    json sessions = json::array();
    for (const auto& s : m.sessions) {
        sessions.push_back(session_to_setup(s, false));
    }
    json ies = json::array({ie(kCuCpUeId, "reject", "GNB-CU-CP-UE-E1AP-ID", m.cu_cp_ue),
                            ie(kSecurityInformation, "reject", "SecurityInformation", {{"securityAlgorithm", alg}, {"uPSecuritykey", keys}}),
                            ie(kUeDlAmbr, "reject", "BitRate", m.ue_dl_ambr),
                            ie(kServingPlmn, "ignore", "PLMN-Identity", hex(m.serving_plmn)),
                            ie(kActivityNotificationLevel, "reject", "ActivityNotificationLevel", m.activity_level)});
    if (m.ue_inactivity_s) {
        ies.push_back(ie(kUeInactivityTimer, "reject", "Inactivity-Timer", *m.ue_inactivity_s));
    }
    ies.push_back(ie(kSystemBcSetupRequest, "reject", "System-BearerContextSetupRequest",
                     {{"nG-RAN-BearerContextSetupRequest",
                       json::array({ie(kToSetupList, "reject", "PDU-Session-Resource-To-Setup-List", sessions)})}}));
    return per(pdu("initiatingMessage", kBearerContextSetup, "reject", "BearerContextSetupRequest", ies));
}

Result<Bytes> build(const BearerContextSetupResponse& m) {
    json sessions = json::array();
    for (const auto& s : m.sessions) {
        sessions.push_back(session_setup(s, false));
    }
    json ies = ue_ids(m.cu_cp_ue, m.cu_up_ue);
    ies.push_back(ie(kSystemBcSetupResponse, "ignore", "System-BearerContextSetupResponse",
                     {{"nG-RAN-BearerContextSetupResponse",
                       json::array({ie(kSetupList, "ignore", "PDU-Session-Resource-Setup-List", sessions)})}}));
    return per(pdu("successfulOutcome", kBearerContextSetup, "reject", "BearerContextSetupResponse", ies));
}

Result<Bytes> build(const BearerContextSetupFailure& m) {
    json ies = json::array({ie(kCuCpUeId, "reject", "GNB-CU-CP-UE-E1AP-ID", m.cu_cp_ue)});
    if (m.cu_up_ue) {
        ies.push_back(ie(kCuUpUeId, "ignore", "GNB-CU-UP-UE-E1AP-ID", *m.cu_up_ue));
    }
    ies.push_back(ie(kCause, "ignore", "Cause", cause(m.cause)));
    return per(pdu("unsuccessfulOutcome", kBearerContextSetup, "reject", "BearerContextSetupFailure", ies));
}

Result<Bytes> build(const BearerContextModificationRequest& m) {
    if (!sessions_ok(m.add)) {
        return bad("E1AP: added sessions need DRBs with flows");
    }
    json ng = json::array();
    if (!m.add.empty()) {
        json l = json::array();
        for (const auto& s : m.add) {
            l.push_back(session_to_setup(s, true));
        }
        ng.push_back(ie(kToSetupModList, "reject", "PDU-Session-Resource-To-Setup-Mod-List", l));
    }
    if (!m.modify.empty()) {
        json l = json::array();
        for (const auto& s : m.modify) {
            // In ASN.1 order (KS-PLAT-D10): the AMBR, then the DRBs to set up, modify, remove.
            json item = {{"pDU-Session-ID", s.psi}};
            if (s.dl_ambr) {
                item["pDU-Session-Resource-DL-AMBR"] = *s.dl_ambr;
            }
            if (!s.drbs_setup.empty()) {
                json add = json::array();
                for (const auto& d : s.drbs_setup) {
                    add.push_back(drb_to_setup(d, "qos-flow-Information-To-Be-Setup"));
                }
                item["dRB-To-Setup-List-NG-RAN"] = add;
            }
            if (!s.drbs.empty()) {
                json drbs = json::array();
                for (const auto& d : s.drbs) {
                    json x = {{"dRB-ID", d.drb_id}};
                    if (d.f1u_dl) {
                        x["dL-UP-Parameters"] = json::array({{{"uP-TNL-Information", tunnel(*d.f1u_dl)}, {"cell-Group-ID", 0}}});
                    }
                    if (d.flows) {
                        if (d.flows->empty()) {
                            return bad("E1AP: a DRB's flow mapping names at least one flow");
                        }
                        json fl = json::array();
                        for (const auto& f : *d.flows) {
                            fl.push_back(flow(f));
                        }
                        x["flow-Mapping-Information"] = fl;
                    }
                    drbs.push_back(x);
                }
                item["dRB-To-Modify-List-NG-RAN"] = drbs;
            }
            if (!s.drbs_remove.empty()) {
                json rm = json::array();
                for (std::uint8_t d : s.drbs_remove) {
                    rm.push_back({{"dRB-ID", d}});
                }
                item["dRB-To-Remove-List-NG-RAN"] = rm;
            }
            l.push_back(item);
        }
        ng.push_back(ie(kToModifyList, "reject", "PDU-Session-Resource-To-Modify-List", l));
    }
    if (!m.remove.empty()) {
        json l = json::array();
        for (std::uint8_t psi : m.remove) {
            l.push_back({{"pDU-Session-ID", psi}});
        }
        ng.push_back(ie(kToRemoveList, "reject", "PDU-Session-Resource-To-Remove-List", l));
    }
    json ies = ue_ids(m.cu_cp_ue, m.cu_up_ue);
    if (!ng.empty()) {
        ies.push_back(ie(kSystemBcModificationRequest, "reject", "System-BearerContextModificationRequest",
                         {{"nG-RAN-BearerContextModificationRequest", ng}}));
    }
    return per(pdu("initiatingMessage", kBearerContextModification, "reject", "BearerContextModificationRequest", ies));
}

Result<Bytes> build(const BearerContextModificationResponse& m) {
    json ng = json::array();
    if (!m.added.empty()) {
        json l = json::array();
        for (const auto& s : m.added) {
            l.push_back(session_setup(s, true));
        }
        ng.push_back(ie(kSetupModList, "reject", "PDU-Session-Resource-Setup-Mod-List", l));
    }
    if (!m.modified.empty()) {
        json l = json::array();
        for (const auto& s : m.modified) {
            json drbs = json::array();
            for (std::uint8_t d : s.drbs) {
                drbs.push_back({{"dRB-ID", d}});
            }
            json item = {{"pDU-Session-ID", s.psi}};
            if (!s.drbs_setup.empty()) {
                json add = json::array();
                for (const auto& d : s.drbs_setup) {
                    add.push_back(drb_setup(d));
                }
                item["dRB-Setup-List-NG-RAN"] = add;   // before the modified list (ASN.1 order)
            }
            if (!drbs.empty()) {
                item["dRB-Modified-List-NG-RAN"] = drbs;
            }
            l.push_back(item);
        }
        ng.push_back(ie(kModifiedList, "reject", "PDU-Session-Resource-Modified-List", l));
    }
    json ies = ue_ids(m.cu_cp_ue, m.cu_up_ue);
    if (!ng.empty()) {
        ies.push_back(ie(kSystemBcModificationResponse, "ignore", "System-BearerContextModificationResponse",
                         {{"nG-RAN-BearerContextModificationResponse", ng}}));
    }
    return per(pdu("successfulOutcome", kBearerContextModification, "reject", "BearerContextModificationResponse", ies));
}

Result<Bytes> build(const BearerContextModificationFailure& m) {
    json ies = ue_ids(m.cu_cp_ue, m.cu_up_ue);
    ies.push_back(ie(kCause, "ignore", "Cause", cause(m.cause)));
    return per(pdu("unsuccessfulOutcome", kBearerContextModification, "reject", "BearerContextModificationFailure", ies));
}

Result<Bytes> build(const BearerContextReleaseCommand& m) {
    json ies = ue_ids(m.cu_cp_ue, m.cu_up_ue);
    ies.push_back(ie(kCause, "ignore", "Cause", cause(m.cause)));
    return per(pdu("initiatingMessage", kBearerContextRelease, "reject", "BearerContextReleaseCommand", ies));
}

Result<Bytes> build(const BearerContextReleaseComplete& m) {
    return per(pdu("successfulOutcome", kBearerContextRelease, "reject", "BearerContextReleaseComplete", ue_ids(m.cu_cp_ue, m.cu_up_ue)));
}

Result<Bytes> build(const BearerContextInactivityNotification& m) {
    json ies = ue_ids(m.cu_cp_ue, m.cu_up_ue);
    ies.push_back(ie(kActivityInformation, "reject", "ActivityInformation", {{"uE-Activity", m.active ? "active" : "not-active"}}));
    return per(pdu("initiatingMessage", kBearerContextInactivityNotification, "ignore", "BearerContextInactivityNotification", ies));
}

Result<Bytes> build(const ErrorIndication& m) {
    json ies = json::array({ie(kTransactionId, "reject", "TransactionID", m.transaction)});
    if (m.cu_cp_ue) {
        ies.push_back(ie(kCuCpUeId, "ignore", "GNB-CU-CP-UE-E1AP-ID", *m.cu_cp_ue));
    }
    if (m.cu_up_ue) {
        ies.push_back(ie(kCuUpUeId, "ignore", "GNB-CU-UP-UE-E1AP-ID", *m.cu_up_ue));
    }
    if (m.cause) {
        ies.push_back(ie(kCause, "ignore", "Cause", cause(*m.cause)));
    }
    return per(pdu("initiatingMessage", kErrorIndication, "ignore", "ErrorIndication", ies));
}

// ---- readers ----------------------------------------------------------------------------

using Ies = std::map<int, const json*>;

Ies ies_of(const json& container) {
    Ies out;
    for (const auto& e : container) {
        auto [type, value] = arm(e.at("value"));
        (void)type;
        out.emplace(e.at("id").get<int>(), value);
    }
    return out;
}

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

std::uint32_t cp_id(const Ies& ies) { return need(ies, kCuCpUeId).get<std::uint32_t>(); }
std::uint32_t up_id(const Ies& ies) { return need(ies, kCuUpUeId).get<std::uint32_t>(); }

/// The IEs inside a System-BearerContext… CHOICE's NG-RAN arm.
Ies ng_ran(const json& system, const char* arm_name) {
    if (!system.contains(arm_name)) {
        throw jer::NotP1("an E-UTRAN bearer context");
    }
    return ies_of(system.at(arm_name));
}

Result<Pdu> read(const std::string& kind, int code, const Ies& ies) {
    switch (code) {
    case kE1Setup:
        if (kind == "initiatingMessage") {
            E1SetupRequest m;
            m.transaction = need(ies, kTransactionId).get<std::uint8_t>();
            m.cu_up_id = need(ies, kCuUpId).get<std::uint64_t>();
            if (const json* n = maybe(ies, kCuUpName)) {
                m.name = n->get<std::string>();
            }
            for (const auto& p : need(ies, kSupportedPlmns)) {
                std::vector<Snssai> slices;
                if (p.contains("slice-Support-List")) {
                    for (const auto& s : p.at("slice-Support-List")) {
                        slices.push_back(read_snssai(s.at("sNSSAI")));
                    }
                }
                m.plmns.emplace_back(read_plmn(p.at("pLMN-Identity")), std::move(slices));
            }
            return Pdu{std::move(m)};
        }
        if (kind == "successfulOutcome") {
            E1SetupResponse m;
            m.transaction = need(ies, kTransactionId).get<std::uint8_t>();
            if (const json* n = maybe(ies, kCuCpName)) {
                m.cu_cp_name = n->get<std::string>();
            }
            return Pdu{std::move(m)};
        }
        return Pdu{E1SetupFailure{need(ies, kTransactionId).get<std::uint8_t>(), read_cause(need(ies, kCause))}};
    case kBearerContextSetup:
        if (kind == "initiatingMessage") {
            BearerContextSetupRequest m;
            m.cu_cp_ue = cp_id(ies);
            const json& sec = need(ies, kSecurityInformation);
            const json& alg = sec.at("securityAlgorithm");
            const auto nea = std::find(kNea.begin(), kNea.end(), alg.at("cipheringAlgorithm").get<std::string>());
            m.security.nea = static_cast<std::uint8_t>(nea - kNea.begin());
            if (alg.contains("integrityProtectionAlgorithm")) {
                const auto nia = std::find(kNia.begin(), kNia.end(), alg.at("integrityProtectionAlgorithm").get<std::string>());
                m.security.nia = static_cast<std::uint8_t>(nia - kNia.begin());
            }
            m.security.enc_key = read_octets(sec.at("uPSecuritykey").at("encryptionKey"));
            if (sec.at("uPSecuritykey").contains("integrityProtectionKey")) {
                m.security.int_key = read_octets(sec.at("uPSecuritykey").at("integrityProtectionKey"));
            }
            m.ue_dl_ambr = need(ies, kUeDlAmbr).get<std::uint64_t>();
            if (const json* p = maybe(ies, kServingPlmn)) {
                m.serving_plmn = read_plmn(*p);
            }
            m.activity_level = need(ies, kActivityNotificationLevel).get<std::string>();
            m.ue_inactivity_s.reset();
            if (const json* t = maybe(ies, kUeInactivityTimer)) {
                m.ue_inactivity_s = t->get<std::uint16_t>();
            }
            const Ies ng = ng_ran(need(ies, kSystemBcSetupRequest), "nG-RAN-BearerContextSetupRequest");
            for (const auto& s : need(ng, kToSetupList)) {
                m.sessions.push_back(read_session_to_setup(s, false));
            }
            return Pdu{std::move(m)};
        }
        if (kind == "successfulOutcome") {
            BearerContextSetupResponse m;
            m.cu_cp_ue = cp_id(ies);
            m.cu_up_ue = up_id(ies);
            const Ies ng = ng_ran(need(ies, kSystemBcSetupResponse), "nG-RAN-BearerContextSetupResponse");
            if (const json* l = maybe(ng, kSetupList)) {
                for (const auto& s : *l) {
                    m.sessions.push_back(read_session_setup(s, false));
                }
            }
            return Pdu{std::move(m)};
        }
        {
            BearerContextSetupFailure m;
            m.cu_cp_ue = cp_id(ies);
            if (const json* u = maybe(ies, kCuUpUeId)) {
                m.cu_up_ue = u->get<std::uint32_t>();
            }
            m.cause = read_cause(need(ies, kCause));
            return Pdu{std::move(m)};
        }
    case kBearerContextModification:
        if (kind == "initiatingMessage") {
            BearerContextModificationRequest m;
            m.cu_cp_ue = cp_id(ies);
            m.cu_up_ue = up_id(ies);
            if (const json* sys = maybe(ies, kSystemBcModificationRequest)) {
                const Ies ng = ng_ran(*sys, "nG-RAN-BearerContextModificationRequest");
                if (const json* l = maybe(ng, kToSetupModList)) {
                    for (const auto& s : *l) {
                        m.add.push_back(read_session_to_setup(s, true));
                    }
                }
                if (const json* l = maybe(ng, kToModifyList)) {
                    for (const auto& s : *l) {
                        SessionToModify x;
                        x.psi = s.at("pDU-Session-ID").get<std::uint8_t>();
                        if (s.contains("pDU-Session-Resource-DL-AMBR")) {
                            x.dl_ambr = s.at("pDU-Session-Resource-DL-AMBR").get<std::uint64_t>();
                        }
                        if (s.contains("dRB-To-Setup-List-NG-RAN")) {
                            for (const auto& d : s.at("dRB-To-Setup-List-NG-RAN")) {
                                x.drbs_setup.push_back(read_drb_to_setup(d, "qos-flow-Information-To-Be-Setup"));
                            }
                        }
                        if (s.contains("dRB-To-Modify-List-NG-RAN")) {
                            for (const auto& d : s.at("dRB-To-Modify-List-NG-RAN")) {
                                DrbToModify y;
                                y.drb_id = d.at("dRB-ID").get<std::uint8_t>();
                                if (d.contains("dL-UP-Parameters")) {
                                    y.f1u_dl = read_tunnel(d.at("dL-UP-Parameters").at(0).at("uP-TNL-Information"));
                                }
                                if (d.contains("flow-Mapping-Information")) {
                                    std::vector<QosFlow> fl;
                                    for (const auto& f : d.at("flow-Mapping-Information")) {
                                        fl.push_back(read_flow(f));
                                    }
                                    y.flows = std::move(fl);
                                }
                                x.drbs.push_back(y);
                            }
                        }
                        if (s.contains("dRB-To-Remove-List-NG-RAN")) {
                            for (const auto& d : s.at("dRB-To-Remove-List-NG-RAN")) {
                                x.drbs_remove.push_back(d.at("dRB-ID").get<std::uint8_t>());
                            }
                        }
                        m.modify.push_back(std::move(x));
                    }
                }
                if (const json* l = maybe(ng, kToRemoveList)) {
                    for (const auto& s : *l) {
                        m.remove.push_back(s.at("pDU-Session-ID").get<std::uint8_t>());
                    }
                }
            }
            return Pdu{std::move(m)};
        }
        if (kind == "successfulOutcome") {
            BearerContextModificationResponse m;
            m.cu_cp_ue = cp_id(ies);
            m.cu_up_ue = up_id(ies);
            if (const json* sys = maybe(ies, kSystemBcModificationResponse)) {
                const Ies ng = ng_ran(*sys, "nG-RAN-BearerContextModificationResponse");
                if (const json* l = maybe(ng, kSetupModList)) {
                    for (const auto& s : *l) {
                        m.added.push_back(read_session_setup(s, true));
                    }
                }
                if (const json* l = maybe(ng, kModifiedList)) {
                    for (const auto& s : *l) {
                        SessionModified x;
                        x.psi = s.at("pDU-Session-ID").get<std::uint8_t>();
                        if (s.contains("dRB-Setup-List-NG-RAN")) {
                            for (const auto& d : s.at("dRB-Setup-List-NG-RAN")) {
                                x.drbs_setup.push_back(read_drb_setup(d));
                            }
                        }
                        if (s.contains("dRB-Modified-List-NG-RAN")) {
                            for (const auto& d : s.at("dRB-Modified-List-NG-RAN")) {
                                x.drbs.push_back(d.at("dRB-ID").get<std::uint8_t>());
                            }
                        }
                        m.modified.push_back(std::move(x));
                    }
                }
            }
            return Pdu{std::move(m)};
        }
        return Pdu{BearerContextModificationFailure{cp_id(ies), up_id(ies), read_cause(need(ies, kCause))}};
    case kBearerContextRelease:
        if (kind == "initiatingMessage") {
            return Pdu{BearerContextReleaseCommand{cp_id(ies), up_id(ies), read_cause(need(ies, kCause))}};
        }
        return Pdu{BearerContextReleaseComplete{cp_id(ies), up_id(ies)}};
    case kBearerContextInactivityNotification: {
        auto [kind_name, v] = arm(need(ies, kActivityInformation));
        if (kind_name != "uE-Activity") {
            throw jer::NotP1("DRB or PDU session activity lists");
        }
        return Pdu{BearerContextInactivityNotification{cp_id(ies), up_id(ies), v->get<std::string>() == "active"}};
    }
    case kErrorIndication: {
        ErrorIndication m;
        m.transaction = need(ies, kTransactionId).get<std::uint8_t>();
        if (const json* c = maybe(ies, kCuCpUeId)) {
            m.cu_cp_ue = c->get<std::uint32_t>();
        }
        if (const json* u = maybe(ies, kCuUpUeId)) {
            m.cu_up_ue = u->get<std::uint32_t>();
        }
        if (const json* c = maybe(ies, kCause)) {
            m.cause = read_cause(*c);
        }
        return Pdu{std::move(m)};
    }
    default:
        break;
    }
    return Error{Errc::unsupported, static_cast<std::uint32_t>(code), "E1AP: a procedure outside the P1 set"};
}

void zero_keys(json& j, unsigned& n) {
    if (j.is_object()) {
        for (auto& [k, v] : j.items()) {
            if ((k == "encryptionKey" || k == "integrityProtectionKey") && v.is_string()) {
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

Result<Pdu> decode(ByteView in) {
    auto j = jer::decode(asn_DEF_E1AP_E1AP_PDU, in, asn1::Rules::aper);
    if (!j) {
        return j.error();
    }
    auto out = guarded([&]() -> Result<Pdu> {
        auto [kind, body] = arm(*j);
        const int code = body->at("procedureCode").get<int>();
        auto [msg, content] = arm(body->at("value"));
        (void)msg;
        return read(kind, code, ies_of(content->at("protocolIEs")));
    });
    jer::scrub(*j);
    return out;
}

Result<Redacted> redact_keys(ByteView in) {
    auto j = jer::decode(asn_DEF_E1AP_E1AP_PDU, in, asn1::Rules::aper);
    if (!j) {
        return j.error();
    }
    Redacted out;
    zero_keys(*j, out.keys);
    auto wire = jer::encode(asn_DEF_E1AP_E1AP_PDU, std::move(*j), asn1::Rules::aper);
    if (!wire) {
        return wire.error();
    }
    out.pdu = std::move(*wire);
    return out;
}

} // namespace ksim::e1ap
