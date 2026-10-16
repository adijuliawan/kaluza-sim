// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "codec/asn1/msg/f1ap.hpp"

#include <algorithm>
#include <map>

#include "codec/asn1/msg/jer.hpp"

extern "C" {
#include "F1AP_F1AP-PDU.h"
}

namespace ksim::f1ap {

namespace {

using jer::arm;
using jer::bad;
using jer::bits;
using jer::guarded;
using jer::hex;
using jer::json;
using jer::read_bits;
using jer::read_octets;

// Procedure codes (F1AP-Constants).
constexpr int kF1Setup = 1;
constexpr int kErrorIndication = 2;
constexpr int kGnbCuConfigurationUpdate = 4;
constexpr int kUeContextSetup = 5;
constexpr int kUeContextRelease = 6;
constexpr int kUeContextModification = 7;
constexpr int kUeContextReleaseRequest = 10;
constexpr int kInitialUlRrcMessageTransfer = 11;
constexpr int kDlRrcMessageTransfer = 12;
constexpr int kUlRrcMessageTransfer = 13;
constexpr int kPaging = 18;

// Protocol IE identifiers.
constexpr int kCause = 0;
constexpr int kCellsFailedToBeActivatedList = 1;
constexpr int kCellsFailedToBeActivatedItem = 2;
constexpr int kCellsToBeActivatedList = 3;
constexpr int kCellsToBeActivatedItem = 4;
constexpr int kCellsToBeDeactivatedList = 5;
constexpr int kCellsToBeDeactivatedItem = 6;
constexpr int kCuToDuRrcInformation = 9;
constexpr int kDuToCuRrcInformation = 39;
constexpr int kCuUeId = 40;
constexpr int kDuUeId = 41;
constexpr int kDuId = 42;
constexpr int kServedCellsItem = 43;
constexpr int kServedCellsList = 44;
constexpr int kDuName = 45;
constexpr int kRrcContainer = 50;
constexpr int kSpCellId = 63;
constexpr int kSrbId = 64;
constexpr int kSrbsToBeSetupItem = 73;
constexpr int kSrbsToBeSetupList = 74;
constexpr int kSrbsToBeSetupModItem = 75;
constexpr int kSrbsToBeSetupModList = 76;
constexpr int kTimeToWait = 77;
constexpr int kTransactionId = 78;
constexpr int kCuName = 82;
constexpr int kCRnti = 95;
constexpr int kServCellIndex = 107;
constexpr int kNrCgi = 111;
constexpr int kPagingCellItem = 112;
constexpr int kPagingCellList = 113;
constexpr int kPagingDrx = 114;
constexpr int kUeIdentityIndexValue = 117;
constexpr int kPagingIdentity = 127;
constexpr int kDuToCuRrcContainer = 128;
constexpr int kCuRrcVersion = 170;
constexpr int kDuRrcVersion = 171;
constexpr int kSrbsSetupList = 202;
constexpr int kSrbsSetupItem = 203;
constexpr int kDrbsSetupItem = 26;
constexpr int kDrbsSetupList = 27;
constexpr int kDrbsSetupModItem = 28;
constexpr int kDrbsSetupModList = 29;
constexpr int kDrbsToBeReleasedItem = 32;
constexpr int kDrbsToBeReleasedList = 33;
constexpr int kDrbsToBeSetupItem = 34;
constexpr int kDrbsToBeSetupList = 35;
constexpr int kDrbsToBeSetupModItem = 36;
constexpr int kDrbsToBeSetupModList = 37;
constexpr int kDrbsModifiedItem = 20;        // P2 Q10
constexpr int kDrbsModifiedList = 21;
constexpr int kDrbsToBeModifiedItem = 30;
constexpr int kDrbsToBeModifiedList = 31;
constexpr int kDrbInformation = 164;
constexpr int kDlPdcpSnLength = 161;
constexpr int kUlPdcpSnLength = 192;

const std::string kRrcVersion = bits(0x4, 3);   // latest-RRC-Version: the Rel-15 'version 15' bit

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

json nr_cgi(const NrCgi& c) { return {{"pLMN-Identity", plmn(c.plmn)}, {"nRCellIdentity", bits(c.nci, 36)}}; }
NrCgi read_nr_cgi(const json& j) { return {read_plmn(j.at("pLMN-Identity")), read_bits(j.at("nRCellIdentity"), 36)}; }

json cause(const Cause& c) { return {{c.group, c.value}}; }
Cause read_cause(const json& j) {
    auto [g, v] = arm(j);
    return {g, v->get<std::string>()};
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

json initiating(int code, const char* crit, const char* message, json ies) {
    return pdu("initiatingMessage", code, crit, message, std::move(ies));
}
json successful(int code, const char* crit, const char* message, json ies) {
    return pdu("successfulOutcome", code, crit, message, std::move(ies));
}
json unsuccessful(int code, const char* crit, const char* message, json ies) {
    return pdu("unsuccessfulOutcome", code, crit, message, std::move(ies));
}

json ue_ids(std::uint32_t cu, std::uint32_t du, const char* crit = "reject") {
    return json::array({ie(kCuUeId, crit, "GNB-CU-UE-F1AP-ID", cu), ie(kDuUeId, crit, "GNB-DU-UE-F1AP-ID", du)});
}

json srb_list(const std::vector<std::uint8_t>& srbs, int item_id, const char* item_type) {
    json l = json::array();
    for (std::uint8_t s : srbs) {
        l.push_back(ie(item_id, "reject", item_type, {{"sRBID", s}}));
    }
    return l;
}

Result<Bytes> per(const json& j) { return jer::encode(asn_DEF_F1AP_F1AP_PDU, j, asn1::Rules::aper); }

json f1_tunnel(const GtpTunnel& t) {
    const std::uint64_t a = (std::uint64_t{t.addr[0]} << 24) | (std::uint64_t{t.addr[1]} << 16) |
                            (std::uint64_t{t.addr[2]} << 8) | t.addr[3];
    return {{"gTPTunnel", {{"transportLayerAddress", jer::var_bits(a, 32)}, {"gTP-TEID", octets(t.teid, 4)}}}};
}
GtpTunnel read_f1_tunnel(const json& j) {
    const json& g = j.at("gTPTunnel");
    if (jer::bits_length(g.at("transportLayerAddress")) != 32) {
        throw jer::NotP1("an IPv6 or dual transport address");
    }
    const auto a = read_bits(g.at("transportLayerAddress"), 32);
    return {{static_cast<std::uint8_t>(a >> 24), static_cast<std::uint8_t>(a >> 16), static_cast<std::uint8_t>(a >> 8),
             static_cast<std::uint8_t>(a)},
            static_cast<std::uint32_t>(read_number(g.at("gTP-TEID")))};
}

json flow_qos(const Flow& f) {
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
    return p;
}
Flow read_flow_qos(std::uint8_t qfi, const json& j) {
    const json& c = j.at("qoS-Characteristics");
    if (!c.contains("non-Dynamic-5QI")) {
        throw jer::NotP1("a dynamic 5QI");
    }
    const json& arp = j.at("nGRANallocationRetentionPriority");
    Flow f{qfi, c.at("non-Dynamic-5QI").at("fiveQI").get<std::uint16_t>(), arp.at("priorityLevel").get<std::uint8_t>(),
           arp.at("pre-emptionCapability").get<std::string>() == "may-trigger-pre-emption",
           arp.at("pre-emptionVulnerability").get<std::string>() == "pre-emptable", std::nullopt, j.contains("reflective-QoS-Attribute")};
    if (j.contains("gBR-QoS-Flow-Information")) {
        const json& g = j.at("gBR-QoS-Flow-Information");   // P2 Q11
        f.gbr = Gbr{g.at("maxFlowBitRateDownlink").get<std::uint64_t>(), g.at("maxFlowBitRateUplink").get<std::uint64_t>(),
                    g.at("guaranteedFlowBitRateDownlink").get<std::uint64_t>(),
                    g.at("guaranteedFlowBitRateUplink").get<std::uint64_t>()};
    }
    return f;
}

bool drbs_ok(const std::vector<DrbToSetup>& l) {
    return std::all_of(l.begin(), l.end(), [](const DrbToSetup& d) { return d.drb_id >= 1 && d.drb_id <= 32 && !d.flows.empty(); });
}

/// DRBs-ToBeSetup(-Mod)-Item: the DRB's QoS is its first flow's (TS 38.473 9.3.1.27).
/// DRBs-ToBeModified-Item (`modify`, P2 Q10) has no RLC mode and keeps the SN lengths.
json drb_items(const std::vector<DrbToSetup>& l, int item_id, const char* item_type, bool modify = false) {
    json out = json::array();
    for (const auto& d : l) {
        json snssai = {{"sST", octets(d.snssai.sst, 1)}};
        if (d.snssai.sd) {
            snssai["sD"] = octets(*d.snssai.sd, 3);
        }
        json flows = json::array();
        for (const auto& f : d.flows) {
            flows.push_back({{"qoSFlowIdentifier", f.qfi}, {"qoSFlowLevelQoSParameters", flow_qos(f)}});
        }
        json info = {{"dRB-QoS", flow_qos(d.flows.front())}, {"sNSSAI", snssai}, {"flows-Mapped-To-DRB-List", flows}};
        const auto sn_length = [](int id, std::uint8_t bits) {
            return json{{"id", id}, {"criticality", "ignore"},
                        {"extensionValue", {{"PDCPSNLength", bits == 12 ? "twelve-bits" : "eighteen-bits"}}}};
        };
        json ext = json::array({sn_length(kDlPdcpSnLength, d.dl_pdcp_sn_bits)});
        if (d.ul_pdcp_sn_bits.has_value()) {
            ext.push_back(sn_length(kUlPdcpSnLength, d.ul_pdcp_sn_bits.value_or(18)));
        }
        json qos = {{"choice-extension", {{"id", kDrbInformation}, {"criticality", "ignore"}, {"value", {{"DRB-Information", info}}}}}};
        json ul = json::array({{{"uLUPTNLInformation", f1_tunnel(d.ul)}}});
        if (modify) {
            out.push_back(ie(item_id, "reject", item_type,
                             {{"dRBID", d.drb_id}, {"qoSInformation", qos}, {"uLUPTNLInformation-ToBeSetup-List", ul}}));
            continue;
        }
        out.push_back(ie(item_id, "reject", item_type,
                         {{"dRBID", d.drb_id},
                          {"qoSInformation", qos},
                          {"uLUPTNLInformation-ToBeSetup-List", ul},
                          {"rLCMode", "rlc-am"},
                          {"iE-Extensions", ext}}));
    }
    return out;
}

json drb_setup_items(const std::vector<DrbSetup>& l, int item_id, const char* item_type) {
    json out = json::array();
    for (const auto& d : l) {
        json v = {{"dRBID", d.drb_id}};
        if (d.lcid) {
            v["lCID"] = *d.lcid;
        }
        v["dLUPTNLInformation-ToBeSetup-List"] = json::array({{{"dLUPTNLInformation", f1_tunnel(d.dl)}}});
        out.push_back(ie(item_id, "ignore", item_type, v));
    }
    return out;
}

bool srbs_ok(const std::vector<std::uint8_t>& srbs) {
    return std::all_of(srbs.begin(), srbs.end(), [](std::uint8_t s) { return s <= 3; });
}

bool sn_lengths_ok(const std::vector<DrbToSetup>& drbs) {
    const auto ok = [](std::uint8_t b) { return b == 12 || b == 18; };
    return std::all_of(drbs.begin(), drbs.end(), [&ok](const DrbToSetup& d) {
        return ok(d.dl_pdcp_sn_bits) && (!d.ul_pdcp_sn_bits || ok(*d.ul_pdcp_sn_bits));
    });
}

// ---- builders ---------------------------------------------------------------------------

Result<Bytes> build(const F1SetupRequest& m) {
    if (m.du_id >> 36 != 0) {
        return bad("F1AP: a gNB-DU ID over 36 bits");
    }
    json ies = json::array({ie(kTransactionId, "reject", "TransactionID", m.transaction),
                            ie(kDuId, "reject", "GNB-DU-ID", m.du_id)});
    if (!m.du_name.empty()) {
        ies.push_back(ie(kDuName, "ignore", "GNB-DU-Name", m.du_name));
    }
    if (!m.cells.empty()) {
        json cells = json::array();
        for (const auto& c : m.cells) {
            if (c.pci > 1007 || c.tac >> 24 != 0 || c.plmns.empty() || c.meas_timing.empty() || c.cgi.nci >> 36 != 0) {
                return bad("F1AP: a served cell needs a PCI, a 24-bit TAC, PLMNs and its measurement timing");
            }
            json plmns = json::array();
            for (const auto& p : c.plmns) {
                plmns.push_back({{"pLMN-Identity", plmn(p)}});
            }
            json info = {{"nRCGI", nr_cgi(c.cgi)},
                         {"nRPCI", c.pci},
                         {"fiveGS-TAC", octets(c.tac, 3)},
                         {"servedPLMNs", plmns},
                         {"nR-Mode-Info",
                          {{"tDD",
                            {{"nRFreqInfo",
                              {{"nRARFCN", c.arfcn},
                               {"freqBandListNr",
                                json::array({{{"freqBandIndicatorNr", c.band}, {"supportedSULBandList", json::array()}}})}}},
                             {"transmission-Bandwidth", {{"nRSCS", c.scs}, {"nRNRB", c.nrb}}}}}}},
                         {"measurementTimingConfiguration", hex(c.meas_timing)}};
            json item = {{"served-Cell-Information", info}};
            if (!c.mib.empty() && !c.sib1.empty()) {
                item["gNB-DU-System-Information"] = {{"mIB-message", hex(c.mib)}, {"sIB1-message", hex(c.sib1)}};
            }
            cells.push_back(ie(kServedCellsItem, "reject", "GNB-DU-Served-Cells-Item", item));
        }
        ies.push_back(ie(kServedCellsList, "reject", "GNB-DU-Served-Cells-List", cells));
    }
    ies.push_back(ie(kDuRrcVersion, "reject", "RRC-Version", {{"latest-RRC-Version", kRrcVersion}}));
    return per(initiating(kF1Setup, "reject", "F1SetupRequest", ies));
}

Result<Bytes> build(const F1SetupResponse& m) {
    json ies = json::array({ie(kTransactionId, "reject", "TransactionID", m.transaction)});
    if (!m.cu_name.empty()) {
        ies.push_back(ie(kCuName, "ignore", "GNB-CU-Name", m.cu_name));
    }
    if (!m.activate.empty()) {
        json l = json::array();
        for (const auto& c : m.activate) {
            l.push_back(ie(kCellsToBeActivatedItem, "reject", "Cells-to-be-Activated-List-Item", {{"nRCGI", nr_cgi(c)}}));
        }
        ies.push_back(ie(kCellsToBeActivatedList, "reject", "Cells-to-be-Activated-List", l));
    }
    ies.push_back(ie(kCuRrcVersion, "reject", "RRC-Version", {{"latest-RRC-Version", kRrcVersion}}));
    return per(successful(kF1Setup, "reject", "F1SetupResponse", ies));
}

Result<Bytes> build(const F1SetupFailure& m) {
    json ies = json::array({ie(kTransactionId, "reject", "TransactionID", m.transaction),
                            ie(kCause, "ignore", "Cause", cause(m.cause))});
    if (m.time_to_wait) {
        ies.push_back(ie(kTimeToWait, "ignore", "TimeToWait", *m.time_to_wait));
    }
    return per(unsuccessful(kF1Setup, "reject", "F1SetupFailure", ies));
}

Result<Bytes> build(const InitialUlRrcMessageTransfer& m) {
    if (m.rrc.empty()) {
        return bad("F1AP: no RRC container");
    }
    json ies = json::array({ie(kDuUeId, "reject", "GNB-DU-UE-F1AP-ID", m.du_ue), ie(kNrCgi, "reject", "NRCGI", nr_cgi(m.cgi)),
                            ie(kCRnti, "reject", "C-RNTI", m.c_rnti), ie(kRrcContainer, "reject", "RRCContainer", hex(m.rrc))});
    if (m.du_to_cu) {
        ies.push_back(ie(kDuToCuRrcContainer, "reject", "DUtoCURRCContainer", hex(*m.du_to_cu)));
    }
    ies.push_back(ie(kTransactionId, "ignore", "TransactionID", m.transaction));
    return per(initiating(kInitialUlRrcMessageTransfer, "ignore", "InitialULRRCMessageTransfer", ies));
}

Result<Bytes> build(const DlRrcMessageTransfer& m) {
    if (m.srb > 3 || m.rrc.empty()) {
        return bad("F1AP: an SRB ID outside 0..3, or no RRC container");
    }
    json ies = ue_ids(m.cu_ue, m.du_ue);
    ies.push_back(ie(kSrbId, "reject", "SRBID", m.srb));
    ies.push_back(ie(kRrcContainer, "reject", "RRCContainer", hex(m.rrc)));
    return per(initiating(kDlRrcMessageTransfer, "ignore", "DLRRCMessageTransfer", ies));
}

Result<Bytes> build(const UlRrcMessageTransfer& m) {
    if (m.srb > 3 || m.rrc.empty()) {
        return bad("F1AP: an SRB ID outside 0..3, or no RRC container");
    }
    json ies = ue_ids(m.cu_ue, m.du_ue);
    ies.push_back(ie(kSrbId, "reject", "SRBID", m.srb));
    ies.push_back(ie(kRrcContainer, "reject", "RRCContainer", hex(m.rrc)));
    return per(initiating(kUlRrcMessageTransfer, "ignore", "ULRRCMessageTransfer", ies));
}

Result<Bytes> build(const UeContextSetupRequest& m) {
    if (!srbs_ok(m.srbs) || m.serv_cell_index > 31 || !sn_lengths_ok(m.drbs)) {
        return bad("F1AP: an SRB ID outside 0..3, a serving cell index over 31, or a PDCP SN length not 12 or 18");
    }
    json ies = json::array({ie(kCuUeId, "reject", "GNB-CU-UE-F1AP-ID", m.cu_ue)});
    if (m.du_ue) {
        ies.push_back(ie(kDuUeId, "ignore", "GNB-DU-UE-F1AP-ID", *m.du_ue));
    }
    ies.push_back(ie(kSpCellId, "reject", "NRCGI", nr_cgi(m.spcell)));
    ies.push_back(ie(kServCellIndex, "reject", "ServCellIndex", m.serv_cell_index));
    json cu_to_du = json::object();
    if (m.ue_capability) {
        cu_to_du["uE-CapabilityRAT-ContainerList"] = hex(*m.ue_capability);
    }
    ies.push_back(ie(kCuToDuRrcInformation, "reject", "CUtoDURRCInformation", cu_to_du));
    if (!m.srbs.empty()) {
        ies.push_back(ie(kSrbsToBeSetupList, "reject", "SRBs-ToBeSetup-List",
                         srb_list(m.srbs, kSrbsToBeSetupItem, "SRBs-ToBeSetup-Item")));
    }
    if (!drbs_ok(m.drbs)) {
        return bad("F1AP: a DRB ID is 1..32 and a DRB maps at least one flow");
    }
    if (!m.drbs.empty()) {
        ies.push_back(ie(kDrbsToBeSetupList, "reject", "DRBs-ToBeSetup-List", drb_items(m.drbs, kDrbsToBeSetupItem, "DRBs-ToBeSetup-Item")));
    }
    if (m.rrc) {
        ies.push_back(ie(kRrcContainer, "ignore", "RRCContainer", hex(*m.rrc)));
    }
    return per(initiating(kUeContextSetup, "reject", "UEContextSetupRequest", ies));
}

Result<Bytes> build(const UeContextSetupResponse& m) {
    if (m.cell_group.empty()) {
        return bad("F1AP: a UE CONTEXT SETUP RESPONSE carries the CellGroupConfig");
    }
    json ies = ue_ids(m.cu_ue, m.du_ue);
    ies.push_back(ie(kDuToCuRrcInformation, "reject", "DUtoCURRCInformation", {{"cellGroupConfig", hex(m.cell_group)}}));
    if (!m.srbs.empty()) {
        json l = json::array();
        for (const auto& [srb, lcid] : m.srbs) {
            l.push_back(ie(kSrbsSetupItem, "ignore", "SRBs-Setup-Item", {{"sRBID", srb}, {"lCID", lcid}}));
        }
        ies.push_back(ie(kSrbsSetupList, "ignore", "SRBs-Setup-List", l));
    }
    if (!m.drbs.empty()) {
        ies.push_back(ie(kDrbsSetupList, "ignore", "DRBs-Setup-List", drb_setup_items(m.drbs, kDrbsSetupItem, "DRBs-Setup-Item")));
    }
    return per(successful(kUeContextSetup, "reject", "UEContextSetupResponse", ies));
}

Result<Bytes> build(const UeContextSetupFailure& m) {
    json ies = json::array({ie(kCuUeId, "reject", "GNB-CU-UE-F1AP-ID", m.cu_ue)});
    if (m.du_ue) {
        ies.push_back(ie(kDuUeId, "ignore", "GNB-DU-UE-F1AP-ID", *m.du_ue));
    }
    ies.push_back(ie(kCause, "ignore", "Cause", cause(m.cause)));
    return per(unsuccessful(kUeContextSetup, "reject", "UEContextSetupFailure", ies));
}

Result<Bytes> build(const UeContextModificationRequest& m) {
    if (!srbs_ok(m.srbs) || !sn_lengths_ok(m.drbs)) {
        return bad("F1AP: an SRB ID outside 0..3, or a PDCP SN length not 12 or 18");
    }
    json ies = ue_ids(m.cu_ue, m.du_ue);
    if (m.rrc) {
        ies.push_back(ie(kRrcContainer, "reject", "RRCContainer", hex(*m.rrc)));
    }
    if (!m.srbs.empty()) {
        ies.push_back(ie(kSrbsToBeSetupModList, "reject", "SRBs-ToBeSetupMod-List",
                         srb_list(m.srbs, kSrbsToBeSetupModItem, "SRBs-ToBeSetupMod-Item")));
    }
    if (!drbs_ok(m.drbs)) {
        return bad("F1AP: a DRB ID is 1..32 and a DRB maps at least one flow");
    }
    if (!m.drbs.empty()) {
        ies.push_back(ie(kDrbsToBeSetupModList, "reject", "DRBs-ToBeSetupMod-List",
                         drb_items(m.drbs, kDrbsToBeSetupModItem, "DRBs-ToBeSetupMod-Item")));
    }
    if (!drbs_ok(m.modify_drbs)) {
        return bad("F1AP: a DRB to modify is 1..32 and maps at least one flow");
    }
    if (!m.modify_drbs.empty()) {
        ies.push_back(ie(kDrbsToBeModifiedList, "reject", "DRBs-ToBeModified-List",
                         drb_items(m.modify_drbs, kDrbsToBeModifiedItem, "DRBs-ToBeModified-Item", true)));
    }
    if (!m.release_drbs.empty()) {
        json l = json::array();
        for (std::uint8_t d : m.release_drbs) {
            l.push_back(ie(kDrbsToBeReleasedItem, "reject", "DRBs-ToBeReleased-Item", {{"dRBID", d}}));
        }
        ies.push_back(ie(kDrbsToBeReleasedList, "reject", "DRBs-ToBeReleased-List", l));
    }
    return per(initiating(kUeContextModification, "reject", "UEContextModificationRequest", ies));
}

Result<Bytes> build(const UeContextModificationResponse& m) {
    json ies = ue_ids(m.cu_ue, m.du_ue);
    if (m.cell_group) {
        ies.push_back(ie(kDuToCuRrcInformation, "reject", "DUtoCURRCInformation", {{"cellGroupConfig", hex(*m.cell_group)}}));
    }
    if (!m.drbs.empty()) {
        ies.push_back(ie(kDrbsSetupModList, "ignore", "DRBs-SetupMod-List", drb_setup_items(m.drbs, kDrbsSetupModItem, "DRBs-SetupMod-Item")));
    }
    if (!m.modified.empty()) {
        ies.push_back(ie(kDrbsModifiedList, "ignore", "DRBs-Modified-List", drb_setup_items(m.modified, kDrbsModifiedItem, "DRBs-Modified-Item")));
    }
    return per(successful(kUeContextModification, "reject", "UEContextModificationResponse", ies));
}

Result<Bytes> build(const UeContextReleaseRequest& m) {
    json ies = ue_ids(m.cu_ue, m.du_ue);
    ies.push_back(ie(kCause, "ignore", "Cause", cause(m.cause)));
    return per(initiating(kUeContextReleaseRequest, "ignore", "UEContextReleaseRequest", ies));
}

Result<Bytes> build(const UeContextReleaseCommand& m) {
    if (m.rrc.has_value() != m.srb.has_value() || (m.srb && *m.srb > 3)) {
        return bad("F1AP: an RRC container travels with its SRB ID (0..3)");
    }
    json ies = ue_ids(m.cu_ue, m.du_ue);
    ies.push_back(ie(kCause, "ignore", "Cause", cause(m.cause)));
    if (m.rrc) {
        ies.push_back(ie(kRrcContainer, "ignore", "RRCContainer", hex(*m.rrc)));
        ies.push_back(ie(kSrbId, "ignore", "SRBID", *m.srb));
    }
    return per(initiating(kUeContextRelease, "reject", "UEContextReleaseCommand", ies));
}

Result<Bytes> build(const UeContextReleaseComplete& m) {
    return per(successful(kUeContextRelease, "reject", "UEContextReleaseComplete", ue_ids(m.cu_ue, m.du_ue)));
}

Result<Bytes> build(const Paging& m) {
    if (m.ue_identity_index > 1023 || m.s_tmsi >> 48 != 0 || m.cells.empty()) {
        return bad("F1AP: a 10-bit UE identity index, a 48-bit 5G-S-TMSI and at least one cell");
    }
    json cells = json::array();
    for (const auto& c : m.cells) {
        cells.push_back(ie(kPagingCellItem, "ignore", "PagingCell-Item", {{"nRCGI", nr_cgi(c)}}));
    }
    json ies = json::array({ie(kUeIdentityIndexValue, "reject", "UEIdentityIndexValue",
                               {{"indexLength10", bits(m.ue_identity_index, 10)}}),
                            ie(kPagingIdentity, "reject", "PagingIdentity",
                               {{"cNUEPagingIdentity", {{"fiveG-S-TMSI", bits(m.s_tmsi, 48)}}}})});
    if (m.drx) {
        ies.push_back(ie(kPagingDrx, "ignore", "PagingDRX", *m.drx));
    }
    ies.push_back(ie(kPagingCellList, "ignore", "PagingCell-list", cells));
    return per(initiating(kPaging, "ignore", "Paging", ies));
}

Result<Bytes> build(const ErrorIndication& m) {
    json ies = json::array({ie(kTransactionId, "reject", "TransactionID", m.transaction)});
    if (m.cu_ue) {
        ies.push_back(ie(kCuUeId, "ignore", "GNB-CU-UE-F1AP-ID", *m.cu_ue));
    }
    if (m.du_ue) {
        ies.push_back(ie(kDuUeId, "ignore", "GNB-DU-UE-F1AP-ID", *m.du_ue));
    }
    if (m.cause) {
        ies.push_back(ie(kCause, "ignore", "Cause", cause(*m.cause)));
    }
    return per(initiating(kErrorIndication, "ignore", "ErrorIndication", ies));
}

Result<Bytes> build(const GnbCuConfigurationUpdate& m) {
    json ies = json::array({ie(kTransactionId, "reject", "TransactionID", m.transaction)});
    const auto cells = [](const std::vector<NrCgi>& l, int item_id, const char* item_type) {
        json out = json::array();
        for (const auto& c : l) {
            out.push_back(ie(item_id, "reject", item_type, {{"nRCGI", nr_cgi(c)}}));
        }
        return out;
    };
    if (!m.activate.empty()) {
        ies.push_back(ie(kCellsToBeActivatedList, "reject", "Cells-to-be-Activated-List",
                         cells(m.activate, kCellsToBeActivatedItem, "Cells-to-be-Activated-List-Item")));
    }
    if (!m.deactivate.empty()) {
        ies.push_back(ie(kCellsToBeDeactivatedList, "reject", "Cells-to-be-Deactivated-List",
                         cells(m.deactivate, kCellsToBeDeactivatedItem, "Cells-to-be-Deactivated-List-Item")));
    }
    return per(initiating(kGnbCuConfigurationUpdate, "reject", "GNBCUConfigurationUpdate", ies));
}

Result<Bytes> build(const GnbCuConfigurationUpdateAcknowledge& m) {
    json ies = json::array({ie(kTransactionId, "reject", "TransactionID", m.transaction)});
    if (!m.failed.empty()) {
        json l = json::array();
        for (const auto& f : m.failed) {
            l.push_back(ie(kCellsFailedToBeActivatedItem, "reject", "Cells-Failed-to-be-Activated-List-Item",
                           {{"nRCGI", nr_cgi(f.cgi)}, {"cause", cause(f.cause)}}));
        }
        ies.push_back(ie(kCellsFailedToBeActivatedList, "reject", "Cells-Failed-to-be-Activated-List", l));
    }
    return per(successful(kGnbCuConfigurationUpdate, "reject", "GNBCUConfigurationUpdateAcknowledge", ies));
}

Result<Bytes> build(const GnbCuConfigurationUpdateFailure& m) {
    json ies = json::array({ie(kTransactionId, "reject", "TransactionID", m.transaction),
                            ie(kCause, "ignore", "Cause", cause(m.cause))});
    if (m.time_to_wait) {
        ies.push_back(ie(kTimeToWait, "ignore", "TimeToWait", *m.time_to_wait));
    }
    return per(unsuccessful(kGnbCuConfigurationUpdate, "reject", "GNBCUConfigurationUpdateFailure", ies));
}

Result<Bytes> build(const UeContextModificationFailure& m) {
    json ies = ue_ids(m.cu_ue, m.du_ue);
    ies.push_back(ie(kCause, "ignore", "Cause", cause(m.cause)));
    return per(unsuccessful(kUeContextModification, "reject", "UEContextModificationFailure", ies));
}

// ---- readers -----------------------------------------------------------------------------

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

std::uint32_t cu_id(const Ies& ies) { return need(ies, kCuUeId).get<std::uint32_t>(); }
std::uint32_t du_id(const Ies& ies) { return need(ies, kDuUeId).get<std::uint32_t>(); }

/// The items of a list of single containers: the value inside each.
std::vector<const json*> items(const json& list) {
    std::vector<const json*> out;
    for (const auto& e : list) {
        out.push_back(arm(e.at("value")).second);
    }
    return out;
}

std::vector<DrbToSetup> read_drbs(const json& list) {
    std::vector<DrbToSetup> out;
    for (const json* i : items(list)) {
        DrbToSetup d;
        d.drb_id = i->at("dRBID").get<std::uint8_t>();
        const json& q = i->at("qoSInformation");
        if (!q.contains("choice-extension")) {
            throw jer::NotP1("E-UTRAN QoS for a DRB");
        }
        auto [type, info] = arm(q.at("choice-extension").at("value"));
        (void)type;
        const json& sn = info->at("sNSSAI");
        d.snssai.sst = static_cast<std::uint8_t>(read_number(sn.at("sST")));
        if (sn.contains("sD")) {
            d.snssai.sd = static_cast<std::uint32_t>(read_number(sn.at("sD")));
        }
        for (const auto& f : info->at("flows-Mapped-To-DRB-List")) {
            d.flows.push_back(read_flow_qos(f.at("qoSFlowIdentifier").get<std::uint8_t>(), f.at("qoSFlowLevelQoSParameters")));
        }
        d.ul = read_f1_tunnel(i->at("uLUPTNLInformation-ToBeSetup-List").at(0).at("uLUPTNLInformation"));
        if (i->contains("iE-Extensions")) {
            for (const auto& e : i->at("iE-Extensions")) {
                const int id = e.at("id").get<int>();
                if (id != kDlPdcpSnLength && id != kUlPdcpSnLength) {
                    continue;
                }
                const std::uint8_t bits = e.at("extensionValue").at("PDCPSNLength").get<std::string>() == "twelve-bits" ? 12 : 18;
                if (id == kDlPdcpSnLength) {
                    d.dl_pdcp_sn_bits = bits;
                } else {
                    d.ul_pdcp_sn_bits = bits;
                }
            }
        }
        out.push_back(std::move(d));
    }
    return out;
}

std::vector<DrbSetup> read_drbs_setup(const json& list) {
    std::vector<DrbSetup> out;
    for (const json* i : items(list)) {
        DrbSetup d;
        d.drb_id = i->at("dRBID").get<std::uint8_t>();
        if (i->contains("lCID")) {
            d.lcid = i->at("lCID").get<std::uint8_t>();
        }
        d.dl = read_f1_tunnel(i->at("dLUPTNLInformation-ToBeSetup-List").at(0).at("dLUPTNLInformation"));
        out.push_back(d);
    }
    return out;
}

std::vector<std::uint8_t> read_srbs(const json& list) {
    std::vector<std::uint8_t> out;
    for (const json* i : items(list)) {
        out.push_back(i->at("sRBID").get<std::uint8_t>());
    }
    return out;
}

ServedCell read_cell(const json& item) {
    ServedCell c;
    const json& info = item.at("served-Cell-Information");
    c.cgi = read_nr_cgi(info.at("nRCGI"));
    c.pci = info.at("nRPCI").get<std::uint16_t>();
    if (info.contains("fiveGS-TAC")) {
        c.tac = static_cast<std::uint32_t>(read_number(info.at("fiveGS-TAC")));
    }
    for (const auto& p : info.at("servedPLMNs")) {
        c.plmns.push_back(read_plmn(p.at("pLMN-Identity")));
    }
    auto [mode, mi] = arm(info.at("nR-Mode-Info"));
    if (mode == "tDD") {
        c.arfcn = mi->at("nRFreqInfo").at("nRARFCN").get<std::uint32_t>();
        c.band = mi->at("nRFreqInfo").at("freqBandListNr").at(0).at("freqBandIndicatorNr").get<std::uint16_t>();
        c.scs = mi->at("transmission-Bandwidth").at("nRSCS").get<std::string>();
        c.nrb = mi->at("transmission-Bandwidth").at("nRNRB").get<std::string>();
    }
    c.meas_timing = read_octets(info.at("measurementTimingConfiguration"));
    if (item.contains("gNB-DU-System-Information")) {
        c.mib = read_octets(item.at("gNB-DU-System-Information").at("mIB-message"));
        c.sib1 = read_octets(item.at("gNB-DU-System-Information").at("sIB1-message"));
    }
    return c;
}

Result<Pdu> read(Header::Kind kind, int code, const Ies& ies) {
    using K = Header::Kind;
    switch (code) {
    case kF1Setup:
        if (kind == K::initiating) {
            F1SetupRequest m;
            m.transaction = need(ies, kTransactionId).get<std::uint8_t>();
            m.du_id = need(ies, kDuId).get<std::uint64_t>();
            if (const json* n = maybe(ies, kDuName)) {
                m.du_name = n->get<std::string>();
            }
            if (const json* l = maybe(ies, kServedCellsList)) {
                for (const json* i : items(*l)) {
                    m.cells.push_back(read_cell(*i));
                }
            }
            return Pdu{std::move(m)};
        }
        if (kind == K::successful) {
            F1SetupResponse m;
            m.transaction = need(ies, kTransactionId).get<std::uint8_t>();
            if (const json* n = maybe(ies, kCuName)) {
                m.cu_name = n->get<std::string>();
            }
            if (const json* l = maybe(ies, kCellsToBeActivatedList)) {
                for (const json* i : items(*l)) {
                    m.activate.push_back(read_nr_cgi(i->at("nRCGI")));
                }
            }
            return Pdu{std::move(m)};
        }
        {
            F1SetupFailure m;
            m.transaction = need(ies, kTransactionId).get<std::uint8_t>();
            m.cause = read_cause(need(ies, kCause));
            if (const json* t = maybe(ies, kTimeToWait)) {
                m.time_to_wait = t->get<std::string>();
            }
            return Pdu{std::move(m)};
        }
    case kInitialUlRrcMessageTransfer: {
        InitialUlRrcMessageTransfer m;
        m.du_ue = du_id(ies);
        m.cgi = read_nr_cgi(need(ies, kNrCgi));
        m.c_rnti = need(ies, kCRnti).get<std::uint16_t>();
        m.rrc = read_octets(need(ies, kRrcContainer));
        if (const json* c = maybe(ies, kDuToCuRrcContainer)) {
            m.du_to_cu = read_octets(*c);
        }
        if (const json* t = maybe(ies, kTransactionId)) {
            m.transaction = t->get<std::uint8_t>();
        }
        return Pdu{std::move(m)};
    }
    case kDlRrcMessageTransfer:
        return Pdu{DlRrcMessageTransfer{cu_id(ies), du_id(ies), need(ies, kSrbId).get<std::uint8_t>(),
                                        read_octets(need(ies, kRrcContainer))}};
    case kUlRrcMessageTransfer:
        return Pdu{UlRrcMessageTransfer{cu_id(ies), du_id(ies), need(ies, kSrbId).get<std::uint8_t>(),
                                        read_octets(need(ies, kRrcContainer))}};
    case kUeContextSetup:
        if (kind == K::initiating) {
            UeContextSetupRequest m;
            m.cu_ue = cu_id(ies);
            if (const json* d = maybe(ies, kDuUeId)) {
                m.du_ue = d->get<std::uint32_t>();
            }
            m.spcell = read_nr_cgi(need(ies, kSpCellId));
            m.serv_cell_index = need(ies, kServCellIndex).get<std::uint8_t>();
            const json& info = need(ies, kCuToDuRrcInformation);
            if (info.contains("uE-CapabilityRAT-ContainerList")) {
                m.ue_capability = read_octets(info.at("uE-CapabilityRAT-ContainerList"));
            }
            if (const json* l = maybe(ies, kSrbsToBeSetupList)) {
                m.srbs = read_srbs(*l);
            }
            if (const json* l = maybe(ies, kDrbsToBeSetupList)) {
                m.drbs = read_drbs(*l);
            }
            if (const json* r = maybe(ies, kRrcContainer)) {
                m.rrc = read_octets(*r);
            }
            return Pdu{std::move(m)};
        }
        if (kind == K::successful) {
            UeContextSetupResponse m;
            m.cu_ue = cu_id(ies);
            m.du_ue = du_id(ies);
            m.cell_group = read_octets(need(ies, kDuToCuRrcInformation).at("cellGroupConfig"));
            if (const json* l = maybe(ies, kSrbsSetupList)) {
                for (const json* i : items(*l)) {
                    m.srbs.emplace_back(i->at("sRBID").get<std::uint8_t>(), i->at("lCID").get<std::uint8_t>());
                }
            }
            if (const json* l = maybe(ies, kDrbsSetupList)) {
                m.drbs = read_drbs_setup(*l);
            }
            return Pdu{std::move(m)};
        }
        {
            UeContextSetupFailure m;
            m.cu_ue = cu_id(ies);
            if (const json* d = maybe(ies, kDuUeId)) {
                m.du_ue = d->get<std::uint32_t>();
            }
            m.cause = read_cause(need(ies, kCause));
            return Pdu{std::move(m)};
        }
    case kUeContextModification:
        if (kind == K::initiating) {
            UeContextModificationRequest m;
            m.cu_ue = cu_id(ies);
            m.du_ue = du_id(ies);
            if (const json* r = maybe(ies, kRrcContainer)) {
                m.rrc = read_octets(*r);
            }
            if (const json* l = maybe(ies, kSrbsToBeSetupModList)) {
                m.srbs = read_srbs(*l);
            }
            if (const json* l = maybe(ies, kDrbsToBeSetupModList)) {
                m.drbs = read_drbs(*l);
            }
            if (const json* l = maybe(ies, kDrbsToBeModifiedList)) {
                m.modify_drbs = read_drbs(*l);
            }
            if (const json* l = maybe(ies, kDrbsToBeReleasedList)) {
                for (const json* i : items(*l)) {
                    m.release_drbs.push_back(i->at("dRBID").get<std::uint8_t>());
                }
            }
            return Pdu{std::move(m)};
        }
        if (kind == K::successful) {
            UeContextModificationResponse m;
            m.cu_ue = cu_id(ies);
            m.du_ue = du_id(ies);
            if (const json* d = maybe(ies, kDuToCuRrcInformation)) {
                m.cell_group = read_octets(d->at("cellGroupConfig"));
            }
            if (const json* l = maybe(ies, kDrbsSetupModList)) {
                m.drbs = read_drbs_setup(*l);
            }
            if (const json* l = maybe(ies, kDrbsModifiedList)) {
                m.modified = read_drbs_setup(*l);
            }
            return Pdu{std::move(m)};
        }
        return Pdu{UeContextModificationFailure{cu_id(ies), du_id(ies), read_cause(need(ies, kCause))}};
    case kGnbCuConfigurationUpdate:
        if (kind == K::initiating) {
            GnbCuConfigurationUpdate m;
            m.transaction = need(ies, kTransactionId).get<std::uint8_t>();
            if (const json* l = maybe(ies, kCellsToBeActivatedList)) {
                for (const json* i : items(*l)) {
                    m.activate.push_back(read_nr_cgi(i->at("nRCGI")));
                }
            }
            if (const json* l = maybe(ies, kCellsToBeDeactivatedList)) {
                for (const json* i : items(*l)) {
                    m.deactivate.push_back(read_nr_cgi(i->at("nRCGI")));
                }
            }
            return Pdu{std::move(m)};
        }
        if (kind == K::successful) {
            GnbCuConfigurationUpdateAcknowledge m;
            m.transaction = need(ies, kTransactionId).get<std::uint8_t>();
            if (const json* l = maybe(ies, kCellsFailedToBeActivatedList)) {
                for (const json* i : items(*l)) {
                    m.failed.push_back(CellFailed{read_nr_cgi(i->at("nRCGI")), read_cause(i->at("cause"))});
                }
            }
            return Pdu{std::move(m)};
        }
        {
            GnbCuConfigurationUpdateFailure m;
            m.transaction = need(ies, kTransactionId).get<std::uint8_t>();
            m.cause = read_cause(need(ies, kCause));
            if (const json* t = maybe(ies, kTimeToWait)) {
                m.time_to_wait = t->get<std::string>();
            }
            return Pdu{std::move(m)};
        }
    case kUeContextReleaseRequest:
        return Pdu{UeContextReleaseRequest{cu_id(ies), du_id(ies), read_cause(need(ies, kCause))}};
    case kUeContextRelease:
        if (kind == K::initiating) {
            UeContextReleaseCommand m;
            m.cu_ue = cu_id(ies);
            m.du_ue = du_id(ies);
            m.cause = read_cause(need(ies, kCause));
            if (const json* r = maybe(ies, kRrcContainer)) {
                m.rrc = read_octets(*r);
            }
            if (const json* s = maybe(ies, kSrbId)) {
                m.srb = s->get<std::uint8_t>();
            }
            return Pdu{std::move(m)};
        }
        return Pdu{UeContextReleaseComplete{cu_id(ies), du_id(ies)}};
    case kPaging: {
        Paging m;
        m.ue_identity_index = static_cast<std::uint16_t>(read_bits(need(ies, kUeIdentityIndexValue).at("indexLength10"), 10));
        m.s_tmsi = read_bits(need(ies, kPagingIdentity).at("cNUEPagingIdentity").at("fiveG-S-TMSI"), 48);
        if (const json* d = maybe(ies, kPagingDrx)) {
            m.drx = d->get<std::string>();
        }
        for (const json* i : items(need(ies, kPagingCellList))) {
            m.cells.push_back(read_nr_cgi(i->at("nRCGI")));
        }
        return Pdu{std::move(m)};
    }
    case kErrorIndication: {
        ErrorIndication m;
        m.transaction = need(ies, kTransactionId).get<std::uint8_t>();
        if (const json* c = maybe(ies, kCuUeId)) {
            m.cu_ue = c->get<std::uint32_t>();
        }
        if (const json* d = maybe(ies, kDuUeId)) {
            m.du_ue = d->get<std::uint32_t>();
        }
        if (const json* c = maybe(ies, kCause)) {
            m.cause = read_cause(*c);
        }
        return Pdu{std::move(m)};
    }
    default:
        break;
    }
    return Error{Errc::unsupported, static_cast<std::uint32_t>(code), "F1AP: a procedure outside the P1 set"};
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
            auto [type, value] = arm(e.at("value"));
            (void)type;
            p.ies.emplace(e.at("id").get<int>(), value);
        }
    }
    if (const json* c = maybe(p.ies, kCuUeId); c != nullptr && c->is_number_unsigned()) {
        p.header.cu_ue = c->get<std::uint32_t>();
    }
    if (const json* d = maybe(p.ies, kDuUeId); d != nullptr && d->is_number_unsigned()) {
        p.header.du_ue = d->get<std::uint32_t>();
    }
    return p;
}

} // namespace

Result<Bytes> encode(const Pdu& p) {
    return std::visit([](const auto& m) { return build(m); }, p);
}

Result<Header> peek(ByteView in) {
    auto j = jer::decode(asn_DEF_F1AP_F1AP_PDU, in, asn1::Rules::aper);
    if (!j) {
        return j.error();
    }
    return guarded([&]() -> Result<Header> { return parse(*j).header; });
}

Result<Pdu> decode(ByteView in) {
    auto j = jer::decode(asn_DEF_F1AP_F1AP_PDU, in, asn1::Rules::aper);
    if (!j) {
        return j.error();
    }
    return guarded([&]() -> Result<Pdu> {
        const Parsed p = parse(*j);
        return read(p.header.kind, p.header.procedure, p.ies);
    });
}

} // namespace ksim::f1ap
