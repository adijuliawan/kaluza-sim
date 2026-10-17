// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "codec/asn1/msg/xnap.hpp"

#include <algorithm>
#include <map>

#include "codec/asn1/msg/jer.hpp"

extern "C" {
#include "XNAP_XnAP-PDU.h"
}

namespace ksim::xnap {

namespace {

using jer::arm;
using jer::bad;
using jer::bits;
using jer::guarded;
using jer::hex;
using jer::json;
using jer::read_bits;
using jer::read_octets;
using jer::var_bits;

// Procedure codes (XnAP-Constants).
constexpr int kXnSetup = 17;
constexpr int kConfigurationUpdate = 18;
constexpr int kReset = 20;
constexpr int kErrorIndication = 21;

// Protocol IE identifiers.
constexpr int kAmfRegionInformation = 4;
constexpr int kCause = 7;
constexpr int kInitiatingNodeChoice = 9;
constexpr int kGlobalNgRanNodeId = 14;
constexpr int kServedCellsNr = 19;
constexpr int kNewUeId = 27;
constexpr int kOldUeId = 29;
constexpr int kResetRequestTypeInfo = 56;
constexpr int kResetResponseTypeInfo = 57;
constexpr int kRespondingNodeTypeConfigUpdateAck = 58;
constexpr int kServedCellsToUpdateNr = 68;
constexpr int kTaiSupportList = 75;
constexpr int kTimeToWait = 76;

json ie(int id, const char* criticality, const char* type, json value) {
    return {{"id", id}, {"criticality", criticality}, {"value", {{type, std::move(value)}}}};
}

json pdu(const char* kind, int code, const char* criticality, const char* message, json ies) {
    return {{kind,
             {{"procedureCode", code},
              {"criticality", criticality},
              {"value", {{message, {{"protocolIEs", std::move(ies)}}}}}}}};
}

Result<Bytes> per(const json& j) { return jer::encode(asn_DEF_XNAP_XnAP_PDU, j, asn1::Rules::aper); }

PlmnId read_plmn(const json& j) {
    const Bytes b = read_octets(j);
    if (b.size() != 3) {
        throw json::other_error::create(501, "PLMN identity is three octets", &j);
    }
    return {b[0], b[1], b[2]};
}

Bytes octets(std::uint64_t v, unsigned n) {
    Bytes b(n);
    for (unsigned i = 0; i < n; ++i) {
        b[i] = static_cast<std::uint8_t>(v >> (8 * (n - 1 - i)));
    }
    return b;
}

std::uint64_t number(const json& j) {
    std::uint64_t v = 0;
    for (std::uint8_t c : read_octets(j)) {
        v = (v << 8) | c;
    }
    return v;
}

json gnb_json(const GnbId& g) {
    return {{"gNB", {{"plmn-id", hex(g.plmn)}, {"gnb-id", {{"gnb-ID", var_bits(g.value, g.bits)}}}}}};
}

GnbId read_gnb(const json& j) {
    auto [k, v] = arm(j);
    if (k != "gNB") {
        throw jer::NotP1("an ng-eNB as the Xn peer");
    }
    GnbId g;
    g.plmn = read_plmn(v->at("plmn-id"));
    auto [ck, cv] = arm(v->at("gnb-id"));
    (void)ck;
    g.bits = static_cast<std::uint8_t>(jer::bits_length(*cv));
    g.value = static_cast<std::uint32_t>(read_bits(*cv));
    return g;
}

json snssai_json(const Snssai& s) {
    json j = {{"sst", hex(Bytes{s.sst})}};
    if (s.sd) {
        j["sd"] = hex(octets(*s.sd, 3));
    }
    return j;
}

Snssai read_snssai(const json& j) {
    Snssai s;
    s.sst = read_octets(j.at("sst")).at(0);
    if (j.contains("sd")) {
        s.sd = static_cast<std::uint32_t>(number(j.at("sd")));
    }
    return s;
}

json tais_json(const std::vector<TaiSupport>& tais) {
    json l = json::array();
    for (const auto& t : tais) {
        json plmns = json::array();
        for (const auto& [p, slices] : t.plmns) {
            json sl = json::array();
            for (const auto& s : slices) {
                sl.push_back(snssai_json(s));
            }
            plmns.push_back({{"plmn-id", hex(p)}, {"tAISliceSupport-List", sl}});
        }
        l.push_back({{"tac", hex(octets(t.tac, 3))}, {"broadcastPLMNs", plmns}});
    }
    return l;
}

std::vector<TaiSupport> read_tais(const json& l) {
    std::vector<TaiSupport> out;
    for (const auto& t : l) {
        TaiSupport s;
        s.tac = static_cast<std::uint32_t>(number(t.at("tac")));
        for (const auto& p : t.at("broadcastPLMNs")) {
            std::vector<Snssai> slices;
            for (const auto& x : p.at("tAISliceSupport-List")) {
                slices.push_back(read_snssai(x));
            }
            s.plmns.emplace_back(read_plmn(p.at("plmn-id")), std::move(slices));
        }
        out.push_back(std::move(s));
    }
    return out;
}

json cgi_json(const PlmnId& p, std::uint64_t nci) { return {{"plmn-id", hex(p)}, {"nr-CI", bits(nci, 36)}}; }

json cell_json(const ServedCell& c) {
    json info = {{"nrPCI", c.pci},
                 {"cellID", cgi_json(c.plmn, c.nci)},
                 {"tac", hex(octets(c.tac, 3))},
                 {"broadcastPLMN", json::array({hex(c.plmn)})},
                 {"nrModeInfo",
                  {{"tdd",
                    {{"nrFrequencyInfo", {{"nrARFCN", c.arfcn}, {"frequencyBand-List", json::array({{{"nr-frequency-band", c.band}}})}}},
                     {"nrTransmissonBandwidth", {{"nRSCS", c.scs}, {"nRNRB", c.nrb}}}}}}},
                 {"measurementTimingConfiguration", hex(c.meas_timing)},
                 {"connectivitySupport", {{"eNDC-Support", "not-supported"}}}};
    return {{"served-cell-info-NR", std::move(info)}};
}

ServedCell read_cell(const json& item) {
    const json& i = item.at("served-cell-info-NR");
    ServedCell c;
    c.pci = i.at("nrPCI").get<std::uint16_t>();
    c.plmn = read_plmn(i.at("cellID").at("plmn-id"));
    c.nci = read_bits(i.at("cellID").at("nr-CI"), 36);
    c.tac = static_cast<std::uint32_t>(number(i.at("tac")));
    auto [mode, mi] = arm(i.at("nrModeInfo"));
    if (mode != "tdd") {
        throw jer::NotP1("an FDD served cell");
    }
    c.arfcn = mi->at("nrFrequencyInfo").at("nrARFCN").get<std::uint32_t>();
    c.band = mi->at("nrFrequencyInfo").at("frequencyBand-List").at(0).at("nr-frequency-band").get<std::uint16_t>();
    c.scs = mi->at("nrTransmissonBandwidth").at("nRSCS").get<std::string>();
    c.nrb = mi->at("nrTransmissonBandwidth").at("nRNRB").get<std::string>();
    c.meas_timing = read_octets(i.at("measurementTimingConfiguration"));
    return c;
}

json cells_json(const std::vector<ServedCell>& cells) {
    json l = json::array();
    for (const auto& c : cells) {
        l.push_back(cell_json(c));
    }
    return l;
}

std::vector<ServedCell> read_cells(const json& l) {
    std::vector<ServedCell> out;
    for (const auto& c : l) {
        out.push_back(read_cell(c));
    }
    return out;
}

json cause(const Cause& c) { return {{c.group, c.value}}; }
Cause read_cause(const json& j) {
    auto [g, v] = arm(j);
    return {g, v->get<std::string>()};
}

bool cells_ok(const std::vector<ServedCell>& cells) {
    return std::all_of(cells.begin(), cells.end(), [](const ServedCell& c) {
        return c.pci <= 1007 && c.nci >> 36 == 0 && c.tac >> 24 == 0 && c.band >= 1 && c.band <= 1024 && !c.meas_timing.empty();
    });
}

bool gnb_ok(const GnbId& g) { return g.bits >= 22 && g.bits <= 32 && (g.bits == 32 || g.value >> g.bits == 0); }

// ---- builders ---------------------------------------------------------------------------

Result<Bytes> build(const XnSetupRequest& m) {
    if (!gnb_ok(m.gnb) || m.tais.empty() || m.amf_regions.empty() || !cells_ok(m.cells)) {
        return bad("XnAP: a gNB ID of 22..32 bits, a TAI and an AMF region, and served cells in range");
    }
    json regions = json::array();
    for (const auto& [p, region] : m.amf_regions) {
        regions.push_back({{"plmn-ID", hex(p)}, {"amf-region-id", bits(region, 8)}});
    }
    json ies = json::array({ie(kGlobalNgRanNodeId, "reject", "GlobalNG-RANNode-ID", gnb_json(m.gnb)),
                            ie(kTaiSupportList, "reject", "TAISupport-List", tais_json(m.tais)),
                            ie(kAmfRegionInformation, "reject", "AMF-Region-Information", regions)});
    if (!m.cells.empty()) {
        ies.push_back(ie(kServedCellsNr, "reject", "ServedCells-NR", cells_json(m.cells)));
    }
    return per(pdu("initiatingMessage", kXnSetup, "reject", "XnSetupRequest", ies));
}

Result<Bytes> build(const XnSetupResponse& m) {
    if (!gnb_ok(m.gnb) || m.tais.empty() || !cells_ok(m.cells)) {
        return bad("XnAP: a gNB ID of 22..32 bits, a TAI, and served cells in range");
    }
    json ies = json::array({ie(kGlobalNgRanNodeId, "reject", "GlobalNG-RANNode-ID", gnb_json(m.gnb)),
                            ie(kTaiSupportList, "reject", "TAISupport-List", tais_json(m.tais))});
    if (!m.cells.empty()) {
        ies.push_back(ie(kServedCellsNr, "reject", "ServedCells-NR", cells_json(m.cells)));
    }
    return per(pdu("successfulOutcome", kXnSetup, "reject", "XnSetupResponse", ies));
}

Result<Bytes> build(const XnSetupFailure& m) {
    json ies = json::array({ie(kCause, "ignore", "Cause", cause(m.cause))});
    if (m.time_to_wait) {
        ies.push_back(ie(kTimeToWait, "ignore", "TimeToWait", *m.time_to_wait));
    }
    return per(pdu("unsuccessfulOutcome", kXnSetup, "reject", "XnSetupFailure", ies));
}

Result<Bytes> build(const NgRanNodeConfigurationUpdate& m) {
    if (!cells_ok(m.add)) {
        return bad("XnAP: a served cell out of range");
    }
    json update = json::object();
    if (!m.add.empty()) {
        update["served-Cells-ToAdd-NR"] = cells_json(m.add);
    }
    if (!m.remove.empty()) {
        json l = json::array();
        for (const auto& [p, nci] : m.remove) {
            l.push_back(cgi_json(p, nci));
        }
        update["served-Cells-ToDelete-NR"] = l;
    }
    json gnb = json::array();
    if (!update.empty()) {
        gnb.push_back(ie(kServedCellsToUpdateNr, "ignore", "ServedCellsToUpdate-NR", update));
    }
    json ies = json::array({ie(kInitiatingNodeChoice, "ignore", "ConfigurationUpdateInitiatingNodeChoice", {{"gNB", gnb}})});
    return per(pdu("initiatingMessage", kConfigurationUpdate, "reject", "NGRANNodeConfigurationUpdate", ies));
}

Result<Bytes> build(const NgRanNodeConfigurationUpdateAcknowledge& m) {
    if (!cells_ok(m.cells)) {
        return bad("XnAP: a served cell out of range");
    }
    json ack = json::object();
    if (!m.cells.empty()) {
        ack["served-NR-Cells"] = cells_json(m.cells);
    }
    json ies = json::array({ie(kRespondingNodeTypeConfigUpdateAck, "ignore", "RespondingNodeTypeConfigUpdateAck", {{"gNB", ack}})});
    return per(pdu("successfulOutcome", kConfigurationUpdate, "reject", "NGRANNodeConfigurationUpdateAcknowledge", ies));
}

Result<Bytes> build(const NgRanNodeConfigurationUpdateFailure& m) {
    json ies = json::array({ie(kCause, "ignore", "Cause", cause(m.cause))});
    return per(pdu("unsuccessfulOutcome", kConfigurationUpdate, "reject", "NGRANNodeConfigurationUpdateFailure", ies));
}

Result<Bytes> build(const ResetRequest& m) {
    json ies = json::array({ie(kResetRequestTypeInfo, "reject", "ResetRequestTypeInfo", {{"fullReset", json::object()}}),
                            ie(kCause, "ignore", "Cause", cause(m.cause))});
    return per(pdu("initiatingMessage", kReset, "reject", "ResetRequest", ies));
}

Result<Bytes> build(const ResetResponse&) {
    json ies = json::array({ie(kResetResponseTypeInfo, "reject", "ResetResponseTypeInfo", {{"fullReset", json::object()}})});
    return per(pdu("successfulOutcome", kReset, "reject", "ResetResponse", ies));
}

Result<Bytes> build(const ErrorIndication& m) {
    json ies = json::array();
    if (m.old_id) {
        ies.push_back(ie(kOldUeId, "ignore", "NG-RANnodeUEXnAPID", *m.old_id));
    }
    if (m.new_id) {
        ies.push_back(ie(kNewUeId, "ignore", "NG-RANnodeUEXnAPID", *m.new_id));
    }
    if (m.cause) {
        ies.push_back(ie(kCause, "ignore", "Cause", cause(*m.cause)));
    }
    return per(pdu("initiatingMessage", kErrorIndication, "ignore", "ErrorIndication", ies));
}

// ---- readers -----------------------------------------------------------------------------

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

Result<Pdu> read(const std::string& kind, int code, const Ies& ies) {
    switch (code) {
    case kXnSetup:
        if (kind == "initiatingMessage") {
            XnSetupRequest m;
            m.gnb = read_gnb(need(ies, kGlobalNgRanNodeId));
            m.tais = read_tais(need(ies, kTaiSupportList));
            for (const auto& r : need(ies, kAmfRegionInformation)) {
                m.amf_regions.emplace_back(read_plmn(r.at("plmn-ID")), static_cast<std::uint8_t>(read_bits(r.at("amf-region-id"), 8)));
            }
            if (const json* c = maybe(ies, kServedCellsNr)) {
                m.cells = read_cells(*c);
            }
            return Pdu{std::move(m)};
        }
        if (kind == "successfulOutcome") {
            XnSetupResponse m;
            m.gnb = read_gnb(need(ies, kGlobalNgRanNodeId));
            m.tais = read_tais(need(ies, kTaiSupportList));
            if (const json* c = maybe(ies, kServedCellsNr)) {
                m.cells = read_cells(*c);
            }
            return Pdu{std::move(m)};
        }
        {
            XnSetupFailure m;
            m.cause = read_cause(need(ies, kCause));
            if (const json* t = maybe(ies, kTimeToWait)) {
                m.time_to_wait = t->get<std::string>();
            }
            return Pdu{std::move(m)};
        }
    case kConfigurationUpdate:
        if (kind == "initiatingMessage") {
            NgRanNodeConfigurationUpdate m;
            auto [k, v] = arm(need(ies, kInitiatingNodeChoice));
            if (k != "gNB") {
                throw jer::NotP1("an ng-eNB's configuration update");
            }
            const Ies g = ies_of(*v);
            if (const json* u = maybe(g, kServedCellsToUpdateNr)) {
                if (u->contains("served-Cells-ToAdd-NR")) {
                    m.add = read_cells(u->at("served-Cells-ToAdd-NR"));
                }
                if (u->contains("served-Cells-ToDelete-NR")) {
                    for (const auto& c : u->at("served-Cells-ToDelete-NR")) {
                        m.remove.emplace_back(read_plmn(c.at("plmn-id")), read_bits(c.at("nr-CI"), 36));
                    }
                }
            }
            return Pdu{std::move(m)};
        }
        if (kind == "successfulOutcome") {
            NgRanNodeConfigurationUpdateAcknowledge m;
            auto [k, v] = arm(need(ies, kRespondingNodeTypeConfigUpdateAck));
            if (k == "gNB" && v->contains("served-NR-Cells")) {
                m.cells = read_cells(v->at("served-NR-Cells"));
            }
            return Pdu{std::move(m)};
        }
        return Pdu{NgRanNodeConfigurationUpdateFailure{read_cause(need(ies, kCause))}};
    case kReset:
        if (kind == "initiatingMessage") {
            if (arm(need(ies, kResetRequestTypeInfo)).first != "fullReset") {
                throw jer::NotP1("a partial Xn Reset");
            }
            return Pdu{ResetRequest{read_cause(need(ies, kCause))}};
        }
        return Pdu{ResetResponse{}};
    case kErrorIndication: {
        ErrorIndication m;
        if (const json* o = maybe(ies, kOldUeId)) {
            m.old_id = o->get<std::uint32_t>();
        }
        if (const json* n = maybe(ies, kNewUeId)) {
            m.new_id = n->get<std::uint32_t>();
        }
        if (const json* c = maybe(ies, kCause)) {
            m.cause = read_cause(*c);
        }
        return Pdu{std::move(m)};
    }
    default:
        throw jer::NotP1("an XnAP procedure outside the R1 set");
    }
}

void zero_keys(json& j, unsigned& n) {
    if (j.is_object()) {
        for (auto& [k, v] : j.items()) {
            if (k == "key-NG-RAN-Star" && v.is_string()) {
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

Result<Bytes> encode(const Pdu& p) {
    return std::visit([](const auto& m) { return build(m); }, p);
}

Result<Pdu> decode(ByteView in) {
    auto j = jer::decode(asn_DEF_XNAP_XnAP_PDU, in, asn1::Rules::aper);
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
    auto j = jer::decode(asn_DEF_XNAP_XnAP_PDU, in, asn1::Rules::aper);
    if (!j) {
        return j.error();
    }
    Redacted out;
    zero_keys(*j, out.keys);
    auto wire = jer::encode(asn_DEF_XNAP_XnAP_PDU, std::move(*j), asn1::Rules::aper);
    if (!wire) {
        return wire.error();
    }
    out.pdu = std::move(*wire);
    return out;
}

} // namespace ksim::xnap
