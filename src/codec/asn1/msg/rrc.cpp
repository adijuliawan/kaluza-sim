// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "codec/asn1/msg/rrc.hpp"

#include <algorithm>
#include <array>
#include "codec/asn1/asn1.hpp"
#include "codec/asn1/msg/jer.hpp"

extern "C" {
#include "RRC_BCCH-BCH-Message.h"
#include "RRC_BCCH-DL-SCH-Message.h"
#include "RRC_CellGroupConfig.h"
#include "RRC_DL-CCCH-Message.h"
#include "RRC_DL-DCCH-Message.h"
#include "RRC_PCCH-Message.h"
#include "RRC_MIB.h"
#include "RRC_MeasurementTimingConfiguration.h"
#include "RRC_SIB1.h"
#include "RRC_UE-CapabilityRAT-ContainerList.h"
#include "RRC_UE-NR-Capability.h"
#include "RRC_UERadioAccessCapabilityInformation.h"
#include "RRC_UL-CCCH-Message.h"
#include "RRC_UL-DCCH-Message.h"
}

namespace ksim::rrc {

namespace {

using jer::arm;
using jer::bad;
using jer::bits;
using jer::guarded;
using jer::hex;
using jer::json;
using jer::read_bits;
using jer::read_octets;
using jer::unread;

Result<Bytes> to_uper(const asn_TYPE_descriptor_t& td, const json& j) { return jer::encode(td, j, asn1::Rules::uper); }
Result<json> from_uper(const asn_TYPE_descriptor_t& td, ByteView in) { return jer::decode(td, in, asn1::Rules::uper); }

json plmn_json(const Plmn& p) {
    json mcc = json::array();
    json mnc = json::array();
    for (char c : p.mcc) {
        mcc.push_back(c - '0');
    }
    for (char c : p.mnc) {
        mnc.push_back(c - '0');
    }
    return {{"mcc", mcc}, {"mnc", mnc}};
}

bool digits(const std::string& s, std::size_t lo, std::size_t hi) {
    return s.size() >= lo && s.size() <= hi && std::all_of(s.begin(), s.end(), [](char c) { return c >= '0' && c <= '9'; });
}

Plmn read_plmn(const json& j) {
    Plmn p;
    if (j.contains("mcc")) {
        for (const auto& d : j.at("mcc")) {
            p.mcc += static_cast<char>('0' + d.get<int>());
        }
    }
    for (const auto& d : j.at("mnc")) {
        p.mnc += static_cast<char>('0' + d.get<int>());
    }
    return p;
}

/// "ms100" from 100 when 100 is one of `allowed`.
std::optional<std::string> enum_of(const char* prefix, int v, std::initializer_list<int> allowed) {
    if (std::find(allowed.begin(), allowed.end(), v) == allowed.end()) {
        return std::nullopt;
    }
    return std::string(prefix) + std::to_string(v);
}

int enum_value(const json& j) {
    const std::string s = j.get<std::string>();
    const auto at = s.find_first_of("0123456789");
    return at == std::string::npos ? 0 : std::stoi(s.substr(at));
}

constexpr std::initializer_list<int> kT300{100, 200, 300, 400, 600, 1000, 1500, 2000};
constexpr std::initializer_list<int> kT310{0, 50, 100, 200, 500, 1000, 2000};
constexpr std::initializer_list<int> kN310{1, 2, 3, 4, 6, 8, 10, 20};
constexpr std::initializer_list<int> kT311{1000, 3000, 5000, 10000, 15000, 20000, 30000};
constexpr std::initializer_list<int> kN311{1, 2, 3, 4, 5, 6, 8, 10};
constexpr std::initializer_list<int> kTReordering{0,   1,   2,   4,   5,   8,   10,   15,   20,   30,   40,   50,
                                                   60,  80,  100, 120, 140, 160, 180,  200,  220,  240,  260,  280,
                                                   300, 500, 750, 1000, 1250, 1500, 1750, 2000, 2250, 2500, 2750, 3000};

json c1(const char* arm, json body) { return {{"message", {{"c1", {{arm, std::move(body)}}}}}}; }

json transaction(std::uint8_t tid, const char* ext, json ies) {
    return {{"rrc-TransactionIdentifier", tid}, {"criticalExtensions", {{ext, std::move(ies)}}}};
}

bool bad_tid(std::uint8_t tid) { return tid > 3; }

// ---- radio bearers and the cell group ----------------------------------------------------

Result<json> pdcp_json(const PdcpSettings& p) {
    json drb = {{"discardTimer", "infinity"},
                {"pdcp-SN-SizeUL", p.sn18_ul ? "len18bits" : "len12bits"},
                {"pdcp-SN-SizeDL", p.sn18_dl ? "len18bits" : "len12bits"},
                {"headerCompression", {{"notUsed", nullptr}}}};
    if (p.integrity) {
        drb["integrityProtection"] = "enabled";
    }
    if (p.status_report) {
        drb["statusReportRequired"] = "true";
    }
    if (p.out_of_order) {
        drb["outOfOrderDelivery"] = "true";
    }
    json out = {{"drb", drb}};
    if (p.t_reordering_ms) {
        auto t = enum_of("ms", *p.t_reordering_ms, kTReordering);
        if (!t) {
            return bad("RRC: t-Reordering is not one of its values");
        }
        out["t-Reordering"] = *t;
    }
    return out;
}

Result<json> bearers_json(const RadioBearers& b) {
    json out = json::object();
    if (!b.srbs.empty()) {
        json l = json::array();
        for (const SrbAdd& s : b.srbs) {
            if (s.srb_id < 1 || s.srb_id > 3) {
                return bad("RRC: an SRB identity outside 1..3");
            }
            json e = {{"srb-Identity", s.srb_id}};
            if (s.reestablish_pdcp) {
                e["reestablishPDCP"] = "true";
            }
            l.push_back(e);
        }
        out["srb-ToAddModList"] = l;
    }
    if (!b.drbs.empty()) {
        json l = json::array();
        for (const DrbAdd& d : b.drbs) {
            if (d.drb_id < 1 || d.drb_id > 32 || d.qfis.size() > 64 ||
                std::any_of(d.qfis.begin(), d.qfis.end(), [](std::uint8_t q) { return q > 63; })) {
                return bad("RRC: a DRB identity or QFI out of range");
            }
            json sdap = {{"pdu-Session", d.pdu_session},
                         {"sdap-HeaderDL", d.sdap_header_dl ? "present" : "absent"},
                         {"sdap-HeaderUL", d.sdap_header_ul ? "present" : "absent"},
                         {"defaultDRB", d.default_drb}};
            if (!d.qfis.empty()) {
                sdap["mappedQoS-FlowsToAdd"] = d.qfis;
            }
            auto pdcp = pdcp_json(d.pdcp);
            if (!pdcp) {
                return pdcp.error();
            }
            l.push_back({{"cnAssociation", {{"sdap-Config", sdap}}}, {"drb-Identity", d.drb_id}, {"pdcp-Config", *pdcp}});
        }
        out["drb-ToAddModList"] = l;
    }
    if (!b.drb_release.empty()) {
        out["drb-ToReleaseList"] = b.drb_release;
    }
    return out;
}

RadioBearers read_bearers(const json& j) {
    RadioBearers b;
    if (j.contains("srb-ToAddModList")) {
        for (const auto& e : j.at("srb-ToAddModList")) {
            b.srbs.push_back(SrbAdd{e.at("srb-Identity").get<std::uint8_t>(), e.contains("reestablishPDCP")});
        }
    }
    if (j.contains("drb-ToAddModList")) {
        for (const auto& e : j.at("drb-ToAddModList")) {
            DrbAdd d;
            d.drb_id = e.at("drb-Identity").get<std::uint8_t>();
            if (e.contains("cnAssociation") && e.at("cnAssociation").contains("sdap-Config")) {
                const json& s = e.at("cnAssociation").at("sdap-Config");
                d.pdu_session = s.at("pdu-Session").get<std::uint8_t>();
                d.sdap_header_dl = s.at("sdap-HeaderDL").get<std::string>() == "present";
                d.sdap_header_ul = s.at("sdap-HeaderUL").get<std::string>() == "present";
                d.default_drb = s.at("defaultDRB").get<bool>();
                if (s.contains("mappedQoS-FlowsToAdd")) {
                    d.qfis = s.at("mappedQoS-FlowsToAdd").get<std::vector<std::uint8_t>>();
                }
            }
            if (e.contains("pdcp-Config")) {
                const json& p = e.at("pdcp-Config");
                if (p.contains("drb")) {
                    const json& r = p.at("drb");
                    d.pdcp.sn18_ul = r.value("pdcp-SN-SizeUL", "len18bits") == "len18bits";
                    d.pdcp.sn18_dl = r.value("pdcp-SN-SizeDL", "len18bits") == "len18bits";
                    d.pdcp.integrity = r.contains("integrityProtection");
                    d.pdcp.status_report = r.contains("statusReportRequired");
                    d.pdcp.out_of_order = r.contains("outOfOrderDelivery");
                }
                if (p.contains("t-Reordering")) {
                    d.pdcp.t_reordering_ms = enum_value(p.at("t-Reordering"));
                }
            }
            b.drbs.push_back(std::move(d));
        }
    }
    if (j.contains("drb-ToReleaseList")) {
        b.drb_release = j.at("drb-ToReleaseList").get<std::vector<std::uint8_t>>();
    }
    return b;
}

json rlc_config(bool am) {
    if (am) {
        return {{"am",
                 {{"ul-AM-RLC",
                   {{"sn-FieldLength", "size12"},
                    {"t-PollRetransmit", "ms45"},
                    {"pollPDU", "infinity"},
                    {"pollByte", "infinity"},
                    {"maxRetxThreshold", "t8"}}},
                  {"dl-AM-RLC", {{"sn-FieldLength", "size12"}, {"t-Reassembly", "ms35"}, {"t-StatusProhibit", "ms0"}}}}}};
    }
    return {{"um-Bi-Directional",
             {{"ul-UM-RLC", {{"sn-FieldLength", "size12"}}},
              {"dl-UM-RLC", {{"sn-FieldLength", "size12"}, {"t-Reassembly", "ms35"}}}}}};
}

Result<json> cell_group_json(const CellGroup& c) {
    if (c.id > 3) {
        return bad("RRC: a cell group identity outside 0..3");
    }
    json out = {{"cellGroupId", c.id}};
    if (!c.bearers.empty()) {
        json l = json::array();
        for (const RlcBearer& b : c.bearers) {
            if (b.lcid < 1 || b.lcid > 32) {
                return bad("RRC: a logical channel identity outside 1..32");
            }
            l.push_back({{"logicalChannelIdentity", b.lcid},
                         {"servedRadioBearer", {{b.srb ? "srb-Identity" : "drb-Identity", b.rb_id}}},
                         {"rlc-Config", rlc_config(b.am)}});
        }
        out["rlc-BearerToAddModList"] = l;
    }
    if (!c.release_lcids.empty()) {
        out["rlc-BearerToReleaseList"] = c.release_lcids;
    }
    return out;
}

CellGroup read_cell_group(const json& j) {
    CellGroup c;
    c.id = j.at("cellGroupId").get<std::uint8_t>();
    if (j.contains("rlc-BearerToAddModList")) {
        for (const auto& e : j.at("rlc-BearerToAddModList")) {
            RlcBearer b;
            b.lcid = e.at("logicalChannelIdentity").get<std::uint8_t>();
            if (e.contains("servedRadioBearer")) {
                auto [k, v] = arm(e.at("servedRadioBearer"));
                b.srb = k == "srb-Identity";
                b.rb_id = v->get<std::uint8_t>();
            }
            if (e.contains("rlc-Config")) {
                b.am = arm(e.at("rlc-Config")).first == "am";
            }
            c.bearers.push_back(b);
        }
    }
    if (j.contains("rlc-BearerToReleaseList")) {
        c.release_lcids = j.at("rlc-BearerToReleaseList").get<std::vector<std::uint8_t>>();
    }
    return c;
}


constexpr std::array<const char*, 10> kCauses{"emergency",     "highPriorityAccess", "mt-Access",   "mo-Signalling",
                                              "mo-Data",       "mo-VoiceCall",       "mo-VideoCall", "mo-SMS",
                                              "mps-PriorityAccess", "mcs-PriorityAccess"};

} // namespace

const char* cause_name(EstablishmentCause c) noexcept { return kCauses.at(static_cast<std::size_t>(c)); }

// ---- BCCH-BCH -----------------------------------------------------------------------------

namespace {

Result<json> mib_json(const Mib& m) {
    if (m.sfn > 1023 || m.ssb_subcarrier_offset > 15 || m.coreset0 > 15 || m.search_space0 > 15) {
        return bad("RRC: a MIB field out of range");
    }
    return json{{"systemFrameNumber", bits(m.sfn >> 4, 6)},
                {"subCarrierSpacingCommon", m.scs_30_or_120 ? "scs30or120" : "scs15or60"},
                {"ssb-SubcarrierOffset", m.ssb_subcarrier_offset},
                {"dmrs-TypeA-Position", m.dmrs_pos3 ? "pos3" : "pos2"},
                {"pdcch-ConfigSIB1", {{"controlResourceSetZero", m.coreset0}, {"searchSpaceZero", m.search_space0}}},
                {"cellBarred", m.barred ? "barred" : "notBarred"},
                {"intraFreqReselection", m.intra_freq_reselection ? "allowed" : "notAllowed"},
                {"spare", bits(0, 1)}};
}

Mib read_mib(const json& m) {
    Mib out;
    out.sfn = static_cast<std::uint16_t>(read_bits(m.at("systemFrameNumber"), 6) << 4);
    out.scs_30_or_120 = m.at("subCarrierSpacingCommon").get<std::string>() == "scs30or120";
    out.ssb_subcarrier_offset = m.at("ssb-SubcarrierOffset").get<std::uint8_t>();
    out.dmrs_pos3 = m.at("dmrs-TypeA-Position").get<std::string>() == "pos3";
    out.coreset0 = m.at("pdcch-ConfigSIB1").at("controlResourceSetZero").get<std::uint8_t>();
    out.search_space0 = m.at("pdcch-ConfigSIB1").at("searchSpaceZero").get<std::uint8_t>();
    out.barred = m.at("cellBarred").get<std::string>() == "barred";
    out.intra_freq_reselection = m.at("intraFreqReselection").get<std::string>() == "allowed";
    return out;
}

Result<json> sib1_json(const Sib1& s) {
    if (s.plmns.empty() || s.plmns.size() > 12 || s.tac >> 24 != 0 || s.cell_identity >> 36 != 0) {
        return bad("RRC: SIB1 needs 1..12 PLMNs, a 24-bit TAC and a 36-bit cell identity");
    }
    json plmns = json::array();
    for (const Plmn& p : s.plmns) {
        if (!digits(p.mcc, 3, 3) || !digits(p.mnc, 2, 3)) {
            return bad("RRC: a PLMN needs a three-digit MCC and a two- or three-digit MNC");
        }
        plmns.push_back(plmn_json(p));
    }
    json info = {{"plmn-IdentityList", plmns},
                 {"trackingAreaCode", bits(s.tac, 24)},
                 {"cellIdentity", bits(s.cell_identity, 36)},
                 {"cellReservedForOperatorUse", s.reserved_for_operator_use ? "reserved" : "notReserved"}};
    json sib1 = {{"cellAccessRelatedInfo", {{"plmn-IdentityInfoList", json::array({info})}}}};
    if (s.timers) {
        const UeTimers& t = *s.timers;
        auto t300 = enum_of("ms", t.t300, kT300);
        auto t301 = enum_of("ms", t.t301, kT300);
        auto t310 = enum_of("ms", t.t310, kT310);
        auto n310 = enum_of("n", t.n310, kN310);
        auto t311 = enum_of("ms", t.t311, kT311);
        auto n311 = enum_of("n", t.n311, kN311);
        auto t319 = enum_of("ms", t.t319, kT300);
        if (!t300 || !t301 || !t310 || !n310 || !t311 || !n311 || !t319) {
            return bad("RRC: a UE timer or constant is not one of its values");
        }
        sib1["ue-TimersAndConstants"] = {{"t300", *t300}, {"t301", *t301}, {"t310", *t310}, {"n310", *n310},
                                         {"t311", *t311}, {"n311", *n311}, {"t319", *t319}};
    }
    return sib1;
}

Result<Sib1> read_sib1(const json& v) {
    const json& info = v.at("cellAccessRelatedInfo").at("plmn-IdentityInfoList").at(0);
    Sib1 s;
    for (const auto& p : info.at("plmn-IdentityList")) {
        s.plmns.push_back(read_plmn(p));
    }
    if (!s.plmns.empty() && s.plmns.front().mcc.empty()) {
        return unread("RRC: the first PLMN of SIB1 has no MCC");
    }
    for (std::size_t i = 1; i < s.plmns.size(); ++i) {
        if (s.plmns[i].mcc.empty()) {
            s.plmns[i].mcc = s.plmns[i - 1].mcc;   // Cond MCC: the previous entry's
        }
    }
    if (info.contains("trackingAreaCode")) {
        s.tac = static_cast<std::uint32_t>(read_bits(info.at("trackingAreaCode"), 24));
    }
    s.cell_identity = read_bits(info.at("cellIdentity"), 36);
    s.reserved_for_operator_use = info.at("cellReservedForOperatorUse").get<std::string>() == "reserved";
    if (v.contains("ue-TimersAndConstants")) {
        const json& t = v.at("ue-TimersAndConstants");
        s.timers = UeTimers{enum_value(t.at("t300")), enum_value(t.at("t301")), enum_value(t.at("t310")),
                            enum_value(t.at("n310")), enum_value(t.at("t311")), enum_value(t.at("n311")),
                            enum_value(t.at("t319"))};
    }
    return s;
}

} // namespace

Result<Bytes> encode(const Mib& m) {
    auto j = mib_json(m);
    if (!j) {
        return j.error();
    }
    return to_uper(asn_DEF_RRC_BCCH_BCH_Message, {{"message", {{"mib", *j}}}});
}

Result<Mib> decode_mib(ByteView in) {
    auto j = from_uper(asn_DEF_RRC_BCCH_BCH_Message, in);
    if (!j) {
        return j.error();
    }
    return guarded([&]() -> Result<Mib> { return read_mib(j->at("message").at("mib")); });
}

Result<Bytes> mib_ie(const Mib& m) {
    auto j = mib_json(m);
    if (!j) {
        return j.error();
    }
    return to_uper(asn_DEF_RRC_MIB, *j);
}

Result<Mib> decode_mib_ie(ByteView in) {
    auto j = from_uper(asn_DEF_RRC_MIB, in);
    if (!j) {
        return j.error();
    }
    return guarded([&]() -> Result<Mib> { return read_mib(*j); });
}

// ---- BCCH-DL-SCH ---------------------------------------------------------------------------

Result<Bytes> encode(const Sib1& s) {
    auto j = sib1_json(s);
    if (!j) {
        return j.error();
    }
    return to_uper(asn_DEF_RRC_BCCH_DL_SCH_Message, c1("systemInformationBlockType1", *j));
}

Result<Sib1> decode_sib1(ByteView in) {
    auto j = from_uper(asn_DEF_RRC_BCCH_DL_SCH_Message, in);
    if (!j) {
        return j.error();
    }
    return guarded([&]() -> Result<Sib1> {
        auto [k, v] = arm(j->at("message").at("c1"));
        if (k != "systemInformationBlockType1") {
            return Error{Errc::unsupported, 0, "RRC: a BCCH-DL-SCH message other than SIB1"};
        }
        return read_sib1(*v);
    });
}

Result<Bytes> sib1_ie(const Sib1& s) {
    auto j = sib1_json(s);
    if (!j) {
        return j.error();
    }
    return to_uper(asn_DEF_RRC_SIB1, *j);
}

Result<Sib1> decode_sib1_ie(ByteView in) {
    auto j = from_uper(asn_DEF_RRC_SIB1, in);
    if (!j) {
        return j.error();
    }
    return guarded([&]() -> Result<Sib1> { return read_sib1(*j); });
}

// ---- PCCH ------------------------------------------------------------------------------------

Result<Bytes> encode(const Paging& p) {
    if (p.s_tmsis.size() > 32) {
        return bad("RRC: at most 32 paging records");
    }
    json paging = json::object();
    if (!p.s_tmsis.empty()) {
        json l = json::array();
        for (std::uint64_t s : p.s_tmsis) {
            if (s >> 48 != 0) {
                return bad("RRC: a 5G-S-TMSI is 48 bits");
            }
            l.push_back({{"ue-Identity", {{"ng-5G-S-TMSI", bits(s, 48)}}}});
        }
        paging["pagingRecordList"] = l;
    }
    return to_uper(asn_DEF_RRC_PCCH_Message, c1("paging", paging));
}

Result<Paging> decode_paging(ByteView in) {
    auto j = from_uper(asn_DEF_RRC_PCCH_Message, in);
    if (!j) {
        return j.error();
    }
    return guarded([&]() -> Result<Paging> {
        const json& p = j->at("message").at("c1").at("paging");
        Paging out;
        if (p.contains("pagingRecordList")) {
            for (const auto& r : p.at("pagingRecordList")) {
                auto [k, v] = arm(r.at("ue-Identity"));
                if (k == "ng-5G-S-TMSI") {
                    out.s_tmsis.push_back(read_bits(*v, 48));
                }
            }
        }
        return out;
    });
}

// ---- CellGroupConfig ---------------------------------------------------------------------------

Result<Bytes> encode(const CellGroup& c) {
    auto j = cell_group_json(c);
    if (!j) {
        return j.error();
    }
    return to_uper(asn_DEF_RRC_CellGroupConfig, *j);
}

Result<CellGroup> decode_cell_group(ByteView in) {
    auto j = from_uper(asn_DEF_RRC_CellGroupConfig, in);
    if (!j) {
        return j.error();
    }
    return guarded([&]() -> Result<CellGroup> { return read_cell_group(*j); });
}

// ---- UL-CCCH -------------------------------------------------------------------------------------

Result<Bytes> encode(const SetupRequest& r) {
    if (r.identity >> 39 != 0) {
        return bad("RRC: the initial UE identity is 39 bits");
    }
    const json ies = {{"ue-Identity", {{r.s_tmsi_part1 ? "ng-5G-S-TMSI-Part1" : "randomValue", bits(r.identity, 39)}}},
                      {"establishmentCause", cause_name(r.cause)},
                      {"spare", bits(0, 1)}};
    return to_uper(asn_DEF_RRC_UL_CCCH_Message, c1("rrcSetupRequest", {{"rrcSetupRequest", ies}}));
}

Result<SetupRequest> decode_ul_ccch(ByteView in) {
    auto j = from_uper(asn_DEF_RRC_UL_CCCH_Message, in);
    if (!j) {
        return j.error();
    }
    return guarded([&]() -> Result<SetupRequest> {
        auto [k, v] = arm(j->at("message").at("c1"));
        if (k != "rrcSetupRequest") {
            return Error{Errc::unsupported, 0, "RRC: a UL-CCCH message other than RRCSetupRequest"};
        }
        const json& ies = v->at("rrcSetupRequest");
        SetupRequest r;
        auto [ik, iv] = arm(ies.at("ue-Identity"));
        r.s_tmsi_part1 = ik == "ng-5G-S-TMSI-Part1";
        r.identity = read_bits(*iv, 39);
        const std::string cause = ies.at("establishmentCause").get<std::string>();
        const auto it = std::find(kCauses.begin(), kCauses.end(), cause);
        if (it == kCauses.end()) {
            return Error{Errc::unsupported, 0, "RRC: a spare establishment cause"};
        }
        r.cause = static_cast<EstablishmentCause>(it - kCauses.begin());
        return r;
    });
}

// ---- DL-CCCH -------------------------------------------------------------------------------------

Result<Bytes> encode(const Setup& m) {
    if (bad_tid(m.tid)) {
        return bad("RRC: a transaction identifier outside 0..3");
    }
    auto rb = bearers_json(m.bearers);
    auto cg = encode(m.cell_group);
    if (!rb || !cg) {
        return !rb ? rb.error() : cg.error();
    }
    return to_uper(asn_DEF_RRC_DL_CCCH_Message,
                   c1("rrcSetup", transaction(m.tid, "rrcSetup", {{"radioBearerConfig", *rb}, {"masterCellGroup", hex(*cg)}})));
}

Result<Bytes> encode(const Reject& m) {
    json ies = json::object();
    if (m.wait_time_s) {
        if (*m.wait_time_s < 1 || *m.wait_time_s > 16) {
            return bad("RRC: a wait time outside 1..16 s");
        }
        ies["waitTime"] = *m.wait_time_s;
    }
    return to_uper(asn_DEF_RRC_DL_CCCH_Message, c1("rrcReject", {{"criticalExtensions", {{"rrcReject", ies}}}}));
}

Result<DlCcch> decode_dl_ccch(ByteView in) {
    auto j = from_uper(asn_DEF_RRC_DL_CCCH_Message, in);
    if (!j) {
        return j.error();
    }
    return guarded([&]() -> Result<DlCcch> {
        auto [k, v] = arm(j->at("message").at("c1"));
        if (k == "rrcSetup") {
            Setup s;
            s.tid = v->at("rrc-TransactionIdentifier").get<std::uint8_t>();
            const json& ies = v->at("criticalExtensions").at("rrcSetup");
            s.bearers = read_bearers(ies.at("radioBearerConfig"));
            auto cg = decode_cell_group(read_octets(ies.at("masterCellGroup")));
            if (!cg) {
                return cg.error();
            }
            s.cell_group = std::move(*cg);
            return DlCcch{std::move(s)};
        }
        if (k == "rrcReject") {
            Reject r;
            const json& ies = v->at("criticalExtensions").at("rrcReject");
            if (ies.contains("waitTime")) {
                r.wait_time_s = ies.at("waitTime").get<std::uint8_t>();
            }
            return DlCcch{r};
        }
        return Error{Errc::unsupported, 0, "RRC: a DL-CCCH message P1 does not read"};
    });
}

// ---- DL-DCCH -------------------------------------------------------------------------------------

Result<Bytes> encode(const SecurityModeCommand& m) {
    if (bad_tid(m.tid) || m.nea > 3 || m.nia > 3) {
        return bad("RRC: a transaction identifier or algorithm out of range");
    }
    const json alg = {{"cipheringAlgorithm", "nea" + std::to_string(m.nea)},
                      {"integrityProtAlgorithm", "nia" + std::to_string(m.nia)}};
    return to_uper(asn_DEF_RRC_DL_DCCH_Message,
                   c1("securityModeCommand",
                      transaction(m.tid, "securityModeCommand", {{"securityConfigSMC", {{"securityAlgorithmConfig", alg}}}})));
}

Result<Bytes> encode(const Reconfiguration& m) {
    if (bad_tid(m.tid) || m.nas.size() > 29) {
        return bad("RRC: a transaction identifier out of range, or more than maxDRB NAS messages");
    }
    json ies = json::object();
    if (m.bearers) {
        auto rb = bearers_json(*m.bearers);
        if (!rb) {
            return rb.error();
        }
        ies["radioBearerConfig"] = *rb;
    }
    if (m.cell_group || !m.nas.empty()) {
        json ext = json::object();
        if (m.cell_group) {
            auto cg = encode(*m.cell_group);
            if (!cg) {
                return cg.error();
            }
            ext["masterCellGroup"] = hex(*cg);
        }
        if (!m.nas.empty()) {
            json l = json::array();
            for (const Bytes& n : m.nas) {
                l.push_back(hex(n));
            }
            ext["dedicatedNAS-MessageList"] = l;
        }
        ies["nonCriticalExtension"] = ext;
    }
    return to_uper(asn_DEF_RRC_DL_DCCH_Message, c1("rrcReconfiguration", transaction(m.tid, "rrcReconfiguration", ies)));
}

Result<Bytes> encode(const Release& m) {
    if (bad_tid(m.tid)) {
        return bad("RRC: a transaction identifier outside 0..3");
    }
    return to_uper(asn_DEF_RRC_DL_DCCH_Message, c1("rrcRelease", transaction(m.tid, "rrcRelease", json::object())));
}

Result<Bytes> encode(const CapabilityEnquiry& m) {
    if (bad_tid(m.tid)) {
        return bad("RRC: a transaction identifier outside 0..3");
    }
    return to_uper(asn_DEF_RRC_DL_DCCH_Message,
                   c1("ueCapabilityEnquiry",
                      transaction(m.tid, "ueCapabilityEnquiry",
                                  {{"ue-CapabilityRAT-RequestList", json::array({{{"rat-Type", "nr"}}})}})));
}

Result<Bytes> encode(const DlInformationTransfer& m) {
    if (bad_tid(m.tid) || m.nas.empty()) {
        return bad("RRC: a transaction identifier out of range, or no NAS message");
    }
    return to_uper(asn_DEF_RRC_DL_DCCH_Message,
                   c1("dlInformationTransfer",
                      transaction(m.tid, "dlInformationTransfer", {{"dedicatedNAS-Message", hex(m.nas)}})));
}

Result<DlDcch> decode_dl_dcch(ByteView in) {
    auto j = from_uper(asn_DEF_RRC_DL_DCCH_Message, in);
    if (!j) {
        return j.error();
    }
    return guarded([&]() -> Result<DlDcch> {
        auto [k, v] = arm(j->at("message").at("c1"));
        const auto tid = v->at("rrc-TransactionIdentifier").get<std::uint8_t>();
        auto [ck, ies] = arm(v->at("criticalExtensions"));
        if (k == "securityModeCommand" && ck == k) {
            const json& alg = ies->at("securityConfigSMC").at("securityAlgorithmConfig");
            SecurityModeCommand s;
            s.tid = tid;
            s.nea = static_cast<std::uint8_t>(enum_value(alg.at("cipheringAlgorithm")));
            s.nia = alg.contains("integrityProtAlgorithm")
                        ? static_cast<std::uint8_t>(enum_value(alg.at("integrityProtAlgorithm")))
                        : std::uint8_t{0};
            return DlDcch{s};
        }
        if (k == "rrcReconfiguration" && ck == k) {
            Reconfiguration r;
            r.tid = tid;
            if (ies->contains("radioBearerConfig")) {
                r.bearers = read_bearers(ies->at("radioBearerConfig"));
            }
            if (ies->contains("nonCriticalExtension")) {
                const json& ext = ies->at("nonCriticalExtension");
                if (ext.contains("masterCellGroup")) {
                    auto cg = decode_cell_group(read_octets(ext.at("masterCellGroup")));
                    if (!cg) {
                        return cg.error();
                    }
                    r.cell_group = std::move(*cg);
                }
                if (ext.contains("dedicatedNAS-MessageList")) {
                    for (const auto& n : ext.at("dedicatedNAS-MessageList")) {
                        r.nas.push_back(read_octets(n));
                    }
                }
            }
            return DlDcch{std::move(r)};
        }
        if (k == "rrcRelease" && ck == k) {
            return DlDcch{Release{tid}};
        }
        if (k == "ueCapabilityEnquiry" && ck == k) {
            return DlDcch{CapabilityEnquiry{tid}};
        }
        if (k == "dlInformationTransfer" && ck == k) {
            DlInformationTransfer d;
            d.tid = tid;
            if (ies->contains("dedicatedNAS-Message")) {
                d.nas = read_octets(ies->at("dedicatedNAS-Message"));
            }
            return DlDcch{std::move(d)};
        }
        return Error{Errc::unsupported, 0, "RRC: a DL-DCCH message P1 does not read"};
    });
}

// ---- UL-DCCH -------------------------------------------------------------------------------------

Result<Bytes> encode(const SetupComplete& m) {
    if (bad_tid(m.tid) || m.selected_plmn < 1 || m.selected_plmn > 12 || m.nas.empty() ||
        (m.s_tmsi_part2 && *m.s_tmsi_part2 >> 9 != 0)) {
        return bad("RRC: an RRCSetupComplete field out of range");
    }
    json ies = {{"selectedPLMN-Identity", m.selected_plmn}, {"dedicatedNAS-Message", hex(m.nas)}};
    if (m.s_tmsi_part2) {
        ies["ng-5G-S-TMSI-Value"] = {{"ng-5G-S-TMSI-Part2", bits(*m.s_tmsi_part2, 9)}};
    }
    return to_uper(asn_DEF_RRC_UL_DCCH_Message, c1("rrcSetupComplete", transaction(m.tid, "rrcSetupComplete", ies)));
}

Result<Bytes> encode(const SecurityModeComplete& m) {
    if (bad_tid(m.tid)) {
        return bad("RRC: a transaction identifier outside 0..3");
    }
    return to_uper(asn_DEF_RRC_UL_DCCH_Message,
                   c1("securityModeComplete", transaction(m.tid, "securityModeComplete", json::object())));
}

Result<Bytes> encode(const SecurityModeFailure& m) {
    if (bad_tid(m.tid)) {
        return bad("RRC: a transaction identifier outside 0..3");
    }
    return to_uper(asn_DEF_RRC_UL_DCCH_Message,
                   c1("securityModeFailure", transaction(m.tid, "securityModeFailure", json::object())));
}

Result<Bytes> encode(const ReconfigurationComplete& m) {
    if (bad_tid(m.tid)) {
        return bad("RRC: a transaction identifier outside 0..3");
    }
    return to_uper(asn_DEF_RRC_UL_DCCH_Message,
                   c1("rrcReconfigurationComplete", transaction(m.tid, "rrcReconfigurationComplete", json::object())));
}

Result<Bytes> encode(const CapabilityInformation& m) {
    if (bad_tid(m.tid) || m.nr_capability.empty()) {
        return bad("RRC: a transaction identifier out of range, or no capability");
    }
    const json list = json::array({{{"rat-Type", "nr"}, {"ue-CapabilityRAT-Container", hex(m.nr_capability)}}});
    return to_uper(asn_DEF_RRC_UL_DCCH_Message,
                   c1("ueCapabilityInformation",
                      transaction(m.tid, "ueCapabilityInformation", {{"ue-CapabilityRAT-ContainerList", list}})));
}

Result<Bytes> encode(const UlInformationTransfer& m) {
    if (m.nas.empty()) {
        return bad("RRC: no NAS message");
    }
    return to_uper(asn_DEF_RRC_UL_DCCH_Message,
                   c1("ulInformationTransfer",
                      {{"criticalExtensions", {{"ulInformationTransfer", {{"dedicatedNAS-Message", hex(m.nas)}}}}}}));
}

Result<UlDcch> decode_ul_dcch(ByteView in) {
    auto j = from_uper(asn_DEF_RRC_UL_DCCH_Message, in);
    if (!j) {
        return j.error();
    }
    return guarded([&]() -> Result<UlDcch> {
        auto [k, v] = arm(j->at("message").at("c1"));
        auto [ck, ies] = arm(v->at("criticalExtensions"));
        if (k == "ulInformationTransfer" && ck == k) {
            UlInformationTransfer u;
            if (ies->contains("dedicatedNAS-Message")) {
                u.nas = read_octets(ies->at("dedicatedNAS-Message"));
            }
            return UlDcch{std::move(u)};
        }
        const auto tid = v->at("rrc-TransactionIdentifier").get<std::uint8_t>();
        if (k == "rrcSetupComplete" && ck == k) {
            SetupComplete s;
            s.tid = tid;
            s.selected_plmn = ies->at("selectedPLMN-Identity").get<std::uint8_t>();
            s.nas = read_octets(ies->at("dedicatedNAS-Message"));
            if (ies->contains("ng-5G-S-TMSI-Value")) {
                auto [tk, tv] = arm(ies->at("ng-5G-S-TMSI-Value"));
                if (tk == "ng-5G-S-TMSI-Part2") {
                    s.s_tmsi_part2 = static_cast<std::uint16_t>(read_bits(*tv, 9));
                }
            }
            return UlDcch{std::move(s)};
        }
        if (k == "securityModeComplete" && ck == k) {
            return UlDcch{SecurityModeComplete{tid}};
        }
        if (k == "securityModeFailure" && ck == k) {
            return UlDcch{SecurityModeFailure{tid}};
        }
        if (k == "rrcReconfigurationComplete" && ck == k) {
            return UlDcch{ReconfigurationComplete{tid}};
        }
        if (k == "ueCapabilityInformation" && ck == k) {
            CapabilityInformation c;
            c.tid = tid;
            if (ies->contains("ue-CapabilityRAT-ContainerList")) {
                for (const auto& e : ies->at("ue-CapabilityRAT-ContainerList")) {
                    if (e.at("rat-Type").get<std::string>() == "nr") {
                        c.nr_capability = read_octets(e.at("ue-CapabilityRAT-Container"));
                    }
                }
            }
            return UlDcch{std::move(c)};
        }
        return Error{Errc::unsupported, 0, "RRC: a UL-DCCH message P1 does not read"};
    });
}

// ---- capabilities and JER -----------------------------------------------------------------------

Result<Bytes> generic_nr_capability() {
    json rohc = json::object();
    for (const char* p : {"profile0x0000", "profile0x0001", "profile0x0002", "profile0x0003", "profile0x0004",
                          "profile0x0006", "profile0x0101", "profile0x0102", "profile0x0103", "profile0x0104"}) {
        rohc[p] = false;
    }
    const json cap = {{"accessStratumRelease", "rel15"},
                      {"pdcp-Parameters", {{"supportedROHC-Profiles", rohc}, {"maxNumberROHC-ContextSessions", "cs2"}}},
                      {"phy-Parameters", json::object()},
                      {"rf-Parameters", {{"supportedBandListNR", json::array({{{"bandNR", 78}}})}}}};
    return to_uper(asn_DEF_RRC_UE_NR_Capability, cap);
}

Result<Bytes> measurement_timing_configuration() {
    return to_uper(asn_DEF_RRC_MeasurementTimingConfiguration,
                   {{"criticalExtensions", {{"c1", {{"measTimingConf", json::object()}}}}}});
}

Result<Bytes> radio_access_capability(const Bytes& nr_capability) {
    if (nr_capability.empty()) {
        return bad("RRC: no NR capability");
    }
    auto list = to_uper(asn_DEF_RRC_UE_CapabilityRAT_ContainerList,
                        json::array({{{"rat-Type", "nr"}, {"ue-CapabilityRAT-Container", hex(nr_capability)}}}));
    if (!list) {
        return list.error();
    }
    return to_uper(asn_DEF_RRC_UERadioAccessCapabilityInformation,
                   {{"criticalExtensions",
                     {{"c1", {{"ueRadioAccessCapabilityInformation", {{"ue-RadioAccessCapabilityInfo", hex(*list)}}}}}}}});
}

Result<Bytes> nr_capability_of(ByteView radio_access_capability) {
    auto j = from_uper(asn_DEF_RRC_UERadioAccessCapabilityInformation, radio_access_capability);
    if (!j) {
        return j.error();
    }
    return guarded([&]() -> Result<Bytes> {
        const Bytes inner = read_octets(
            j->at("criticalExtensions").at("c1").at("ueRadioAccessCapabilityInformation").at("ue-RadioAccessCapabilityInfo"));
        auto list = from_uper(asn_DEF_RRC_UE_CapabilityRAT_ContainerList, inner);
        if (!list) {
            return list.error();
        }
        for (const auto& e : *list) {
            if (e.at("rat-Type").get<std::string>() == "nr") {
                return read_octets(e.at("ue-CapabilityRAT-Container"));
            }
        }
        return Error{Errc::invalid_argument, 0, "RRC: no NR capability in the container list"};
    });
}

Result<std::string> to_jer(std::string_view channel, ByteView in) {
    const asn_TYPE_descriptor_t* td = nullptr;
    if (channel == "BCCH-BCH") {
        td = &asn_DEF_RRC_BCCH_BCH_Message;
    } else if (channel == "BCCH-DL-SCH") {
        td = &asn_DEF_RRC_BCCH_DL_SCH_Message;
    } else if (channel == "PCCH") {
        td = &asn_DEF_RRC_PCCH_Message;
    } else if (channel == "UL-CCCH") {
        td = &asn_DEF_RRC_UL_CCCH_Message;
    } else if (channel == "DL-CCCH") {
        td = &asn_DEF_RRC_DL_CCCH_Message;
    } else if (channel == "DL-DCCH") {
        td = &asn_DEF_RRC_DL_DCCH_Message;
    } else if (channel == "UL-DCCH") {
        td = &asn_DEF_RRC_UL_DCCH_Message;
    } else if (channel == "CellGroupConfig") {
        td = &asn_DEF_RRC_CellGroupConfig;
    } else if (channel == "UE-NR-Capability") {
        td = &asn_DEF_RRC_UE_NR_Capability;
    } else {
        return bad("RRC: an unknown channel");
    }
    auto v = asn1::decode(*td, asn1::Rules::uper, in);
    if (!v) {
        return v.error();
    }
    return asn1::to_jer(v.value());
}

} // namespace ksim::rrc
