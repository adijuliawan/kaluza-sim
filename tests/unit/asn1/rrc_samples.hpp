// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// One sample of every RRC builder (P1 N6), shared by the round-trip tests and
// msg_builders_dump, whose output the oracle checks with tshark and pycrate.

#pragma once

#include <string>
#include <vector>

#include "codec/asn1/msg/rrc.hpp"

namespace ksim::rrc::samples {

struct Sample {
    std::string channel;   // as rrc::to_jer names it
    std::string name;
    Result<Bytes> bytes;
};

inline CellGroup cell_group() {
    CellGroup c;
    c.bearers.push_back(RlcBearer{1, true, 1, true});
    c.bearers.push_back(RlcBearer{4, false, 1, true});
    c.bearers.push_back(RlcBearer{5, false, 2, false});
    return c;
}

inline RadioBearers bearers() {
    RadioBearers b;
    b.srbs.push_back(SrbAdd{2, false});
    DrbAdd d;
    d.drb_id = 1;
    d.pdu_session = 1;
    d.sdap_header_dl = true;
    d.sdap_header_ul = true;
    d.qfis = {1, 9};
    d.pdcp.integrity = true;
    d.pdcp.status_report = true;
    d.pdcp.t_reordering_ms = 100;
    b.drbs.push_back(d);
    return b;
}

inline std::vector<Sample> all() {
    std::vector<Sample> s;
    s.push_back({"BCCH-BCH", "MIB", encode(Mib{512, true, 0, false, 12, 0, false, true})});
    Sib1 sib1;
    sib1.plmns = {Plmn{"001", "01"}, Plmn{"999", "70"}};
    sib1.tac = 1;
    sib1.cell_identity = 0x1A0000001;
    sib1.timers = UeTimers{};
    s.push_back({"BCCH-DL-SCH", "SIB1", encode(sib1)});
    s.push_back({"PCCH", "Paging", encode(Paging{{0x0CA040000001ULL, 0x0CA0400000FFULL}})});
    s.push_back({"UL-CCCH", "RRCSetupRequest", encode(SetupRequest{false, 0x123456789AULL >> 1, EstablishmentCause::mo_signalling})});
    s.push_back({"UL-CCCH", "RRCSetupRequest.s-tmsi-part1", encode(SetupRequest{true, 0x40000001ULL, EstablishmentCause::mt_access})});
    s.push_back({"DL-CCCH", "RRCSetup", encode(Setup{0, RadioBearers{{SrbAdd{1, false}}, {}, {}}, cell_group()})});
    s.push_back({"DL-CCCH", "RRCReject", encode(Reject{5})});
    s.push_back({"DL-DCCH", "SecurityModeCommand", encode(SecurityModeCommand{1, 2, 2})});
    s.push_back({"DL-DCCH", "RRCReconfiguration",
                 encode(Reconfiguration{2, bearers(), cell_group(), {*from_hex("7e00680112000f2e0101c1ffff91a1280100")}})});
    {
        // P2 Q10: a QoS flow on a new DRB, another moved off the default DRB, which keeps its PDCP.
        RadioBearers q;
        DrbAdd fresh;
        fresh.drb_id = 2;
        fresh.default_drb = false;
        fresh.sdap_header_dl = fresh.sdap_header_ul = true;
        fresh.qfis = {3};
        DrbAdd remap;
        remap.sdap_header_dl = remap.sdap_header_ul = true;
        remap.qfis = {4};
        remap.qfis_release = {2};
        remap.setup = false;
        q.drbs = {fresh, remap};
        q.drb_release = {5};
        s.push_back({"DL-DCCH", "RRCReconfiguration.qos-remap", encode(Reconfiguration{3, q, std::nullopt, {}})});
    }
    s.push_back({"DL-DCCH", "RRCRelease", encode(Release{3})});
    s.push_back({"DL-DCCH", "UECapabilityEnquiry", encode(CapabilityEnquiry{0})});
    s.push_back({"DL-DCCH", "DLInformationTransfer", encode(DlInformationTransfer{1, *from_hex("7e005b01")})});
    s.push_back({"UL-DCCH", "RRCSetupComplete",
                 encode(SetupComplete{0, 1, *from_hex("7e004179000d0100f110000000000000000001"), std::nullopt})});
    s.push_back({"UL-DCCH", "RRCSetupComplete.part2", encode(SetupComplete{0, 1, *from_hex("7e004179000d0100f110000000000000000001"), 0x0CA})});
    s.push_back({"UL-DCCH", "SecurityModeComplete", encode(SecurityModeComplete{1})});
    s.push_back({"UL-DCCH", "SecurityModeFailure", encode(SecurityModeFailure{1})});
    s.push_back({"UL-DCCH", "RRCReconfigurationComplete", encode(ReconfigurationComplete{2})});
    auto cap = generic_nr_capability();
    s.push_back({"UL-DCCH", "UECapabilityInformation",
                 cap ? encode(CapabilityInformation{0, *cap}) : Result<Bytes>(cap.error())});
    s.push_back({"UL-DCCH", "ULInformationTransfer", encode(UlInformationTransfer{*from_hex("7e0043")})});
    s.push_back({"CellGroupConfig", "CellGroupConfig", encode(cell_group())});
    s.push_back({"UE-NR-Capability", "UE-NR-Capability", generic_nr_capability()});
    return s;
}

} // namespace ksim::rrc::samples
