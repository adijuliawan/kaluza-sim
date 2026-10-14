// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// One sample of every F1AP builder (P1 N7), shared by the round-trip tests and
// msg_builders_dump, whose output the oracle checks with tshark and pycrate.

#pragma once

#include <string>
#include <vector>

#include "codec/asn1/msg/f1ap.hpp"
#include "rrc_samples.hpp"

namespace ksim::f1ap::samples {

struct Sample {
    std::string name;
    Pdu pdu;
};

inline const PlmnId kPlmn{0x00, 0xF1, 0x10};
inline const NrCgi kCgi{kPlmn, 0x1A0000001};

inline std::vector<Sample> all() {
    std::vector<Sample> s;
    rrc::Sib1 sib1;
    sib1.plmns = {rrc::Plmn{"001", "01"}};
    sib1.tac = 1;
    sib1.cell_identity = kCgi.nci;
    ServedCell cell;
    cell.cgi = kCgi;
    cell.pci = 101;
    cell.tac = 1;
    cell.plmns = {kPlmn};
    cell.arfcn = 632628;
    cell.meas_timing = *rrc::measurement_timing_configuration();
    cell.mib = *rrc::mib_ie(rrc::Mib{});
    cell.sib1 = *rrc::sib1_ie(sib1);
    s.push_back({"F1SetupRequest", F1SetupRequest{1, 0x1A0, "ksim-du1", {cell}}});
    s.push_back({"F1SetupResponse", F1SetupResponse{1, "ksim-cu1", {kCgi}}});
    s.push_back({"F1SetupFailure", F1SetupFailure{1, Cause{"misc", "unspecified"}, "v10s"}});
    const Bytes setup_request = *rrc::encode(rrc::SetupRequest{false, 0x123456789AULL >> 1});
    const Bytes cell_group = *rrc::encode(rrc::samples::cell_group());
    s.push_back({"InitialULRRCMessageTransfer", InitialUlRrcMessageTransfer{1, kCgi, 0x4601, setup_request, cell_group, 0}});
    const rrc::Setup setup{0, rrc::RadioBearers{{rrc::SrbAdd{1, false}}, {}, {}}, rrc::samples::cell_group()};
    s.push_back({"DLRRCMessageTransfer", DlRrcMessageTransfer{7, 1, 0, *rrc::encode(setup)}});
    // SRB1 PDCP PDUs: a 2-octet header, the RRC message, a zero MAC-I.
    auto pdcp = [](const Bytes& rrc) {
        Bytes p{0x00, 0x00};
        p.insert(p.end(), rrc.begin(), rrc.end());
        p.insert(p.end(), 4, 0x00);
        return p;
    };
    s.push_back({"DLRRCMessageTransfer.srb1",
                 DlRrcMessageTransfer{7, 1, 1, pdcp(*rrc::encode(rrc::SecurityModeCommand{1, 2, 2}))}});
    s.push_back({"ULRRCMessageTransfer",
                 UlRrcMessageTransfer{7, 1, 1, pdcp(*rrc::encode(rrc::SetupComplete{0, 1, *from_hex("7e004179000d0100f110000000000000000001"), std::nullopt}))}});
    s.push_back({"UEContextSetupRequest", UeContextSetupRequest{7, 1, kCgi, 0, std::nullopt, {2}, std::nullopt}});
    s.push_back({"UEContextSetupResponse", UeContextSetupResponse{7, 1, cell_group, {{2, 2}}}});
    s.push_back({"UEContextSetupFailure", UeContextSetupFailure{7, 1, Cause{"radioNetwork", "unspecified"}}});
    s.push_back({"UEContextModificationRequest", UeContextModificationRequest{7, 1, {2}, std::nullopt}});
    s.push_back({"UEContextModificationResponse", UeContextModificationResponse{7, 1, cell_group}});
    s.push_back({"UEContextReleaseRequest", UeContextReleaseRequest{7, 1, Cause{"radioNetwork", "rl-failure-others"}}});
    s.push_back({"UEContextReleaseCommand",
                 UeContextReleaseCommand{7, 1, Cause{"radioNetwork", "normal-release"}, pdcp(*rrc::encode(rrc::Release{0})), 1}});
    s.push_back({"UEContextReleaseComplete", UeContextReleaseComplete{7, 1}});
    s.push_back({"Paging", Paging{0x0CA040000001ULL % 1024, 0x0CA040000001ULL, {kCgi}, "v128"}});
    s.push_back({"ErrorIndication", ErrorIndication{0, 7, 1, Cause{"protocol", "abstract-syntax-error-reject"}}});
    return s;
}

} // namespace ksim::f1ap::samples
