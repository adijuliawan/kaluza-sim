// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// One sample of every XnAP builder (P3 R1), shared by the round-trip test and
// msg_builders_dump, whose output the oracle checks with tshark and pycrate.

#pragma once

#include <string>
#include <vector>

#include "codec/asn1/msg/rrc.hpp"
#include "codec/asn1/msg/xnap.hpp"

namespace ksim::xnap::samples {

struct Sample {
    std::string name;
    Pdu pdu;
};

inline const PlmnId kPlmn{0x00, 0xF1, 0x10};   // 001/01

inline ServedCell cell(std::uint16_t pci, std::uint64_t nci) {
    ServedCell c;
    c.pci = pci;
    c.plmn = kPlmn;
    c.nci = nci;
    c.tac = 1;
    c.meas_timing = *rrc::measurement_timing_configuration();
    return c;
}

inline std::vector<Sample> all() {
    std::vector<Sample> s;
    const TaiSupport tai{1, {{kPlmn, {Snssai{1, std::nullopt}, Snssai{1, 0x000001}}}}};
    s.push_back({"XnSetupRequest", XnSetupRequest{GnbId{kPlmn, 0x1A0, 22}, {tai}, {{kPlmn, 0x02}},
                                                  {cell(101, 0x1A0000001ULL), cell(102, 0x1A0000002ULL)}}});
    s.push_back({"XnSetupResponse", XnSetupResponse{GnbId{kPlmn, 0x1A2, 22}, {tai}, {cell(103, 0x1A2000001ULL)}}});
    s.push_back({"XnSetupFailure", XnSetupFailure{Cause{"misc", "unspecified"}, std::string("v10s")}});
    s.push_back({"NGRANNodeConfigurationUpdate",
                 NgRanNodeConfigurationUpdate{{cell(104, 0x1A2000002ULL)}, {{kPlmn, 0x1A2000001ULL}}}});
    s.push_back({"NGRANNodeConfigurationUpdateAcknowledge", NgRanNodeConfigurationUpdateAcknowledge{{cell(101, 0x1A0000001ULL)}}});
    s.push_back({"NGRANNodeConfigurationUpdateFailure", NgRanNodeConfigurationUpdateFailure{Cause{"radioNetwork", "unspecified"}}});
    s.push_back({"ResetRequest", ResetRequest{Cause{"misc", "o-and-M-intervention"}}});
    s.push_back({"ResetResponse", ResetResponse{}});
    s.push_back({"ErrorIndication", ErrorIndication{7, std::nullopt, Cause{"protocol", "abstract-syntax-error-reject"}}});
    return s;
}

} // namespace ksim::xnap::samples
