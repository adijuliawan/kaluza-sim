// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// One sample of every E1AP builder (P1 N10), shared by the round-trip tests and
// msg_builders_dump, whose output the oracle checks with tshark and pycrate.

#pragma once

#include <string>
#include <vector>

#include "codec/asn1/msg/e1ap.hpp"

namespace ksim::e1ap::samples {

struct Sample {
    std::string name;
    Pdu pdu;
};

inline std::vector<Sample> all() {
    std::vector<Sample> s;
    const PlmnId plmn{0x00, 0xF1, 0x10};
    const Snssai slice{1, 0x000001};
    s.push_back({"GNB-CU-UP-E1SetupRequest", E1SetupRequest{1, 0x1A0, "ksim-cuup1", {{plmn, {slice}}}}});
    s.push_back({"GNB-CU-UP-E1SetupResponse", E1SetupResponse{1, "ksim-gnb1"}});
    s.push_back({"GNB-CU-UP-E1SetupFailure", E1SetupFailure{1, Cause{"misc", "unspecified"}}});
    const DrbToSetup drb{1, true, true, true, 18, {QosFlow{1, 9, 8, false, true}}};
    const SessionToSetup sess{1, "ipv4", slice, SecurityIndication{"preferred", "required"},
                              GtpTunnel{{172, 30, 50, 2}, 0x101}, {drb}};
    BearerContextSetupRequest req;
    req.cu_cp_ue = 1;
    req.security = Security{2, 2, Bytes(16, 0x5A), Bytes(16, 0xA5)};   // placeholders, not derived keys
    req.ue_dl_ambr = 2'000'000'000;
    req.serving_plmn = plmn;
    req.sessions = {sess};
    s.push_back({"BearerContextSetupRequest", req});
    const SessionSetup done{1, SecurityResult{false, true}, GtpTunnel{{172, 30, 30, 31}, 0x10000001},
                            {DrbSetup{1, GtpTunnel{{127, 0, 0, 4}, 0x20000001}, {1}}}};
    s.push_back({"BearerContextSetupResponse", BearerContextSetupResponse{1, 1, {done}}});
    s.push_back({"BearerContextSetupFailure", BearerContextSetupFailure{1, std::nullopt, Cause{"radioNetwork", "unspecified"}}});
    BearerContextModificationRequest mod;
    mod.cu_cp_ue = 1;
    mod.cu_up_ue = 1;
    mod.modify = {SessionToModify{1, {DrbToModify{1, GtpTunnel{{127, 0, 0, 3}, 0x30000001}}}}};
    s.push_back({"BearerContextModificationRequest", mod});
    BearerContextModificationRequest add;
    add.cu_cp_ue = 1;
    add.cu_up_ue = 1;
    SessionToSetup second = sess;
    second.psi = 2;
    second.drbs[0].drb_id = 2;
    add.add = {second};
    add.remove = {1};
    s.push_back({"BearerContextModificationRequest.add-remove", add});
    s.push_back({"BearerContextModificationResponse", BearerContextModificationResponse{1, 1, {}, {SessionModified{1, {1}}}}});
    SessionSetup added = done;
    added.psi = 2;
    added.drbs[0].drb_id = 2;
    s.push_back({"BearerContextModificationResponse.added", BearerContextModificationResponse{1, 1, {added}, {}}});
    s.push_back({"BearerContextModificationFailure", BearerContextModificationFailure{1, 1, Cause{"radioNetwork", "unspecified"}}});
    s.push_back({"BearerContextReleaseCommand", BearerContextReleaseCommand{1, 1, Cause{"radioNetwork", "normal-release"}}});
    s.push_back({"BearerContextReleaseComplete", BearerContextReleaseComplete{1, 1}});
    s.push_back({"ErrorIndication", ErrorIndication{0, 1, std::nullopt, Cause{"protocol", "abstract-syntax-error-reject"}}});
    return s;
}

} // namespace ksim::e1ap::samples
