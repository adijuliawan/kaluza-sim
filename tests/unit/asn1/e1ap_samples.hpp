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

inline DrbToModify drb_mod(std::uint8_t id, std::optional<GtpTunnel> f1u_dl, std::optional<std::vector<QosFlow>> flows) {
    DrbToModify d;
    d.drb_id = id;
    d.f1u_dl = f1u_dl;
    d.flows = std::move(flows);
    return d;
}

inline SessionModified sess_modified(std::uint8_t psi, std::vector<std::uint8_t> drbs, std::vector<DrbSetup> setup) {
    SessionModified m;
    m.psi = psi;
    m.drbs = std::move(drbs);
    m.drbs_setup = std::move(setup);
    return m;
}

inline std::vector<Sample> all() {
    std::vector<Sample> s;
    const PlmnId plmn{0x00, 0xF1, 0x10};
    const Snssai slice{1, 0x000001};
    s.push_back({"GNB-CU-UP-E1SetupRequest", E1SetupRequest{1, 0x1A0, "ksim-cuup1", {{plmn, {slice}}}}});
    s.push_back({"GNB-CU-UP-E1SetupResponse", E1SetupResponse{1, "ksim-gnb1"}});
    s.push_back({"GNB-CU-UP-E1SetupFailure", E1SetupFailure{1, Cause{"misc", "unspecified"}}});
    const DrbToSetup drb{1, true, true, true, 18, {QosFlow{1, 9, 8, false, true, std::nullopt, false}}, "ms100", 40};   // P2 Q5: the PDCP timers
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
    SessionToModify one;
    one.psi = 1;
    one.drbs = {drb_mod(1, GtpTunnel{{127, 0, 0, 3}, 0x30000001}, std::nullopt)};
    mod.modify = {one};
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
    s.push_back({"BearerContextModificationResponse", BearerContextModificationResponse{1, 1, {}, {sess_modified(1, {1}, {})}}});
    // P2 Q10: a QoS flow added on a new DRB, another remapped, a DRB removed, the AMBR changed.
    BearerContextModificationRequest qos;
    qos.cu_cp_ue = 1;
    qos.cu_up_ue = 1;
    SessionToModify sm;
    sm.psi = 1;
    sm.dl_ambr = 500'000'000;
    DrbToSetup drb3 = drb;
    drb3.drb_id = 3;
    drb3.default_drb = false;
    drb3.flows = {QosFlow{3, 1, 2, true, false, Gbr{256000, 128000, 128000, 64000}, true}};   // P2 Q11: GBR, reflective
    sm.drbs_setup = {drb3};
    sm.drbs = {drb_mod(1, std::nullopt, std::vector<QosFlow>{QosFlow{1, 9, 8, false, true, std::nullopt, false}, QosFlow{2, 9, 8, false, true, std::nullopt, false}})};
    sm.drbs_remove = {2};
    qos.modify = {sm};
    s.push_back({"BearerContextModificationRequest.qos", qos});
    s.push_back({"BearerContextModificationResponse.qos",
                 BearerContextModificationResponse{1, 1, {}, {sess_modified(1, {1}, {DrbSetup{3, GtpTunnel{{127, 0, 0, 4}, 0x20000003}, {3}}})}}});
    SessionSetup added = done;
    added.psi = 2;
    added.drbs[0].drb_id = 2;
    s.push_back({"BearerContextModificationResponse.added", BearerContextModificationResponse{1, 1, {added}, {}}});
    s.push_back({"BearerContextModificationFailure", BearerContextModificationFailure{1, 1, Cause{"radioNetwork", "unspecified"}}});
    s.push_back({"BearerContextReleaseCommand", BearerContextReleaseCommand{1, 1, Cause{"radioNetwork", "normal-release"}}});
    s.push_back({"BearerContextReleaseComplete", BearerContextReleaseComplete{1, 1}});
    s.push_back({"ErrorIndication", ErrorIndication{0, 1, std::nullopt, Cause{"protocol", "abstract-syntax-error-reject"}}});
    s.push_back({"BearerContextInactivityNotification", BearerContextInactivityNotification{1, 2, false}});   // P2 Q5
    // P3 R1: a handover's E1AP (TS 37.483 §8.3.2, §8.3.3, §8.3.5): the source asked for
    // the SN status and forwarding, the target given them with PDCP re-establishment and a
    // path switch's new UPF end, the CU-UP's own requests.
    {
        BearerContextModificationRequest src;
        src.cu_cp_ue = 1;
        src.cu_up_ue = 1;
        SessionToModify s1;
        s1.psi = 1;
        s1.forwarding_request = true;
        DrbToModify d1 = drb_mod(1, std::nullopt, std::nullopt);
        d1.sn_status_request = true;
        s1.drbs = {d1};
        src.modify = {s1};
        s.push_back({"BearerContextModificationRequest.ho-source", src});
        BearerContextModificationResponse srsp{1, 1, {}, {sess_modified(1, {1}, {})}};
        srsp.modified[0].forwarding = Forwarding{GtpTunnel{{127, 0, 0, 4}, 0x20000010}, GtpTunnel{{127, 0, 0, 4}, 0x20000011}};
        srsp.modified[0].sn_status = {{1, SnStatus{PdcpCount{17, 0}, PdcpCount{42, 1}}}};
        s.push_back({"BearerContextModificationResponse.ho-source", srsp});
        BearerContextModificationRequest tgt;
        tgt.cu_cp_ue = 2;
        tgt.cu_up_ue = 2;
        SessionToModify s2;
        s2.psi = 1;
        s2.ng_ul = GtpTunnel{{127, 0, 0, 9}, 0x00000042};
        DrbToModify d2 = drb_mod(1, GtpTunnel{{127, 0, 0, 3}, 0x30000002}, std::nullopt);
        d2.pdcp_reestablish = true;
        d2.forwarding = Forwarding{std::nullopt, GtpTunnel{{127, 0, 0, 5}, 0x20000020}};
        d2.sn_status = SnStatus{PdcpCount{17, 0}, PdcpCount{42, 1}};
        s2.drbs = {d2};
        tgt.modify = {s2};
        s.push_back({"BearerContextModificationRequest.ho-target", tgt});
        s.push_back({"BearerContextModificationRequired",
                     BearerContextModificationRequired{1, 1, {{1, GtpTunnel{{127, 0, 0, 4}, 0x20000030}}}}});
        s.push_back({"BearerContextModificationConfirm", BearerContextModificationConfirm{1, 1, {1}}});
        s.push_back({"BearerContextReleaseRequest", BearerContextReleaseRequest{1, 1, Cause{"radioNetwork", "unspecified"}}});
    }
    return s;
}

} // namespace ksim::e1ap::samples
