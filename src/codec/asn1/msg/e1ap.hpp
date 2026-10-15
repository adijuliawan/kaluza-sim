// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Typed E1AP builders and readers (P1 N10; TS 37.483 j40), the route of the
// NGAP and F1AP ones (KS-NGAP-B1): a struct per message of the P1 set, built
// as JER and encoded strictly as APER, read back from APER. The set: gNB-CU-UP
// E1 Setup, Bearer Context Setup, Modification (adding and removing sessions,
// the DU's F1-U ends for DRBs), Release, and Error Indication, for NG-RAN
// bearer contexts only (no E-UTRAN). The UP keys cross the codec as octets
// (rule R3): the caller copies them into SecretBytes and wipes these.

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "platform/buf.hpp"
#include "platform/result.hpp"

namespace ksim::e1ap {

using PlmnId = std::array<std::uint8_t, 3>;   // TS 24.008 coding

struct Snssai {
    std::uint8_t sst = 1;
    std::optional<std::uint32_t> sd;
    friend bool operator==(const Snssai&, const Snssai&) = default;
};
struct GtpTunnel {
    std::array<std::uint8_t, 4> addr{};   // IPv4 (P1)
    std::uint32_t teid = 0;
    friend bool operator==(const GtpTunnel&, const GtpTunnel&) = default;
};
struct Cause {
    std::string group = "misc";           // radioNetwork, transport, protocol, misc
    std::string value = "unspecified";
    friend bool operator==(const Cause&, const Cause&) = default;
};
struct SecurityIndication {
    std::string integrity = "not-needed";       // required, preferred, not-needed
    std::string confidentiality = "required";
    friend bool operator==(const SecurityIndication&, const SecurityIndication&) = default;
};
struct SecurityResult {
    bool integrity = false;
    bool confidentiality = false;
    friend bool operator==(const SecurityResult&, const SecurityResult&) = default;
};
/// The UP algorithms (0..3: NEA0, 128-NEA1 … ) and keys (K_UPenc, K_UPint), 16 octets each.
struct Security {
    std::uint8_t nea = 2;
    std::optional<std::uint8_t> nia;
    Bytes enc_key;
    std::optional<Bytes> int_key;
    friend bool operator==(const Security&, const Security&) = default;
};
struct QosFlow {
    std::uint8_t qfi = 1;
    std::uint16_t five_qi = 9;
    std::uint8_t arp_priority = 8;
    bool may_preempt = false;
    bool preemptable = true;
    friend bool operator==(const QosFlow&, const QosFlow&) = default;
};
struct DrbToSetup {
    std::uint8_t drb_id = 1;
    bool default_drb = true;
    bool sdap_ul = true;            // SDAP headers present
    bool sdap_dl = true;
    std::uint8_t sn_bits = 18;      // 12 or 18
    std::vector<QosFlow> flows;
    friend bool operator==(const DrbToSetup&, const DrbToSetup&) = default;
};
struct SessionToSetup {
    std::uint8_t psi = 1;
    std::string type = "ipv4";
    Snssai snssai;
    SecurityIndication security;
    GtpTunnel ng_ul;                // the UPF's N3 end
    std::vector<DrbToSetup> drbs;
    friend bool operator==(const SessionToSetup&, const SessionToSetup&) = default;
};
struct DrbSetup {
    std::uint8_t drb_id = 1;
    GtpTunnel f1u_ul;               // the CU-UP's F1-U end for this DRB
    std::vector<std::uint8_t> qfis;
    friend bool operator==(const DrbSetup&, const DrbSetup&) = default;
};
struct SessionSetup {
    std::uint8_t psi = 1;
    std::optional<SecurityResult> security;
    GtpTunnel ng_dl;                // the CU-UP's N3 end
    std::vector<DrbSetup> drbs;
    friend bool operator==(const SessionSetup&, const SessionSetup&) = default;
};
struct DrbToModify {
    std::uint8_t drb_id = 1;
    std::optional<GtpTunnel> f1u_dl;   // the DU's F1-U end
    friend bool operator==(const DrbToModify&, const DrbToModify&) = default;
};
struct SessionToModify {
    std::uint8_t psi = 1;
    std::vector<DrbToModify> drbs;
    friend bool operator==(const SessionToModify&, const SessionToModify&) = default;
};
struct SessionModified {
    std::uint8_t psi = 1;
    std::vector<std::uint8_t> drbs;
    friend bool operator==(const SessionModified&, const SessionModified&) = default;
};

struct E1SetupRequest {
    std::uint8_t transaction = 0;
    std::uint64_t cu_up_id = 0;
    std::string name;
    std::vector<std::pair<PlmnId, std::vector<Snssai>>> plmns;
    friend bool operator==(const E1SetupRequest&, const E1SetupRequest&) = default;
};
struct E1SetupResponse {
    std::uint8_t transaction = 0;
    std::string cu_cp_name;
    friend bool operator==(const E1SetupResponse&, const E1SetupResponse&) = default;
};
struct E1SetupFailure {
    std::uint8_t transaction = 0;
    Cause cause;
    friend bool operator==(const E1SetupFailure&, const E1SetupFailure&) = default;
};
struct BearerContextSetupRequest {
    std::uint32_t cu_cp_ue = 0;
    Security security;
    std::uint64_t ue_dl_ambr = 0;   // bit/s
    PlmnId serving_plmn{};
    std::vector<SessionToSetup> sessions;
    friend bool operator==(const BearerContextSetupRequest&, const BearerContextSetupRequest&) = default;
};
struct BearerContextSetupResponse {
    std::uint32_t cu_cp_ue = 0;
    std::uint32_t cu_up_ue = 0;
    std::vector<SessionSetup> sessions;
    friend bool operator==(const BearerContextSetupResponse&, const BearerContextSetupResponse&) = default;
};
struct BearerContextSetupFailure {
    std::uint32_t cu_cp_ue = 0;
    std::optional<std::uint32_t> cu_up_ue;
    Cause cause;
    friend bool operator==(const BearerContextSetupFailure&, const BearerContextSetupFailure&) = default;
};
struct BearerContextModificationRequest {
    std::uint32_t cu_cp_ue = 0;
    std::uint32_t cu_up_ue = 0;
    std::vector<SessionToSetup> add;
    std::vector<SessionToModify> modify;
    std::vector<std::uint8_t> remove;
    friend bool operator==(const BearerContextModificationRequest&, const BearerContextModificationRequest&) = default;
};
struct BearerContextModificationResponse {
    std::uint32_t cu_cp_ue = 0;
    std::uint32_t cu_up_ue = 0;
    std::vector<SessionSetup> added;
    std::vector<SessionModified> modified;
    friend bool operator==(const BearerContextModificationResponse&, const BearerContextModificationResponse&) = default;
};
struct BearerContextModificationFailure {
    std::uint32_t cu_cp_ue = 0;
    std::uint32_t cu_up_ue = 0;
    Cause cause;
    friend bool operator==(const BearerContextModificationFailure&, const BearerContextModificationFailure&) = default;
};
struct BearerContextReleaseCommand {
    std::uint32_t cu_cp_ue = 0;
    std::uint32_t cu_up_ue = 0;
    Cause cause;
    friend bool operator==(const BearerContextReleaseCommand&, const BearerContextReleaseCommand&) = default;
};
struct BearerContextReleaseComplete {
    std::uint32_t cu_cp_ue = 0;
    std::uint32_t cu_up_ue = 0;
    friend bool operator==(const BearerContextReleaseComplete&, const BearerContextReleaseComplete&) = default;
};
struct ErrorIndication {
    std::uint8_t transaction = 0;
    std::optional<std::uint32_t> cu_cp_ue;
    std::optional<std::uint32_t> cu_up_ue;
    std::optional<Cause> cause;
    friend bool operator==(const ErrorIndication&, const ErrorIndication&) = default;
};

using Pdu = std::variant<E1SetupRequest, E1SetupResponse, E1SetupFailure, BearerContextSetupRequest,
                         BearerContextSetupResponse, BearerContextSetupFailure, BearerContextModificationRequest,
                         BearerContextModificationResponse, BearerContextModificationFailure, BearerContextReleaseCommand,
                         BearerContextReleaseComplete, ErrorIndication>;

Result<Bytes> encode(const Pdu& p);
/// Errc::unsupported for a procedure outside the P1 set, Errc::malformed for
/// one P1 reads that lacks what it needs.
Result<Pdu> decode(ByteView in);

/// "001", "01" -> 00 F1 10.
PlmnId plmn_id(std::string_view mcc, std::string_view mnc);

/// Any E1AP PDU with its UP keys zeroed, for captures (the NGAP rule, KS-NGAP-B4).
struct Redacted {
    Bytes pdu;
    unsigned keys = 0;
};
Result<Redacted> redact_keys(ByteView in);

} // namespace ksim::e1ap
