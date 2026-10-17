// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Typed builders and readers for XnAP (P3 R1; TS 38.423 j40; architecture.md
// §4.1 msg/), the same route as NGAP, F1AP and E1AP: a struct per message,
// built as X.697 JSON and encoded by the generated asn1c code (APER).
//
// Covered at R1, the non-UE-associated procedures of TS 38.423 §8.4
// (KS-XNAP-001): Xn Setup (§8.4.1), NG-RAN node Configuration Update (§8.4.2,
// a gNB's served NR cells added or deleted), Reset (§8.4.3, full) and Error
// Indication (§8.4.4). The handover messages (§8.2) come with R8.

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "platform/buf.hpp"
#include "platform/result.hpp"

namespace ksim::xnap {

using PlmnId = std::array<std::uint8_t, 3>;   // TS 38.423 9.2.2.4, as NGAP's

struct GnbId {
    PlmnId plmn{};
    std::uint32_t value = 0;
    std::uint8_t bits = 22;   // 22..32
    friend bool operator==(const GnbId&, const GnbId&) = default;
};
struct Snssai {
    std::uint8_t sst = 1;
    std::optional<std::uint32_t> sd;   // 24 bits
    friend bool operator==(const Snssai&, const Snssai&) = default;
};
/// TAI Support List item (9.2.3.20): a TAC with the PLMNs and slices it serves.
struct TaiSupport {
    std::uint32_t tac = 1;   // 24 bits
    std::vector<std::pair<PlmnId, std::vector<Snssai>>> plmns;
    friend bool operator==(const TaiSupport&, const TaiSupport&) = default;
};
/// Served Cell Information NR (9.2.2.11), the TDD form the sim's cells take.
struct ServedCell {
    std::uint16_t pci = 0;            // 0..1007
    PlmnId plmn{};
    std::uint64_t nci = 0;            // 36 bits
    std::uint32_t tac = 1;
    std::uint32_t arfcn = 632628;
    std::uint16_t band = 78;
    std::string scs = "scs30";        // NRSCS
    std::string nrb = "nrb106";       // NRNRB
    Bytes meas_timing;                // MeasurementTimingConfiguration (TS 38.331)
    friend bool operator==(const ServedCell&, const ServedCell&) = default;
};
struct Cause {
    std::string group = "misc";       // radioNetwork, transport, protocol, misc
    std::string value = "unspecified";
    friend bool operator==(const Cause&, const Cause&) = default;
};

struct XnSetupRequest {
    GnbId gnb;
    std::vector<TaiSupport> tais;
    std::vector<std::pair<PlmnId, std::uint8_t>> amf_regions;   // GlobalAMF-Region-Information
    std::vector<ServedCell> cells;
    friend bool operator==(const XnSetupRequest&, const XnSetupRequest&) = default;
};
struct XnSetupResponse {
    GnbId gnb;
    std::vector<TaiSupport> tais;
    std::vector<ServedCell> cells;
    friend bool operator==(const XnSetupResponse&, const XnSetupResponse&) = default;
};
struct XnSetupFailure {
    Cause cause;
    std::optional<std::string> time_to_wait;   // v1s, v2s, v5s, v10s, v20s, v60s
    friend bool operator==(const XnSetupFailure&, const XnSetupFailure&) = default;
};
/// A gNB's configuration update (ConfigurationUpdateInitiatingNodeChoice gNB).
struct NgRanNodeConfigurationUpdate {
    std::vector<ServedCell> add;
    std::vector<std::pair<PlmnId, std::uint64_t>> remove;   // NR CGIs
    friend bool operator==(const NgRanNodeConfigurationUpdate&, const NgRanNodeConfigurationUpdate&) = default;
};
struct NgRanNodeConfigurationUpdateAcknowledge {
    std::vector<ServedCell> cells;   // the responding gNB's served NR cells
    friend bool operator==(const NgRanNodeConfigurationUpdateAcknowledge&, const NgRanNodeConfigurationUpdateAcknowledge&) = default;
};
struct NgRanNodeConfigurationUpdateFailure {
    Cause cause;
    friend bool operator==(const NgRanNodeConfigurationUpdateFailure&, const NgRanNodeConfigurationUpdateFailure&) = default;
};
struct ResetRequest {   // a full reset
    Cause cause;
    friend bool operator==(const ResetRequest&, const ResetRequest&) = default;
};
struct ResetResponse {
    friend bool operator==(const ResetResponse&, const ResetResponse&) = default;
};
struct ErrorIndication {
    std::optional<std::uint32_t> old_id;   // old NG-RAN node UE XnAP ID
    std::optional<std::uint32_t> new_id;
    std::optional<Cause> cause;
    friend bool operator==(const ErrorIndication&, const ErrorIndication&) = default;
};

using Pdu = std::variant<XnSetupRequest, XnSetupResponse, XnSetupFailure, NgRanNodeConfigurationUpdate,
                         NgRanNodeConfigurationUpdateAcknowledge, NgRanNodeConfigurationUpdateFailure, ResetRequest,
                         ResetResponse, ErrorIndication>;

Result<Bytes> encode(const Pdu& p);
/// Errc::unsupported for a procedure outside the R1 set.
Result<Pdu> decode(ByteView in);

/// Any XnAP PDU with its key material zeroed, for captures (as ngap::redact_keys):
/// every K_NG-RAN* (key-NG-RAN-Star, AS Security Information, TS 38.423 9.2.3.49)
/// found by walking the decoded value. `keys` counts the values zeroed.
struct Redacted {
    Bytes pdu;
    unsigned keys = 0;
};
Result<Redacted> redact_keys(ByteView in);

} // namespace ksim::xnap
