// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Typed builders and readers for the RRC messages P1 uses (P1 N6; TS 38.331
// j40 §6.2, §6.3; architecture.md §4.1 msg/). A message is a plain struct;
// encode() checks its inputs, builds the value as X.697 JSON and lets the
// generated asn1c code (JER in, strict UPER out) produce the octets, so every
// constraint of the ASN.1 is applied by the same code that decodes. The
// readers decode UPER and read the fields P1 interprets from the JER.
//
// Covered: MIB (BCCH-BCH), SIB1 (BCCH-DL-SCH), Paging (PCCH), RRCSetupRequest
// (UL-CCCH), RRCSetup and RRCReject (DL-CCCH), SecurityModeCommand,
// RRCReconfiguration, RRCRelease, UECapabilityEnquiry and
// DLInformationTransfer (DL-DCCH), RRCSetupComplete, SecurityModeComplete,
// SecurityModeFailure, RRCReconfigurationComplete, UECapabilityInformation
// and ULInformationTransfer (UL-DCCH), CellGroupConfig (the RLC bearers only)
// and a generic UE-NR-Capability.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "platform/buf.hpp"
#include "platform/result.hpp"

namespace ksim::rrc {

struct Plmn {
    std::string mcc;   // 3 digits
    std::string mnc;   // 2 or 3 digits
    friend bool operator==(const Plmn&, const Plmn&) = default;
};

// ---- BCCH-BCH -----------------------------------------------------------------------

struct Mib {
    std::uint16_t sfn = 0;                 // 10 bits; the MIB carries the six most significant
    bool scs_30_or_120 = true;             // subCarrierSpacingCommon
    std::uint8_t ssb_subcarrier_offset = 0;   // 0..15
    bool dmrs_pos3 = false;                // dmrs-TypeA-Position
    std::uint8_t coreset0 = 0;             // 0..15
    std::uint8_t search_space0 = 0;        // 0..15
    bool barred = false;
    bool intra_freq_reselection = true;
    friend bool operator==(const Mib&, const Mib&) = default;
};
Result<Bytes> encode(const Mib& m);
Result<Mib> decode_mib(ByteView in);

// ---- BCCH-DL-SCH ----------------------------------------------------------------------

struct UeTimers {   // UE-TimersAndConstants, values in ms or counts
    int t300 = 1000;
    int t301 = 1000;
    int t310 = 1000;
    int n310 = 1;
    int t311 = 3000;
    int n311 = 1;
    int t319 = 1000;
    friend bool operator==(const UeTimers&, const UeTimers&) = default;
};

struct Sib1 {
    std::vector<Plmn> plmns;               // 1..12, one PLMN-IdentityInfo
    std::uint32_t tac = 0;                 // 24 bits
    std::uint64_t cell_identity = 0;       // 36 bits (the NCI)
    bool reserved_for_operator_use = false;
    std::optional<UeTimers> timers;
    friend bool operator==(const Sib1&, const Sib1&) = default;
};
Result<Bytes> encode(const Sib1& s);
Result<Sib1> decode_sib1(ByteView in);

// ---- PCCH ------------------------------------------------------------------------------

struct Paging {
    std::vector<std::uint64_t> s_tmsis;    // 48-bit 5G-S-TMSIs (fullI-RNTI is P3b)
    friend bool operator==(const Paging&, const Paging&) = default;
};
Result<Bytes> encode(const Paging& p);
Result<Paging> decode_paging(ByteView in);

// ---- radio bearers and the cell group ----------------------------------------------------

struct PdcpSettings {
    bool sn18_ul = true;
    bool sn18_dl = true;
    bool integrity = false;                // integrityProtection enabled
    bool status_report = false;
    bool out_of_order = false;
    std::optional<int> t_reordering_ms;    // absent: infinity
    friend bool operator==(const PdcpSettings&, const PdcpSettings&) = default;
};

struct SrbAdd {
    std::uint8_t srb_id = 1;               // 1..3
    bool reestablish_pdcp = false;
    friend bool operator==(const SrbAdd&, const SrbAdd&) = default;
};

struct DrbAdd {
    std::uint8_t drb_id = 1;               // 1..32
    std::uint8_t pdu_session = 1;          // 0..255
    bool sdap_header_dl = false;
    bool sdap_header_ul = false;
    bool default_drb = true;
    std::vector<std::uint8_t> qfis;        // mappedQoS-FlowsToAdd
    PdcpSettings pdcp;
    friend bool operator==(const DrbAdd&, const DrbAdd&) = default;
};

struct RadioBearers {
    std::vector<SrbAdd> srbs;
    std::vector<DrbAdd> drbs;
    std::vector<std::uint8_t> drb_release;
    friend bool operator==(const RadioBearers&, const RadioBearers&) = default;
};

struct RlcBearer {
    std::uint8_t lcid = 1;                 // 1..32
    bool srb = true;
    std::uint8_t rb_id = 1;                // the SRB or DRB it serves
    bool am = true;                        // AM, else UM bidirectional
    friend bool operator==(const RlcBearer&, const RlcBearer&) = default;
};

struct CellGroup {
    std::uint8_t id = 0;
    std::vector<RlcBearer> bearers;
    std::vector<std::uint8_t> release_lcids;
    friend bool operator==(const CellGroup&, const CellGroup&) = default;
};
Result<Bytes> encode(const CellGroup& c);
Result<CellGroup> decode_cell_group(ByteView in);

// ---- UL-CCCH ---------------------------------------------------------------------------

enum class EstablishmentCause : std::uint8_t {
    emergency, high_priority_access, mt_access, mo_signalling, mo_data, mo_voice_call, mo_video_call, mo_sms,
    mps_priority_access, mcs_priority_access,
};
const char* cause_name(EstablishmentCause c) noexcept;

struct SetupRequest {
    bool s_tmsi_part1 = false;             // ng-5G-S-TMSI-Part1, else randomValue
    std::uint64_t identity = 0;            // 39 bits
    EstablishmentCause cause = EstablishmentCause::mo_signalling;
    friend bool operator==(const SetupRequest&, const SetupRequest&) = default;
};
Result<Bytes> encode(const SetupRequest& r);
Result<SetupRequest> decode_ul_ccch(ByteView in);

// ---- DL-CCCH ---------------------------------------------------------------------------

struct Setup {
    std::uint8_t tid = 0;                  // rrc-TransactionIdentifier 0..3
    RadioBearers bearers;                  // SRB1
    CellGroup cell_group;
    friend bool operator==(const Setup&, const Setup&) = default;
};
struct Reject {
    std::optional<std::uint8_t> wait_time_s;   // 1..16
    friend bool operator==(const Reject&, const Reject&) = default;
};
using DlCcch = std::variant<Setup, Reject>;
Result<Bytes> encode(const Setup& m);
Result<Bytes> encode(const Reject& m);
Result<DlCcch> decode_dl_ccch(ByteView in);

// ---- DL-DCCH ---------------------------------------------------------------------------

struct SecurityModeCommand {
    std::uint8_t tid = 0;
    std::uint8_t nea = 2;                  // 0..3
    std::uint8_t nia = 2;                  // 0..3
    friend bool operator==(const SecurityModeCommand&, const SecurityModeCommand&) = default;
};
struct Reconfiguration {
    std::uint8_t tid = 0;
    std::optional<RadioBearers> bearers;
    std::optional<CellGroup> cell_group;   // masterCellGroup
    std::vector<Bytes> nas;                // dedicatedNAS-MessageList
    friend bool operator==(const Reconfiguration&, const Reconfiguration&) = default;
};
struct Release {
    std::uint8_t tid = 0;
    friend bool operator==(const Release&, const Release&) = default;
};
struct CapabilityEnquiry {
    std::uint8_t tid = 0;                  // the RAT is NR
    friend bool operator==(const CapabilityEnquiry&, const CapabilityEnquiry&) = default;
};
struct DlInformationTransfer {
    std::uint8_t tid = 0;
    Bytes nas;
    friend bool operator==(const DlInformationTransfer&, const DlInformationTransfer&) = default;
};
using DlDcch = std::variant<SecurityModeCommand, Reconfiguration, Release, CapabilityEnquiry, DlInformationTransfer>;
Result<Bytes> encode(const SecurityModeCommand& m);
Result<Bytes> encode(const Reconfiguration& m);
Result<Bytes> encode(const Release& m);
Result<Bytes> encode(const CapabilityEnquiry& m);
Result<Bytes> encode(const DlInformationTransfer& m);
Result<DlDcch> decode_dl_dcch(ByteView in);

// ---- UL-DCCH ---------------------------------------------------------------------------

struct SetupComplete {
    std::uint8_t tid = 0;
    std::uint8_t selected_plmn = 1;        // 1..12
    Bytes nas;
    std::optional<std::uint16_t> s_tmsi_part2;   // 9 bits, with a Part1 request
    friend bool operator==(const SetupComplete&, const SetupComplete&) = default;
};
struct SecurityModeComplete {
    std::uint8_t tid = 0;
    friend bool operator==(const SecurityModeComplete&, const SecurityModeComplete&) = default;
};
struct SecurityModeFailure {
    std::uint8_t tid = 0;
    friend bool operator==(const SecurityModeFailure&, const SecurityModeFailure&) = default;
};
struct ReconfigurationComplete {
    std::uint8_t tid = 0;
    friend bool operator==(const ReconfigurationComplete&, const ReconfigurationComplete&) = default;
};
struct CapabilityInformation {
    std::uint8_t tid = 0;
    Bytes nr_capability;                   // UE-NR-Capability, UPER
    friend bool operator==(const CapabilityInformation&, const CapabilityInformation&) = default;
};
struct UlInformationTransfer {
    Bytes nas;
    friend bool operator==(const UlInformationTransfer&, const UlInformationTransfer&) = default;
};
using UlDcch = std::variant<SetupComplete, SecurityModeComplete, SecurityModeFailure, ReconfigurationComplete,
                            CapabilityInformation, UlInformationTransfer>;
Result<Bytes> encode(const SetupComplete& m);
Result<Bytes> encode(const SecurityModeComplete& m);
Result<Bytes> encode(const SecurityModeFailure& m);
Result<Bytes> encode(const ReconfigurationComplete& m);
Result<Bytes> encode(const CapabilityInformation& m);
Result<Bytes> encode(const UlInformationTransfer& m);
Result<UlDcch> decode_ul_dcch(ByteView in);

// ---- capabilities ------------------------------------------------------------------------

/// A minimal UE-NR-Capability for the generic persona (N15 brings real ones):
/// Rel-15, no ROHC, band n78.
Result<Bytes> generic_nr_capability();

/// The message's JER (X.697 JSON) for logs and the oracle: `channel` is
/// "BCCH-BCH", "BCCH-DL-SCH", "PCCH", "UL-CCCH", "DL-CCCH", "DL-DCCH",
/// "UL-DCCH", "CellGroupConfig" or "UE-NR-Capability".
Result<std::string> to_jer(std::string_view channel, ByteView in);

} // namespace ksim::rrc
