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
// and a generic UE-NR-Capability. P3 R1 adds mobility: the CellGroupConfig's
// spCellConfig with reconfigurationWithSync (the target cell's common
// configuration, the new C-RNTI, T304 and contention-free RA), masterKeyUpdate,
// RRCReestablishmentRequest (UL-CCCH), RRCReestablishment (DL-DCCH),
// RRCReestablishmentComplete (UL-DCCH), the registeredAMF and S-NSSAI list of
// RRCSetupComplete, and the inter-node HandoverPreparationInformation and
// HandoverCommand (TS 38.331 §11.2.2).

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
Result<Bytes> encode(const Mib& m);   // a BCCH-BCH-Message
Result<Mib> decode_mib(ByteView in);
/// The MIB alone, as F1 Setup's gNB-DU System Information carries it (TS 38.473 §9.3.1.18).
Result<Bytes> mib_ie(const Mib& m);
Result<Mib> decode_mib_ie(ByteView in);

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
Result<Bytes> encode(const Sib1& s);   // a BCCH-DL-SCH-Message
Result<Sib1> decode_sib1(ByteView in);
/// SIB1 alone, as F1 Setup carries it.
Result<Bytes> sib1_ie(const Sib1& s);
Result<Sib1> decode_sib1_ie(ByteView in);

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
    bool ciphering_disabled = false;       // P2 Q8/Q9: cipheringDisabled (the session's UP confidentiality not performed)
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
    // P2 Q10: mappedQoS-FlowsToRelease; and false for a DRB already set up whose QoS flow
    // mapping alone changes (no pdcp-Config: TS 38.331 DRB-ToAddMod, Cond PDCP, Need M).
    std::vector<std::uint8_t> qfis_release;
    bool setup = true;
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

/// The target cell's ServingCellConfigCommon as a handover gives it (TS 38.331
/// §6.3.2): what a UE needs to reach the cell. The ideal radio has no PHY, so the
/// values only have to be consistent: an n78 carrier of `carrier_prbs` PRBs at
/// `scs_khz`, its SSB at `ssb_arfcn`, a 5 ms TDD pattern (7 DL slots, 6 DL
/// symbols, 2 UL slots, 4 UL symbols), one SSB in the burst.
struct ServingCellCommon {
    std::uint16_t pci = 0;                 // 0..1007
    std::uint32_t ssb_arfcn = 632640;      // absoluteFrequencySSB, on the sync raster (as SsbTiming)
    std::uint32_t point_a = 631656;        // absoluteFrequencyPointA
    std::uint16_t band = 78;
    std::uint16_t scs_khz = 30;            // 15 or 30
    std::uint16_t carrier_prbs = 106;      // 1..275
    std::int8_t ss_pbch_power = -16;       // dBm, -60..50
    friend bool operator==(const ServingCellCommon&, const ServingCellCommon&) = default;
};
/// Contention-free random access on one SSB (TS 38.331 CFRA; TS 38.321 §5.1).
struct Cfra {
    std::uint8_t ssb = 0;                  // 0..63
    std::uint8_t preamble = 63;            // ra-PreambleIndex 0..63
    friend bool operator==(const Cfra&, const Cfra&) = default;
};
/// ReconfigurationWithSync (TS 38.331 §5.3.5.5.2): a handover's target.
struct ReconfigWithSync {
    ServingCellCommon cell;
    std::uint16_t new_ue_id = 0;           // the target's C-RNTI
    std::uint16_t t304_ms = 1000;          // 50, 100, 150, 200, 500, 1000, 2000, 10000
    std::optional<Cfra> cfra;
    friend bool operator==(const ReconfigWithSync&, const ReconfigWithSync&) = default;
};

struct CellGroup {
    std::uint8_t id = 0;
    std::vector<RlcBearer> bearers;
    std::vector<std::uint8_t> release_lcids;
    std::optional<ReconfigWithSync> sync;  // P3 R1: spCellConfig.reconfigurationWithSync
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
enum class ReestablishmentCause : std::uint8_t { reconfiguration_failure, handover_failure, other_failure };
/// RRCReestablishmentRequest (TS 38.331 §5.3.7.4): the UE's C-RNTI and PCI in the
/// source cell and its shortMAC-I (VarShortMAC-Input over the source K_RRCint).
struct ReestablishmentRequest {
    std::uint16_t c_rnti = 0;
    std::uint16_t pci = 0;                 // 0..1007
    std::uint16_t short_mac_i = 0;         // 16 bits
    ReestablishmentCause cause = ReestablishmentCause::other_failure;
    friend bool operator==(const ReestablishmentRequest&, const ReestablishmentRequest&) = default;
};
using UlCcch = std::variant<SetupRequest, ReestablishmentRequest>;
Result<Bytes> encode(const SetupRequest& r);
Result<Bytes> encode(const ReestablishmentRequest& r);
/// An RRCSetupRequest; an RRCReestablishmentRequest is an error here (decode_ul_ccch_any reads both).
Result<SetupRequest> decode_ul_ccch(ByteView in);
Result<UlCcch> decode_ul_ccch_any(ByteView in);

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
/// MasterKeyUpdate (TS 38.331 §5.3.5.7): the key change at a handover or an
/// intra-cell key refresh; keySetChangeIndicator false is K_gNB* from the current
/// K_gNB or from NH (by the NCC), true a new K_AMF's.
struct KeyUpdate {
    bool key_set_change = false;
    std::uint8_t ncc = 0;                  // 0..7
    friend bool operator==(const KeyUpdate&, const KeyUpdate&) = default;
};
struct Reconfiguration {
    std::uint8_t tid = 0;
    std::optional<RadioBearers> bearers;
    std::optional<CellGroup> cell_group;   // masterCellGroup
    std::vector<Bytes> nas;                // dedicatedNAS-MessageList
    std::optional<KeyUpdate> key_update;   // P3 R1: masterKeyUpdate
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
/// RRCReestablishment (TS 38.331 §5.3.7.5): the NCC the UE derives K_gNB* with.
struct Reestablishment {
    std::uint8_t tid = 0;
    std::uint8_t ncc = 0;                  // 0..7
    friend bool operator==(const Reestablishment&, const Reestablishment&) = default;
};
using DlDcch = std::variant<SecurityModeCommand, Reconfiguration, Release, CapabilityEnquiry, DlInformationTransfer,
                            Reestablishment>;
Result<Bytes> encode(const SecurityModeCommand& m);
Result<Bytes> encode(const Reconfiguration& m);
Result<Bytes> encode(const Release& m);
Result<Bytes> encode(const CapabilityEnquiry& m);
Result<Bytes> encode(const DlInformationTransfer& m);
Result<Bytes> encode(const Reestablishment& m);
Result<DlDcch> decode_dl_dcch(ByteView in);
/// The RRCReconfiguration alone (not a DL-DCCH-Message), as the inter-node
/// containers carry it: AS-Config's rrcReconfiguration, HandoverCommand's message.
Result<Bytes> reconfiguration_ie(const Reconfiguration& m);
Result<Reconfiguration> decode_reconfiguration_ie(ByteView in);

// ---- UL-DCCH ---------------------------------------------------------------------------

struct Snssai {
    std::uint8_t sst = 0;
    std::optional<std::uint32_t> sd;       // 24 bits
    friend bool operator==(const Snssai&, const Snssai&) = default;
};
struct SetupComplete {
    std::uint8_t tid = 0;
    std::uint8_t selected_plmn = 1;        // 1..12
    Bytes nas;
    std::optional<std::uint16_t> s_tmsi_part2;   // 9 bits, with a Part1 request
    // P3 R1 (TS 38.331 §5.3.3.4): the AMF the UE is registered with (AMF Region ID,
    // Set ID and Pointer, 24 bits, from its 5G-GUTI) and the NSSAI it asked for, so
    // the gNB can select the AMF (NNSF).
    std::optional<std::uint32_t> registered_amf;
    std::vector<Snssai> nssai;             // up to 8
    friend bool operator==(const SetupComplete&, const SetupComplete&) = default;
};
struct ReestablishmentComplete {
    std::uint8_t tid = 0;
    friend bool operator==(const ReestablishmentComplete&, const ReestablishmentComplete&) = default;
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
                            CapabilityInformation, UlInformationTransfer, ReestablishmentComplete>;
Result<Bytes> encode(const SetupComplete& m);
Result<Bytes> encode(const SecurityModeComplete& m);
Result<Bytes> encode(const SecurityModeFailure& m);
Result<Bytes> encode(const ReconfigurationComplete& m);
Result<Bytes> encode(const CapabilityInformation& m);
Result<Bytes> encode(const UlInformationTransfer& m);
Result<Bytes> encode(const ReestablishmentComplete& m);
Result<UlDcch> decode_ul_dcch(ByteView in);

// ---- inter-node containers (TS 38.331 §11.2.2) ------------------------------------------

/// HandoverPreparationInformation: what a source gives a target (in F1AP's
/// CU-to-DU RRC Information, XnAP's and NGAP's source-to-target containers).
struct HandoverPreparation {
    Bytes nr_capability;                   // UE-NR-Capability, as the UE sent it
    std::optional<Reconfiguration> source; // AS-Config's rrcReconfiguration (the UE's current configuration)
    // AS-Context's reestablishmentInfo: the source PCI and the target cell's shortMAC-I.
    std::optional<std::pair<std::uint16_t, std::uint16_t>> reestablishment;
    friend bool operator==(const HandoverPreparation&, const HandoverPreparation&) = default;
};
Result<Bytes> encode(const HandoverPreparation& m);
Result<HandoverPreparation> decode_handover_preparation(ByteView in);
/// HandoverCommand: the target's RRCReconfiguration back to the source.
Result<Bytes> encode_handover_command(const Reconfiguration& m);
Result<Reconfiguration> decode_handover_command(ByteView in);

// ---- capabilities ------------------------------------------------------------------------

/// A minimal UE-NR-Capability for the generic persona (N15 brings real ones):
/// Rel-15, no ROHC, band n78.
Result<Bytes> generic_nr_capability();

/// The served cell's SSB as its MeasurementTimingConfiguration describes it
/// (TS 38.331 §11.2.2 MeasTiming, SSB-MTC). P2 Q4 (KS-F1AP-D2): P1 sent no
/// measTiming, which a CU-CP (OCUDU's) refuses. The defaults are our n78 cell:
/// the SSB on the sync raster next to the carrier (NR-ARFCN 632640, 3489.6 MHz,
/// GSCN 7839, TS 38.104 Table 5.4.3.1-1), 30 kHz, every 20 ms (the period a UE
/// assumes at initial access, TS 38.213 §4.1), a 5-subframe window from
/// subframe 0 (a burst lies in one half frame, TS 38.213 §4.1).
struct SsbTiming {
    std::uint32_t ssb_arfcn = 632640;   // carrierFreq
    std::uint16_t scs_khz = 30;         // ssbSubcarrierSpacing: 15, 30, 120, 240
    std::uint16_t period_ms = 20;       // 5, 10, 20, 40, 80, 160
    std::uint8_t offset = 0;            // subframes, below the period
    std::uint8_t duration = 5;          // subframes, 1..5
    std::optional<std::uint16_t> pci;   // physCellId (the r15 extension)
};

/// A MeasurementTimingConfiguration with one measTiming for `s`: what F1
/// Setup's served cell carries (TS 38.473 §9.3.1.10).
Result<Bytes> measurement_timing_configuration(const SsbTiming& s = {});

/// UERadioAccessCapabilityInformation (TS 38.331 §11.2.2) around an NR
/// capability: what NGAP's UE Radio Capability IE carries (TS 38.413 §9.3.1.74).
Result<Bytes> radio_access_capability(const Bytes& nr_capability);
/// The UE-NR-Capability inside a UERadioAccessCapabilityInformation, if any.
Result<Bytes> nr_capability_of(ByteView radio_access_capability);

/// The message's JER (X.697 JSON) for logs and the oracle: `channel` is
/// "BCCH-BCH", "BCCH-DL-SCH", "PCCH", "UL-CCCH", "DL-CCCH", "DL-DCCH",
/// "UL-DCCH", "CellGroupConfig", "UE-NR-Capability", and from P3 R1
/// "RRCReconfiguration", "HandoverPreparationInformation" or "HandoverCommand".
Result<std::string> to_jer(std::string_view channel, ByteView in);

} // namespace ksim::rrc
