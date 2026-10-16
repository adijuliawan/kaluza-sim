// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Typed builders and readers for the F1AP set of P1 (P1 N7; TS 38.473 j40
// §8, §9), built like the NGAP ones (msg/ngap.hpp): F1 Setup, the initial,
// downlink and uplink RRC message transfers, UE Context Setup, Modification,
// Release Request and Release, Paging and Error Indication. RRC containers
// travel as octets (CellGroupConfig, the UE capability list, PDCP PDUs of
// SRB1 and SRB2, CCCH messages of SRB0); their builders are msg/rrc.hpp's.

#pragma once

#include <type_traits>

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "platform/buf.hpp"
#include "platform/result.hpp"

namespace ksim::f1ap {

using PlmnId = std::array<std::uint8_t, 3>;

struct NrCgi {
    PlmnId plmn{};
    std::uint64_t nci = 0;   // 36 bits
    friend bool operator==(const NrCgi&, const NrCgi&) = default;
};

/// §9.3.1.2: the group (radioNetwork, transport, protocol, misc) and the value's name.
struct Cause {
    std::string group = "misc";
    std::string value = "unspecified";
    friend bool operator==(const Cause&, const Cause&) = default;
};

struct ServedCell {
    NrCgi cgi;
    std::uint16_t pci = 0;            // 0..1007
    std::uint32_t tac = 0;            // 5GS TAC, 24 bits
    std::vector<PlmnId> plmns;
    std::uint32_t arfcn = 0;          // NR-ARFCN
    std::uint16_t band = 78;          // TDD here; FDD is P2
    std::string scs = "scs30";
    std::string nrb = "nrb106";
    Bytes meas_timing;                // MeasurementTimingConfiguration (TS 38.331)
    Bytes mib;                        // gNB-DU System Information
    Bytes sib1;
    friend bool operator==(const ServedCell&, const ServedCell&) = default;
};

struct F1SetupRequest {
    std::uint8_t transaction = 0;
    std::uint64_t du_id = 0;          // 36 bits
    std::string du_name;
    std::vector<ServedCell> cells;
    friend bool operator==(const F1SetupRequest&, const F1SetupRequest&) = default;
};
struct F1SetupResponse {
    std::uint8_t transaction = 0;
    std::string cu_name;
    std::vector<NrCgi> activate;      // Cells to be Activated
    friend bool operator==(const F1SetupResponse&, const F1SetupResponse&) = default;
};
struct F1SetupFailure {
    std::uint8_t transaction = 0;
    Cause cause;
    std::optional<std::string> time_to_wait;   // v1s … v60s
    friend bool operator==(const F1SetupFailure&, const F1SetupFailure&) = default;
};
struct InitialUlRrcMessageTransfer {
    std::uint32_t du_ue = 0;
    NrCgi cgi;
    std::uint16_t c_rnti = 0;
    Bytes rrc;                        // the UL-CCCH message
    std::optional<Bytes> du_to_cu;    // CellGroupConfig
    std::uint8_t transaction = 0;
    friend bool operator==(const InitialUlRrcMessageTransfer&, const InitialUlRrcMessageTransfer&) = default;
};
struct DlRrcMessageTransfer {
    std::uint32_t cu_ue = 0;
    std::uint32_t du_ue = 0;
    std::uint8_t srb = 0;
    Bytes rrc;                        // a DL-CCCH message on SRB0, else a PDCP PDU
    friend bool operator==(const DlRrcMessageTransfer&, const DlRrcMessageTransfer&) = default;
};
struct UlRrcMessageTransfer {
    std::uint32_t cu_ue = 0;
    std::uint32_t du_ue = 0;
    std::uint8_t srb = 1;
    Bytes rrc;                        // a PDCP PDU
    friend bool operator==(const UlRrcMessageTransfer&, const UlRrcMessageTransfer&) = default;
};
// ---- DRBs (P1 N10): F1-U ends and the QoS of the flows a DRB carries ----------------

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
/// A non-GBR flow with a standardised 5QI and its ARP.
/// GBR QoS Flow Information (TS 38.473 9.3.1.46; P2 Q11): bit/s each way.
struct Gbr {
    std::uint64_t mfbr_dl = 0;
    std::uint64_t mfbr_ul = 0;
    std::uint64_t gfbr_dl = 0;
    std::uint64_t gfbr_ul = 0;
    friend bool operator==(const Gbr&, const Gbr&) = default;
};
struct Flow {
    std::uint8_t qfi = 1;
    std::uint16_t five_qi = 9;
    std::uint8_t arp_priority = 8;
    bool may_preempt = false;
    bool preemptable = true;
    std::optional<Gbr> gbr;    // P2 Q11
    bool reflective = false;   // reflective-QoS-Attribute subject-to (P2 Q11)
    friend bool operator==(const Flow&, const Flow&) = default;
};
struct DrbToSetup {
    std::uint8_t drb_id = 1;
    Snssai snssai;
    std::vector<Flow> flows;   // the DRB's own QoS is the first flow's
    GtpTunnel ul;              // the CU-UP's F1-U end
    // PDCP SN lengths, 12 or 18 (TS 38.473 9.3.1.y; DL mandatory in UE Context
    // Setup's DRB item; P2 Q4, KS-F1AP-D3: P1 sent neither).
    std::uint8_t dl_pdcp_sn_bits = 18;
    std::optional<std::uint8_t> ul_pdcp_sn_bits;
    friend bool operator==(const DrbToSetup&, const DrbToSetup&) = default;
};
struct DrbSetup {
    std::uint8_t drb_id = 1;
    std::optional<std::uint8_t> lcid;
    GtpTunnel dl;              // the DU's F1-U end
    friend bool operator==(const DrbSetup&, const DrbSetup&) = default;
};

struct UeContextSetupRequest {
    std::uint32_t cu_ue = 0;
    std::optional<std::uint32_t> du_ue;
    NrCgi spcell;
    std::uint8_t serv_cell_index = 0;
    std::optional<Bytes> ue_capability;   // UE-CapabilityRAT-ContainerList
    std::vector<std::uint8_t> srbs;       // SRBs to be set up
    std::vector<DrbToSetup> drbs;
    std::optional<Bytes> rrc;             // an RRC container (a PDCP PDU of SRB1)
    friend bool operator==(const UeContextSetupRequest&, const UeContextSetupRequest&) = default;
};
struct UeContextSetupResponse {
    std::uint32_t cu_ue = 0;
    std::uint32_t du_ue = 0;
    Bytes cell_group;                     // CellGroupConfig
    std::vector<std::pair<std::uint8_t, std::uint8_t>> srbs;   // (SRB ID, LCID) set up
    std::vector<DrbSetup> drbs;
    friend bool operator==(const UeContextSetupResponse&, const UeContextSetupResponse&) = default;
};
struct UeContextSetupFailure {
    std::uint32_t cu_ue = 0;
    std::optional<std::uint32_t> du_ue;
    Cause cause;
    friend bool operator==(const UeContextSetupFailure&, const UeContextSetupFailure&) = default;
};
struct UeContextModificationRequest {
    std::uint32_t cu_ue = 0;
    std::uint32_t du_ue = 0;
    std::vector<std::uint8_t> srbs;
    std::vector<DrbToSetup> drbs;
    std::vector<std::uint8_t> release_drbs;
    std::optional<Bytes> rrc;
    // P2 Q10: DRBs-ToBeModified (TS 38.473 9.2.2.7), a DRB's QoS flows changed; the UL
    // end stays the CU-UP's, the SN lengths as set up.
    std::vector<DrbToSetup> modify_drbs;
    friend bool operator==(const UeContextModificationRequest&, const UeContextModificationRequest&) = default;
};
struct UeContextModificationResponse {
    std::uint32_t cu_ue = 0;
    std::uint32_t du_ue = 0;
    std::optional<Bytes> cell_group;
    std::vector<DrbSetup> drbs;
    std::vector<DrbSetup> modified;   // P2 Q10: DRBs-Modified (the DU's F1-U DL end, unchanged)
    friend bool operator==(const UeContextModificationResponse&, const UeContextModificationResponse&) = default;
};
struct UeContextReleaseRequest {
    std::uint32_t cu_ue = 0;
    std::uint32_t du_ue = 0;
    Cause cause;
    friend bool operator==(const UeContextReleaseRequest&, const UeContextReleaseRequest&) = default;
};
struct UeContextReleaseCommand {
    std::uint32_t cu_ue = 0;
    std::uint32_t du_ue = 0;
    Cause cause;
    std::optional<Bytes> rrc;             // the RRCRelease, a PDCP PDU
    std::optional<std::uint8_t> srb;      // with the container
    friend bool operator==(const UeContextReleaseCommand&, const UeContextReleaseCommand&) = default;
};
struct UeContextReleaseComplete {
    std::uint32_t cu_ue = 0;
    std::uint32_t du_ue = 0;
    friend bool operator==(const UeContextReleaseComplete&, const UeContextReleaseComplete&) = default;
};
struct Paging {
    std::uint16_t ue_identity_index = 0;  // 5G-S-TMSI mod 1024 (TS 38.304 §7.1)
    std::uint64_t s_tmsi = 0;             // 48 bits
    std::vector<NrCgi> cells;
    std::optional<std::string> drx;
    friend bool operator==(const Paging&, const Paging&) = default;
};
struct ErrorIndication {
    std::uint8_t transaction = 0;
    std::optional<std::uint32_t> cu_ue;
    std::optional<std::uint32_t> du_ue;
    std::optional<Cause> cause;
    friend bool operator==(const ErrorIndication&, const ErrorIndication&) = default;
};

// P2 Q4 (TS 38.473 8.2.5, 8.3.4.3): the gNB-CU's cell (de)activation, which the
// DU answers, and the DU's refusal of a whole UE context modification. Of the
// update's other IEs (TNL associations, barring, protected E-UTRA resources,
// neighbour cells) none is read: the DU supports none, all "if supported".
struct GnbCuConfigurationUpdate {
    std::uint8_t transaction = 0;
    std::vector<NrCgi> activate;      // Cells to be Activated
    std::vector<NrCgi> deactivate;    // Cells to be Deactivated
    friend bool operator==(const GnbCuConfigurationUpdate&, const GnbCuConfigurationUpdate&) = default;
};
struct CellFailed {
    NrCgi cgi;
    Cause cause;
    friend bool operator==(const CellFailed&, const CellFailed&) = default;
};
struct GnbCuConfigurationUpdateAcknowledge {
    std::uint8_t transaction = 0;
    std::vector<CellFailed> failed;   // Cells Failed to be Activated
    friend bool operator==(const GnbCuConfigurationUpdateAcknowledge&, const GnbCuConfigurationUpdateAcknowledge&) = default;
};
struct GnbCuConfigurationUpdateFailure {
    std::uint8_t transaction = 0;
    Cause cause;
    std::optional<std::string> time_to_wait;
    friend bool operator==(const GnbCuConfigurationUpdateFailure&, const GnbCuConfigurationUpdateFailure&) = default;
};
struct UeContextModificationFailure {
    std::uint32_t cu_ue = 0;
    std::uint32_t du_ue = 0;
    Cause cause;
    friend bool operator==(const UeContextModificationFailure&, const UeContextModificationFailure&) = default;
};

using Pdu = std::variant<F1SetupRequest, F1SetupResponse, F1SetupFailure, InitialUlRrcMessageTransfer,
                         DlRrcMessageTransfer, UlRrcMessageTransfer, UeContextSetupRequest, UeContextSetupResponse,
                         UeContextSetupFailure, UeContextModificationRequest, UeContextModificationResponse,
                         UeContextReleaseRequest, UeContextReleaseCommand, UeContextReleaseComplete, Paging,
                         ErrorIndication, GnbCuConfigurationUpdate, GnbCuConfigurationUpdateAcknowledge,
                         GnbCuConfigurationUpdateFailure, UeContextModificationFailure>;

namespace detail {
template <class T>
std::optional<std::uint32_t> id_of(const T& v) {
    if constexpr (std::is_same_v<T, std::optional<std::uint32_t>>) {
        return v;
    } else {
        return static_cast<std::uint32_t>(v);
    }
}
} // namespace detail

/// The UE a PDU is about, by the gNB-CU (cu_ue_of) or gNB-DU (du_ue_of) side's UE F1AP ID, or none for a non-UE-associated
/// one (P2 Q2: TS 38.472 §7, a UE's signalling keeps one SCTP stream).
inline std::optional<std::uint32_t> cu_ue_of(const Pdu& p) {
    return std::visit(
        [](const auto& m) -> std::optional<std::uint32_t> {
            if constexpr (requires { m.cu_ue; }) {
                return detail::id_of(m.cu_ue);
            } else {
                return std::nullopt;
            }
        },
        p);
}
inline std::optional<std::uint32_t> du_ue_of(const Pdu& p) {
    return std::visit(
        [](const auto& m) -> std::optional<std::uint32_t> {
            if constexpr (requires { m.du_ue; }) {
                return detail::id_of(m.du_ue);
            } else {
                return std::nullopt;
            }
        },
        p);
}

Result<Bytes> encode(const Pdu& p);

struct Header {
    enum class Kind : std::uint8_t { initiating, successful, unsuccessful };
    Kind kind = Kind::initiating;
    std::uint8_t procedure = 0;
    bool reject = false;
    std::optional<std::uint32_t> cu_ue;
    std::optional<std::uint32_t> du_ue;
};
Result<Header> peek(ByteView in);
Result<Pdu> decode(ByteView in);

} // namespace ksim::f1ap
