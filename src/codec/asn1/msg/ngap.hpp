// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Typed builders and readers for the NGAP core set of P1 (P1 N7; TS 38.413
// j40 §8, §9; ADR 0009 point h), built like the RRC ones (msg/rrc.hpp): a
// plain struct, its inputs checked, the value built as JER and encoded by
// the generated code as APER; readers decode APER and read the IEs P1
// interprets. peek() reads a PDU's procedure, class, criticality and UE IDs
// even when the rest does not decode, for the error handling of §10.
//
// The INITIAL CONTEXT SETUP REQUEST carries K_gNB (Security Key). The codec
// layer holds no SecretBytes (rule R3), so the key crosses it as octets: the
// caller moves it into SecretBytes at once and wipes the copy; the codec
// wipes the JER text it built or read (row KS-NGAP-B2).

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "platform/buf.hpp"
#include "platform/result.hpp"

namespace ksim::ngap {

using PlmnId = std::array<std::uint8_t, 3>;   // TS 24.008 coding (TS 38.413 §9.3.3.5)

/// "001", "01" -> 00 F1 10.
PlmnId plmn_id(std::string_view mcc, std::string_view mnc);

struct Snssai {
    std::uint8_t sst = 1;
    std::optional<std::uint32_t> sd;
    friend bool operator==(const Snssai&, const Snssai&) = default;
};

struct Tai {
    PlmnId plmn{};
    std::uint32_t tac = 0;   // 24 bits
    friend bool operator==(const Tai&, const Tai&) = default;
};

struct NrCgi {
    PlmnId plmn{};
    std::uint64_t nci = 0;   // 36 bits
    friend bool operator==(const NrCgi&, const NrCgi&) = default;
};

struct Guami {
    PlmnId plmn{};
    std::uint8_t region = 0;
    std::uint16_t set = 0;      // 10 bits
    std::uint8_t pointer = 0;   // 6 bits
    friend bool operator==(const Guami&, const Guami&) = default;
};

struct FiveGSTmsi {
    std::uint16_t set = 0;      // 10 bits
    std::uint8_t pointer = 0;   // 6 bits
    std::uint32_t tmsi = 0;
    std::uint64_t value() const noexcept {
        return (std::uint64_t{set} << 38) | (std::uint64_t{pointer} << 32) | tmsi;
    }
    static FiveGSTmsi of(std::uint64_t v) noexcept {
        return {static_cast<std::uint16_t>((v >> 38) & 0x3FF), static_cast<std::uint8_t>((v >> 32) & 0x3F),
                static_cast<std::uint32_t>(v)};
    }
    friend bool operator==(const FiveGSTmsi&, const FiveGSTmsi&) = default;
};

/// §9.3.1.2: the group and the value's ASN.1 name, e.g. radioNetwork /
/// "user-inactivity".
struct Cause {
    std::string group = "misc";      // radioNetwork, transport, nas, protocol, misc
    std::string value = "unspecified";
    friend bool operator==(const Cause&, const Cause&) = default;
};

struct PlmnSlices {
    PlmnId plmn{};
    std::vector<Snssai> slices;
    friend bool operator==(const PlmnSlices&, const PlmnSlices&) = default;
};

struct UeIds {
    std::optional<std::uint64_t> amf;   // AMF UE NGAP ID, 0..2^40-1
    std::optional<std::uint32_t> ran;   // RAN UE NGAP ID
    friend bool operator==(const UeIds&, const UeIds&) = default;
};

// ---- non-UE-associated -----------------------------------------------------------

struct NgSetupRequest {
    PlmnId plmn{};
    std::uint32_t gnb_id = 0;
    std::uint8_t gnb_id_bits = 22;   // 22..32
    std::string name;                // RANNodeName, optional
    struct Ta {
        std::uint32_t tac = 0;
        std::vector<PlmnSlices> plmns;
        friend bool operator==(const Ta&, const Ta&) = default;
    };
    std::vector<Ta> tas;
    std::string paging_drx = "v128";
    friend bool operator==(const NgSetupRequest&, const NgSetupRequest&) = default;
};
struct NgSetupResponse {
    std::string amf_name;
    std::vector<Guami> guamis;
    std::uint8_t capacity = 255;
    std::vector<PlmnSlices> plmns;
    friend bool operator==(const NgSetupResponse&, const NgSetupResponse&) = default;
};
struct NgSetupFailure {
    Cause cause;
    std::optional<std::string> time_to_wait;   // v1s, v2s, v5s, v10s, v20s, v60s
    friend bool operator==(const NgSetupFailure&, const NgSetupFailure&) = default;
};
struct NgReset {
    Cause cause;
    bool all = true;                   // nG-Interface, else partOfNG-Interface
    std::vector<UeIds> connections;
    friend bool operator==(const NgReset&, const NgReset&) = default;
};
struct NgResetAcknowledge {
    std::vector<UeIds> connections;
    friend bool operator==(const NgResetAcknowledge&, const NgResetAcknowledge&) = default;
};
struct ErrorIndication {
    UeIds ids;
    std::optional<Cause> cause;
    friend bool operator==(const ErrorIndication&, const ErrorIndication&) = default;
};
struct AmfStatusIndication {
    std::vector<Guami> unavailable;
    friend bool operator==(const AmfStatusIndication&, const AmfStatusIndication&) = default;
};
struct AmfConfigurationUpdate {
    std::optional<std::string> amf_name;
    friend bool operator==(const AmfConfigurationUpdate&, const AmfConfigurationUpdate&) = default;
};
struct AmfConfigurationUpdateAcknowledge {
    friend bool operator==(const AmfConfigurationUpdateAcknowledge&, const AmfConfigurationUpdateAcknowledge&) = default;
};
struct Paging {
    FiveGSTmsi s_tmsi;
    std::vector<Tai> tais;
    std::optional<std::string> drx;
    friend bool operator==(const Paging&, const Paging&) = default;
};

// ---- PDU sessions (P1 N10; TS 38.413 9.3.4) ----------------------------------------

/// UP Transport Layer Information: an IPv4 GTP-U tunnel end (P1 has no IPv6 transport).
struct GtpTunnel {
    std::array<std::uint8_t, 4> addr{};
    std::uint32_t teid = 0;
    friend bool operator==(const GtpTunnel&, const GtpTunnel&) = default;
};
struct Arp {
    std::uint8_t priority = 8;     // 1..15
    bool may_preempt = false;      // pre-emptionCapability may-trigger-pre-emption
    bool preemptable = true;       // pre-emptionVulnerability pre-emptable
    friend bool operator==(const Arp&, const Arp&) = default;
};
/// A non-GBR flow with a standardised 5QI (GBR and dynamic 5QIs are not P1's).
struct QosFlowRequest {
    std::uint8_t qfi = 1;
    std::uint16_t five_qi = 9;
    Arp arp;
    friend bool operator==(const QosFlowRequest&, const QosFlowRequest&) = default;
};
struct Ambr {
    std::uint64_t dl = 0;   // bit/s
    std::uint64_t ul = 0;
    friend bool operator==(const Ambr&, const Ambr&) = default;
};
/// "required", "preferred" or "not-needed" (9.3.1.27).
struct SecurityIndication {
    std::string integrity = "not-needed";
    std::string confidentiality = "not-needed";
    // P2 Q9 (9.3.1.27): "bitrate64kbs" or "maximum-UE-rate"; UL present when integrity is
    // required or preferred (the encoder then puts maximum-UE-rate when none is given),
    // DL in the IE's extension (id 151).
    std::optional<std::string> max_rate_ul;
    std::optional<std::string> max_rate_dl;
    friend bool operator==(const SecurityIndication&, const SecurityIndication&) = default;
};
struct SecurityResult {
    bool integrity = false;         // performed
    bool confidentiality = false;
    friend bool operator==(const SecurityResult&, const SecurityResult&) = default;
};
struct SetupRequestTransfer {
    std::optional<Ambr> session_ambr;
    GtpTunnel ul;                    // the UPF's N3 end
    std::string type = "ipv4";       // PDUSessionType
    std::optional<SecurityIndication> security;
    std::vector<QosFlowRequest> flows;
    friend bool operator==(const SetupRequestTransfer&, const SetupRequestTransfer&) = default;
};
struct SetupResponseTransfer {
    GtpTunnel dl;                    // the gNB's N3 end
    std::vector<std::uint8_t> qfis;  // the flows set up on it
    std::optional<SecurityResult> security;
    friend bool operator==(const SetupResponseTransfer&, const SetupResponseTransfer&) = default;
};
struct SessionSetupItem {
    std::uint8_t psi = 1;
    std::optional<Bytes> nas;        // the session's own NAS PDU (5GSM)
    Snssai snssai;
    SetupRequestTransfer transfer;
    friend bool operator==(const SessionSetupItem&, const SessionSetupItem&) = default;
};
struct SessionSetupOk {
    std::uint8_t psi = 1;
    SetupResponseTransfer transfer;
    friend bool operator==(const SessionSetupOk&, const SessionSetupOk&) = default;
};
/// A session with a cause: failed to set up or modify, or to be released.
struct SessionCause {
    std::uint8_t psi = 1;
    Cause cause;
    friend bool operator==(const SessionCause&, const SessionCause&) = default;
};
struct ModifyRequestTransfer {
    std::optional<Ambr> session_ambr;
    std::vector<QosFlowRequest> add_or_modify;
    std::vector<std::uint8_t> release;   // QFIs, with cause nas/normal-release
    friend bool operator==(const ModifyRequestTransfer&, const ModifyRequestTransfer&) = default;
};
struct ModifyResponseTransfer {
    std::vector<std::uint8_t> added_or_modified;   // QFIs
    friend bool operator==(const ModifyResponseTransfer&, const ModifyResponseTransfer&) = default;
};
struct SessionModifyItem {
    std::uint8_t psi = 1;
    std::optional<Bytes> nas;
    ModifyRequestTransfer transfer;
    friend bool operator==(const SessionModifyItem&, const SessionModifyItem&) = default;
};
struct SessionModifyOk {
    std::uint8_t psi = 1;
    ModifyResponseTransfer transfer;
    friend bool operator==(const SessionModifyOk&, const SessionModifyOk&) = default;
};

// ---- UE-associated ------------------------------------------------------------------

struct InitialUeMessage {
    std::uint32_t ran = 0;
    Bytes nas;
    NrCgi cgi;
    Tai tai;
    std::string cause = "mo-Signalling";   // RRCEstablishmentCause
    std::optional<FiveGSTmsi> s_tmsi;
    bool context_requested = true;
    friend bool operator==(const InitialUeMessage&, const InitialUeMessage&) = default;
};
struct DownlinkNasTransport {
    std::uint64_t amf = 0;
    std::uint32_t ran = 0;
    Bytes nas;
    friend bool operator==(const DownlinkNasTransport&, const DownlinkNasTransport&) = default;
};
struct UplinkNasTransport {
    std::uint64_t amf = 0;
    std::uint32_t ran = 0;
    Bytes nas;
    NrCgi cgi;
    Tai tai;
    friend bool operator==(const UplinkNasTransport&, const UplinkNasTransport&) = default;
};
struct NasNonDeliveryIndication {
    std::uint64_t amf = 0;
    std::uint32_t ran = 0;
    Bytes nas;
    Cause cause;
    friend bool operator==(const NasNonDeliveryIndication&, const NasNonDeliveryIndication&) = default;
};
struct InitialContextSetupRequest {
    std::uint64_t amf = 0;
    std::uint32_t ran = 0;
    Guami guami;
    std::vector<Snssai> allowed_nssai;
    std::uint16_t nr_enc = 0;      // 16-bit maps: bit 1 (MSB) 128-NEA1 … (TS 38.413 §9.3.1.86)
    std::uint16_t nr_int = 0;
    std::uint16_t eutra_enc = 0;
    std::uint16_t eutra_int = 0;
    Bytes security_key;            // K_gNB, 32 octets: the caller moves it into SecretBytes
    std::optional<Bytes> nas;
    std::optional<Bytes> ue_radio_capability;
    std::optional<std::uint64_t> masked_imeisv;
    std::vector<SessionSetupItem> sessions;   // PDUSessionResourceSetupListCxtReq
    std::optional<Ambr> ue_ambr;              // mandatory when sessions are set up (9.2.2.1)
    friend bool operator==(const InitialContextSetupRequest&, const InitialContextSetupRequest&) = default;
};
struct InitialContextSetupResponse {
    std::uint64_t amf = 0;
    std::uint32_t ran = 0;
    std::vector<SessionSetupOk> sessions;
    std::vector<SessionCause> failed;
    friend bool operator==(const InitialContextSetupResponse&, const InitialContextSetupResponse&) = default;
};
struct InitialContextSetupFailure {
    std::uint64_t amf = 0;
    std::uint32_t ran = 0;
    Cause cause;
    friend bool operator==(const InitialContextSetupFailure&, const InitialContextSetupFailure&) = default;
};
struct UeContextReleaseRequest {
    std::uint64_t amf = 0;
    std::uint32_t ran = 0;
    Cause cause;
    friend bool operator==(const UeContextReleaseRequest&, const UeContextReleaseRequest&) = default;
};
struct UeContextReleaseCommand {
    std::uint64_t amf = 0;
    std::optional<std::uint32_t> ran;   // the pair, or the AMF UE NGAP ID alone
    Cause cause;
    friend bool operator==(const UeContextReleaseCommand&, const UeContextReleaseCommand&) = default;
};
struct UeContextReleaseComplete {
    std::uint64_t amf = 0;
    std::uint32_t ran = 0;
    friend bool operator==(const UeContextReleaseComplete&, const UeContextReleaseComplete&) = default;
};
struct UeContextModificationRequest {
    std::uint64_t amf = 0;
    std::uint32_t ran = 0;
    std::optional<Bytes> security_key;
    friend bool operator==(const UeContextModificationRequest&, const UeContextModificationRequest&) = default;
};
struct UeContextModificationResponse {
    std::uint64_t amf = 0;
    std::uint32_t ran = 0;
    friend bool operator==(const UeContextModificationResponse&, const UeContextModificationResponse&) = default;
};
struct UeRadioCapabilityInfoIndication {
    std::uint64_t amf = 0;
    std::uint32_t ran = 0;
    Bytes capability;   // UERadioCapability: UERadioAccessCapabilityInformation (TS 38.331)
    friend bool operator==(const UeRadioCapabilityInfoIndication&, const UeRadioCapabilityInfoIndication&) = default;
};

struct PduSessionResourceSetupRequest {
    std::uint64_t amf = 0;
    std::uint32_t ran = 0;
    std::optional<Bytes> nas;
    std::vector<SessionSetupItem> sessions;
    std::optional<Ambr> ue_ambr;
    friend bool operator==(const PduSessionResourceSetupRequest&, const PduSessionResourceSetupRequest&) = default;
};
struct PduSessionResourceSetupResponse {
    std::uint64_t amf = 0;
    std::uint32_t ran = 0;
    std::vector<SessionSetupOk> sessions;
    std::vector<SessionCause> failed;
    friend bool operator==(const PduSessionResourceSetupResponse&, const PduSessionResourceSetupResponse&) = default;
};
struct PduSessionResourceReleaseCommand {
    std::uint64_t amf = 0;
    std::uint32_t ran = 0;
    std::optional<Bytes> nas;
    std::vector<SessionCause> sessions;
    friend bool operator==(const PduSessionResourceReleaseCommand&, const PduSessionResourceReleaseCommand&) = default;
};
struct PduSessionResourceReleaseResponse {
    std::uint64_t amf = 0;
    std::uint32_t ran = 0;
    std::vector<std::uint8_t> released;
    friend bool operator==(const PduSessionResourceReleaseResponse&, const PduSessionResourceReleaseResponse&) = default;
};
struct PduSessionResourceModifyRequest {
    std::uint64_t amf = 0;
    std::uint32_t ran = 0;
    std::vector<SessionModifyItem> sessions;
    friend bool operator==(const PduSessionResourceModifyRequest&, const PduSessionResourceModifyRequest&) = default;
};
struct PduSessionResourceModifyResponse {
    std::uint64_t amf = 0;
    std::uint32_t ran = 0;
    std::vector<SessionModifyOk> sessions;
    std::vector<SessionCause> failed;
    friend bool operator==(const PduSessionResourceModifyResponse&, const PduSessionResourceModifyResponse&) = default;
};

using Pdu = std::variant<NgSetupRequest, NgSetupResponse, NgSetupFailure, NgReset, NgResetAcknowledge,
                         ErrorIndication, AmfStatusIndication, AmfConfigurationUpdate, AmfConfigurationUpdateAcknowledge,
                         Paging, InitialUeMessage, DownlinkNasTransport, UplinkNasTransport, NasNonDeliveryIndication,
                         InitialContextSetupRequest, InitialContextSetupResponse, InitialContextSetupFailure,
                         UeContextReleaseRequest, UeContextReleaseCommand, UeContextReleaseComplete,
                         UeContextModificationRequest, UeContextModificationResponse, UeRadioCapabilityInfoIndication,
                         PduSessionResourceSetupRequest, PduSessionResourceSetupResponse, PduSessionResourceReleaseCommand,
                         PduSessionResourceReleaseResponse, PduSessionResourceModifyRequest, PduSessionResourceModifyResponse>;

Result<Bytes> encode(const Pdu& p);

/// What any NGAP PDU says about itself (§10).
struct Header {
    enum class Kind : std::uint8_t { initiating, successful, unsuccessful };
    Kind kind = Kind::initiating;
    std::uint8_t procedure = 0;
    bool reject = false;   // the procedure's criticality
    UeIds ids;             // AMF and RAN UE NGAP IDs, where the message has them
};
Result<Header> peek(ByteView in);
/// Errc::unsupported for a procedure outside the P1 set (peek() still reads it),
/// Errc::malformed for one P1 reads that lacks an IE it needs.
Result<Pdu> decode(ByteView in);

/// Any NGAP PDU with its key material zeroed, for captures (P1 N8): every
/// Security Key (TS 38.413 9.3.1.87) and Next Hop NH (9.3.1.88, in a Security
/// Context) anywhere in the PDU, found by walking the decoded value and
/// re-encoded. `keys` counts the values zeroed. A PDU that does not decode is
/// an error: the caller drops it from the capture.
struct Redacted {
    Bytes pdu;
    unsigned keys = 0;
};
Result<Redacted> redact_keys(ByteView in);

} // namespace ksim::ngap
