// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Typed NAS information elements (P1 N4; TS 24.501 j80 §9.11; closes KS-NAS-G1
// for P1). The generic codec (nas.hpp) frames a message into IEs and keeps
// each IE's contents as octets; these types read and write those contents for
// every IE that P1's procedures build or interpret. The others stay raw, each
// with its reason, in ie/p1_ies.tsv (tools/guards/check_nas_ies.py keeps the
// two in step).
//
// Every type has the same shape: `kRef` (its clause), a static decode() over
// the IE's contents (the value part: no IEI, no length; a type 1 IE's value in
// the low four bits of one octet) and encode() back to those contents. decode()
// refuses what the clause makes impossible (a length outside the table, a
// reserved value the clause says is not to be accepted) with Errc::malformed
// or Errc::out_of_range; what the clause says to read as another value is read
// so. What to do with an error (§7) is the entity's choice, not the codec's.

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "platform/buf.hpp"
#include "platform/result.hpp"

namespace ksim::nas::ie {

// ---- shared building blocks ---------------------------------------------------

/// A PLMN identity: MCC and MNC digits (TS 24.008 figure 10.5.154 octets 6-8;
/// TS 24.501 §9.11.3.4). Three octets.
struct Plmn {
    std::string mcc;   // 3 digits
    std::string mnc;   // 2 or 3 digits
    static Result<Plmn> decode(ByteView three);
    Bytes encode() const;
    friend bool operator==(const Plmn&, const Plmn&) = default;
};

struct Tai {
    Plmn plmn;
    std::uint32_t tac = 0;   // 24 bits
    friend bool operator==(const Tai&, const Tai&) = default;
};

/// Milliseconds for a GPRS timer unit and value; nullopt when deactivated.
using TimerMs = std::optional<std::int64_t>;

// ---- 9.11.2: common IEs -------------------------------------------------------------

/// §9.11.2.3 GPRS timer (TS 24.008 §10.5.7.3): units of 2 s, 1 min or 6 min.
struct GprsTimer {
    static constexpr std::string_view kRef = "9.11.2.3";
    std::uint8_t unit = 7;    // bits 8-6: 0 2 s, 1 1 min, 2 decihours, 7 deactivated
    std::uint8_t value = 0;   // bits 5-1
    TimerMs ms() const noexcept;
    static Result<GprsTimer> decode(ByteView v);
    Bytes encode() const;
};

/// §9.11.2.4 GPRS timer 2 (TS 24.008 §10.5.7.4): GPRS timer's coding in an LV.
struct GprsTimer2 {
    static constexpr std::string_view kRef = "9.11.2.4";
    GprsTimer timer;
    TimerMs ms() const noexcept { return timer.ms(); }
    static Result<GprsTimer2> decode(ByteView v);
    Bytes encode() const { return timer.encode(); }
};

/// §9.11.2.5 GPRS timer 3 (TS 24.008 §10.5.7.4a): units 10 min, 1 h, 10 h,
/// 2 s, 30 s, 1 min, 320 h; 7 is deactivated.
struct GprsTimer3 {
    static constexpr std::string_view kRef = "9.11.2.5";
    std::uint8_t unit = 7;
    std::uint8_t value = 0;
    TimerMs ms() const noexcept;
    static Result<GprsTimer3> decode(ByteView v);
    Bytes encode() const;
};

/// §9.11.2.8 S-NSSAI: SST, an optional SD, and the optional mapped HPLMN SST and SD.
struct Snssai {
    static constexpr std::string_view kRef = "9.11.2.8";
    std::uint8_t sst = 0;
    std::optional<std::uint32_t> sd;
    std::optional<std::uint8_t> mapped_sst;
    std::optional<std::uint32_t> mapped_sd;
    static Result<Snssai> decode(ByteView v);
    Bytes encode() const;
    friend bool operator==(const Snssai&, const Snssai&) = default;
};

/// §9.11.2.1B DNN: the APN's length-prefixed labels (TS 23.003 §9.1), as text "internet".
struct Dnn {
    static constexpr std::string_view kRef = "9.11.2.1B";
    std::string name;
    static Result<Dnn> decode(ByteView v);
    Result<Bytes> encode() const;
};

/// §9.11.2.1A Access type (type 1): 1 3GPP, 2 non-3GPP.
struct AccessType {
    static constexpr std::string_view kRef = "9.11.2.1A";
    std::uint8_t value = 1;
    static Result<AccessType> decode(ByteView v);
    Bytes encode() const { return {value}; }
};

/// §9.11.2.2 EAP message: the EAP packet (RFC 3748), read by the EAP-AKA' entity.
struct EapMessage {
    static constexpr std::string_view kRef = "9.11.2.2";
    Bytes packet;
    static Result<EapMessage> decode(ByteView v);
    Bytes encode() const { return packet; }
};

// ---- 9.11.3: 5GMM IEs -----------------------------------------------------------------

/// §9.11.3.1 5GMM capability: kept as octets with the bits P1 reads.
struct FiveGmmCapability {
    static constexpr std::string_view kRef = "9.11.3.1";
    Bytes octets;   // octet 3 onwards
    bool s1_mode() const noexcept { return !octets.empty() && (octets[0] & 0x01) != 0; }
    static Result<FiveGmmCapability> decode(ByteView v);
    Bytes encode() const { return octets; }
};

/// §9.11.3.2 5GMM cause and §9.11.4.2 5GSM cause: one octet (Annex A).
struct Cause {
    static constexpr std::string_view kRef = "9.11.3.2";
    std::uint8_t value = 0;
    static Result<Cause> decode(ByteView v);
    Bytes encode() const { return {value}; }
};

/// §9.11.3.3 5GS identity type (type 1).
struct IdentityType {
    static constexpr std::string_view kRef = "9.11.3.3";
    enum Value : std::uint8_t { suci = 1, guti = 2, imei = 3, s_tmsi = 4, imeisv = 5, mac = 6, eui64 = 7 };
    std::uint8_t value = suci;
    static Result<IdentityType> decode(ByteView v);
    Bytes encode() const { return {value}; }
};

/// §9.11.3.4 5GS mobile identity: SUCI (IMSI format), 5G-GUTI, IMEI, IMEISV,
/// 5G-S-TMSI or no identity. The SUCI scheme output stays octets (the null
/// scheme's is the MSIN in BCD); MAC address and EUI-64 are refused in P1.
struct MobileIdentity {
    static constexpr std::string_view kRef = "9.11.3.4";
    enum class Type : std::uint8_t { none = 0, suci = 1, guti = 2, imei = 3, s_tmsi = 4, imeisv = 5 };
    Type type = Type::none;
    // SUCI
    std::uint8_t supi_format = 0;          // 0 IMSI
    std::string routing_indicator = "0";   // 1-4 digits
    std::uint8_t protection_scheme = 0;    // 0 null, 1 profile A, 2 profile B
    std::uint8_t hn_key_id = 0;
    Bytes scheme_output;
    // SUCI and 5G-GUTI
    Plmn plmn;
    // 5G-GUTI and 5G-S-TMSI
    std::uint8_t amf_region = 0;
    std::uint16_t amf_set = 0;             // 10 bits
    std::uint8_t amf_pointer = 0;          // 6 bits
    std::uint32_t tmsi = 0;
    // IMEI and IMEISV
    std::string digits;

    /// The null-scheme SUCI's MSIN (its scheme output in BCD), or empty.
    std::string null_scheme_msin() const;
    static MobileIdentity null_suci(const Plmn& plmn, std::string_view msin, std::string_view routing_indicator = "0");
    static Result<MobileIdentity> decode(ByteView v);
    Result<Bytes> encode() const;
};

/// §9.11.3.5 5GS network feature support: kept as octets with the bits P1 reads.
struct NetworkFeatureSupport {
    static constexpr std::string_view kRef = "9.11.3.5";
    Bytes octets;
    bool ims_vops_3gpp() const noexcept { return !octets.empty() && (octets[0] & 0x01) != 0; }
    static Result<NetworkFeatureSupport> decode(ByteView v);
    Bytes encode() const { return octets; }
};

/// §9.11.3.6 5GS registration result.
struct RegistrationResult {
    static constexpr std::string_view kRef = "9.11.3.6";
    std::uint8_t access = 1;      // 1 3GPP, 2 non-3GPP, 3 both; unused values read as 3GPP
    bool sms_allowed = false;
    bool nssaa_to_be_performed = false;
    bool emergency_registered = false;
    bool disaster_roaming = false;
    static Result<RegistrationResult> decode(ByteView v);
    Bytes encode() const;
};

/// §9.11.3.7 5GS registration type (type 1).
struct RegistrationType {
    static constexpr std::string_view kRef = "9.11.3.7";
    enum Value : std::uint8_t { initial = 1, mobility = 2, periodic = 3, emergency = 4, snpn_onboarding = 5 };
    std::uint8_t value = initial;
    bool follow_on_request = false;
    static Result<RegistrationType> decode(ByteView v);
    Bytes encode() const;
};

/// §9.11.3.8 5GS tracking area identity: PLMN and TAC.
struct TaiIe {
    static constexpr std::string_view kRef = "9.11.3.8";
    Tai tai;
    static Result<TaiIe> decode(ByteView v);
    Bytes encode() const;
};

/// §9.11.3.9 5GS tracking area identity list: partial lists of the three types.
struct TaiList {
    static constexpr std::string_view kRef = "9.11.3.9";
    std::vector<Tai> tais;   // expanded (type 01 lists become their consecutive TACs)
    bool contains(const Tai& t) const;
    static Result<TaiList> decode(ByteView v);
    /// Encoded as type 00 partial lists, one per PLMN, up to 16 TACs each.
    Result<Bytes> encode() const;
};

/// §9.11.3.9A 5GS update type.
struct UpdateType {
    static constexpr std::string_view kRef = "9.11.3.9A";
    bool sms_requested = false;
    bool ng_ran_rcu = false;
    std::uint8_t pnb_ciot_5gs = 0;
    std::uint8_t pnb_ciot_eps = 0;
    static Result<UpdateType> decode(ByteView v);
    Bytes encode() const;
};

/// §9.11.3.10 ABBA: two or more octets (TS 33.501 §A.7.1).
struct Abba {
    static constexpr std::string_view kRef = "9.11.3.10";
    Bytes value;
    static Result<Abba> decode(ByteView v);
    Bytes encode() const { return value; }
};

/// §9.11.3.12 Additional 5G security information: RINMR and HDP.
struct Additional5gSecurityInformation {
    static constexpr std::string_view kRef = "9.11.3.12";
    bool rinmr = false;   // retransmission of the initial NAS message requested
    bool hdp = false;     // horizontal derivation parameter
    static Result<Additional5gSecurityInformation> decode(ByteView v);
    Bytes encode() const;
};

/// §9.11.3.44 PDU session status (also §9.11.3.13 allowed PDU session status,
/// §9.11.3.42 PDU session reactivation result, §9.11.3.57 uplink data status):
/// one bit per PSI 0..15.
struct PsiBitmap {
    static constexpr std::string_view kRef = "9.11.3.44";
    std::uint16_t psis = 0;   // bit n is PSI n
    bool has(unsigned psi) const noexcept { return psi < 16 && (psis & (1U << psi)) != 0; }
    void set(unsigned psi, bool on = true) noexcept;
    static Result<PsiBitmap> decode(ByteView v);
    Bytes encode() const;
};

/// §9.11.3.43 PDU session reactivation result error cause: (PSI, cause) pairs.
struct ReactivationErrorCause {
    static constexpr std::string_view kRef = "9.11.3.43";
    std::vector<std::pair<std::uint8_t, std::uint8_t>> entries;
    static Result<ReactivationErrorCause> decode(ByteView v);
    Bytes encode() const;
};

/// §9.11.3.14 Authentication failure parameter: AUTS (14 octets).
struct AuthenticationFailureParameter {
    static constexpr std::string_view kRef = "9.11.3.14";
    Bytes auts;
    static Result<AuthenticationFailureParameter> decode(ByteView v);
    Bytes encode() const { return auts; }
};

/// §9.11.3.15 Authentication parameter AUTN (16 octets).
struct Autn {
    static constexpr std::string_view kRef = "9.11.3.15";
    Bytes value;
    static Result<Autn> decode(ByteView v);
    Bytes encode() const { return value; }
};

/// §9.11.3.16 Authentication parameter RAND (16 octets).
struct Rand {
    static constexpr std::string_view kRef = "9.11.3.16";
    Bytes value;
    static Result<Rand> decode(ByteView v);
    Bytes encode() const { return value; }
};

/// §9.11.3.17 Authentication response parameter: RES* (16 octets).
struct AuthenticationResponseParameter {
    static constexpr std::string_view kRef = "9.11.3.17";
    Bytes res_star;
    static Result<AuthenticationResponseParameter> decode(ByteView v);
    Bytes encode() const { return res_star; }
};

/// §9.11.3.18 Configuration update indication (type 1): ACK and RED.
struct ConfigurationUpdateIndication {
    static constexpr std::string_view kRef = "9.11.3.18";
    bool ack_requested = false;
    bool registration_requested = false;
    static Result<ConfigurationUpdateIndication> decode(ByteView v);
    Bytes encode() const;
};

/// §9.11.3.20 De-registration type (type 1).
struct DeregistrationType {
    static constexpr std::string_view kRef = "9.11.3.20";
    bool switch_off = false;
    bool reregistration_required = false;   // network to UE only
    std::uint8_t access = 1;                // 1 3GPP, 2 non-3GPP, 3 both
    static Result<DeregistrationType> decode(ByteView v);
    Bytes encode() const;
};

/// §9.11.3.28 IMEISV request (type 1).
struct ImeisvRequest {
    static constexpr std::string_view kRef = "9.11.3.28";
    bool requested = false;
    static Result<ImeisvRequest> decode(ByteView v);
    Bytes encode() const { return {static_cast<std::uint8_t>(requested ? 1 : 0)}; }
};

/// §9.11.3.31 MICO indication (type 1): RAAI and SPRTI.
struct MicoIndication {
    static constexpr std::string_view kRef = "9.11.3.31";
    bool raai = false;
    bool sprti = false;
    static Result<MicoIndication> decode(ByteView v);
    Bytes encode() const;
};

/// §9.11.3.32 NAS key set identifier (type 1): TSC and the ngKSI value (7: no key).
struct NgKsi {
    static constexpr std::string_view kRef = "9.11.3.32";
    bool mapped = false;   // TSC: 0 native, 1 mapped
    std::uint8_t value = 7;
    bool none() const noexcept { return value == 7; }
    static Result<NgKsi> decode(ByteView v);
    Bytes encode() const;
    friend bool operator==(const NgKsi&, const NgKsi&) = default;
};

/// §9.11.3.33 NAS message container: a whole NAS message, plain or ciphered.
struct NasMessageContainer {
    static constexpr std::string_view kRef = "9.11.3.33";
    Bytes message;
    static Result<NasMessageContainer> decode(ByteView v);
    Bytes encode() const { return message; }
};

/// §9.11.3.34 NAS security algorithms: the ciphering and integrity algorithm ids.
struct NasSecurityAlgorithms {
    static constexpr std::string_view kRef = "9.11.3.34";
    std::uint8_t ciphering = 0;   // 0 5G-EA0, 1 128-5G-EA1, 2 128-5G-EA2, 3 128-5G-EA3
    std::uint8_t integrity = 0;   // 0 5G-IA0, 1 128-5G-IA1, 2 128-5G-IA2, 3 128-5G-IA3
    static Result<NasSecurityAlgorithms> decode(ByteView v);
    Bytes encode() const { return {static_cast<std::uint8_t>((ciphering << 4) | integrity)}; }
};

/// §9.11.3.36 Network slicing indication (type 1): NSSCI and DCNI.
struct NetworkSlicingIndication {
    static constexpr std::string_view kRef = "9.11.3.36";
    bool nssci = false;
    bool dcni = false;
    static Result<NetworkSlicingIndication> decode(ByteView v);
    Bytes encode() const;
};

/// §9.11.3.37 NSSAI: S-NSSAI values, each length-prefixed.
struct Nssai {
    static constexpr std::string_view kRef = "9.11.3.37";
    std::vector<Snssai> list;
    static Result<Nssai> decode(ByteView v);
    Result<Bytes> encode() const;
};

/// §9.11.3.39 Payload container: its octets; its type says what they are.
struct PayloadContainer {
    static constexpr std::string_view kRef = "9.11.3.39";
    Bytes octets;
    static Result<PayloadContainer> decode(ByteView v);
    Bytes encode() const { return octets; }
};

/// §9.11.3.40 Payload container type (type 1).
struct PayloadContainerType {
    static constexpr std::string_view kRef = "9.11.3.40";
    enum Value : std::uint8_t { n1_sm = 1, sms = 2, lpp = 3, sor = 4, ue_policy = 5, ue_parameters_update = 6,
                                location_services = 7, ciot_user_data = 8, multiple = 15 };
    std::uint8_t value = n1_sm;
    static Result<PayloadContainerType> decode(ByteView v);
    Bytes encode() const { return {value}; }
};

/// §9.11.3.41 PDU session identity 2: one octet (§9.4).
struct PduSessionIdentity2 {
    static constexpr std::string_view kRef = "9.11.3.41";
    std::uint8_t psi = 0;
    static Result<PduSessionIdentity2> decode(ByteView v);
    Bytes encode() const { return {psi}; }
};

/// §9.11.3.45 PLMN list: equivalent PLMNs, three octets each.
struct PlmnList {
    static constexpr std::string_view kRef = "9.11.3.45";
    std::vector<Plmn> plmns;
    static Result<PlmnList> decode(ByteView v);
    Bytes encode() const;
};

/// §9.11.3.46 Rejected NSSAI: rejected S-NSSAIs with their causes.
struct RejectedNssai {
    static constexpr std::string_view kRef = "9.11.3.46";
    struct Entry {
        std::uint8_t cause = 0;   // 0 not available in the current PLMN, 1 in the registration area, 2 NSSAA failed …
        std::uint8_t sst = 0;
        std::optional<std::uint32_t> sd;
    };
    std::vector<Entry> list;
    static Result<RejectedNssai> decode(ByteView v);
    Bytes encode() const;
};

/// §9.11.3.47 Request type (type 1).
struct RequestType {
    static constexpr std::string_view kRef = "9.11.3.47";
    enum Value : std::uint8_t { initial = 1, existing = 2, initial_emergency = 3, existing_emergency = 4,
                                modification = 5, ma_pdu = 6 };
    std::uint8_t value = initial;
    static Result<RequestType> decode(ByteView v);
    Bytes encode() const { return {value}; }
};

/// §9.11.3.48 S1 UE network capability: octets, built from the persona.
struct S1UeNetworkCapability {
    static constexpr std::string_view kRef = "9.11.3.48";
    Bytes octets;
    static Result<S1UeNetworkCapability> decode(ByteView v);
    Bytes encode() const { return octets; }
};

/// §9.11.3.50 Service type (type 1).
struct ServiceType {
    static constexpr std::string_view kRef = "9.11.3.50";
    enum Value : std::uint8_t { signalling = 0, data = 1, mobile_terminated = 2, emergency = 3,
                                emergency_fallback = 4, high_priority = 5, elevated_signalling = 6 };
    std::uint8_t value = signalling;
    static Result<ServiceType> decode(ByteView v);
    Bytes encode() const { return {value}; }
};

/// §9.11.3.50A SMS indication (type 1): SAI.
struct SmsIndication {
    static constexpr std::string_view kRef = "9.11.3.50A";
    bool available = false;
    static Result<SmsIndication> decode(ByteView v);
    Bytes encode() const { return {static_cast<std::uint8_t>(available ? 1 : 0)}; }
};

/// §9.11.3.54 UE security capability: 5G-EA and 5G-IA (and EEA, EIA) bitmaps.
struct UeSecurityCapability {
    static constexpr std::string_view kRef = "9.11.3.54";
    std::uint8_t ea = 0;    // bit 8 is 5G-EA0 … bit 1 5G-EA7
    std::uint8_t ia = 0;
    std::optional<std::uint8_t> eea;
    std::optional<std::uint8_t> eia;
    Bytes spare;            // octets 7 onwards, kept for the replayed-capability check
    bool supports_ea(unsigned n) const noexcept { return n < 8 && (ea & (0x80U >> n)) != 0; }
    bool supports_ia(unsigned n) const noexcept { return n < 8 && (ia & (0x80U >> n)) != 0; }
    static Result<UeSecurityCapability> decode(ByteView v);
    Bytes encode() const;
    friend bool operator==(const UeSecurityCapability&, const UeSecurityCapability&) = default;
};

/// §9.11.3.55 UE's usage setting: 0 voice centric, 1 data centric.
struct UsageSetting {
    static constexpr std::string_view kRef = "9.11.3.55";
    bool data_centric = true;
    static Result<UsageSetting> decode(ByteView v);
    Bytes encode() const { return {static_cast<std::uint8_t>(data_centric ? 1 : 0)}; }
};

/// §9.11.3.56 UE status: S1 mode reg and N1 mode reg.
struct UeStatus {
    static constexpr std::string_view kRef = "9.11.3.56";
    bool s1_registered = false;
    bool n1_registered = false;
    static Result<UeStatus> decode(ByteView v);
    Bytes encode() const;
};

/// §9.11.3.2A 5GS DRX parameters: 0 not specified, 1 T=32, 2 T=64, 3 T=128, 4 T=256.
struct DrxParameters {
    static constexpr std::string_view kRef = "9.11.3.2A";
    std::uint8_t value = 0;
    static Result<DrxParameters> decode(ByteView v);
    Bytes encode() const { return {value}; }
};

// ---- 9.11.4: 5GSM IEs -------------------------------------------------------------------

/// §9.11.4.1 5GSM capability: kept as octets with RqoS.
struct FiveGsmCapability {
    static constexpr std::string_view kRef = "9.11.4.1";
    Bytes octets;
    bool reflective_qos() const noexcept { return !octets.empty() && (octets[0] & 0x01) != 0; }
    static Result<FiveGsmCapability> decode(ByteView v);
    Bytes encode() const { return octets; }
};

/// §9.11.4.5 Allowed SSC mode (type 1).
struct AllowedSscMode {
    static constexpr std::string_view kRef = "9.11.4.5";
    bool ssc1 = false;
    bool ssc2 = false;
    bool ssc3 = false;
    static Result<AllowedSscMode> decode(ByteView v);
    Bytes encode() const;
};

/// §9.11.4.7 Integrity protection maximum data rate, uplink and downlink:
/// 0x00 64 kbps, 0x01 NULL, 0xFF full data rate.
struct IntegrityProtectionMaxDataRate {
    static constexpr std::string_view kRef = "9.11.4.7";
    std::uint8_t ul = 0xFF;
    std::uint8_t dl = 0xFF;
    static Result<IntegrityProtectionMaxDataRate> decode(ByteView v);
    Bytes encode() const { return {ul, dl}; }
};

/// §9.11.4.9 Maximum number of supported packet filters: 17..1024 (11 bits).
struct MaxPacketFilters {
    static constexpr std::string_view kRef = "9.11.4.9";
    std::uint16_t value = 17;
    static Result<MaxPacketFilters> decode(ByteView v);
    Bytes encode() const;
};

/// §9.11.4.10 PDU address: the session type and the UE's address (IPv4, the
/// IPv6 interface identifier, or both), and the SMF's link-local address.
struct PduAddress {
    static constexpr std::string_view kRef = "9.11.4.10";
    std::uint8_t type = 1;                      // 1 IPv4, 2 IPv6, 3 IPv4v6
    std::optional<std::array<std::uint8_t, 4>> ipv4;
    std::optional<std::array<std::uint8_t, 8>> ipv6_iid;
    std::optional<std::array<std::uint8_t, 16>> smf_ipv6_lla;
    std::string ipv4_text() const;
    static Result<PduAddress> decode(ByteView v);
    Bytes encode() const;
};

/// §9.11.4.11 PDU session type (type 1).
struct PduSessionType {
    static constexpr std::string_view kRef = "9.11.4.11";
    enum Value : std::uint8_t { ipv4 = 1, ipv6 = 2, ipv4v6 = 3, unstructured = 4, ethernet = 5 };
    std::uint8_t value = ipv4;
    static Result<PduSessionType> decode(ByteView v);
    Bytes encode() const { return {value}; }
};

/// §9.11.4.12 QoS flow descriptions.
struct QosFlowDescriptions {
    static constexpr std::string_view kRef = "9.11.4.12";
    struct Parameter {
        std::uint8_t id = 0;   // 1 5QI, 2 GFBR UL, 3 GFBR DL, 4 MFBR UL, 5 MFBR DL, 6 averaging window, 7 EBI
        Bytes contents;
    };
    struct Description {
        std::uint8_t qfi = 0;
        std::uint8_t operation = 1;   // 1 create, 2 delete, 3 modify
        bool e_bit = false;           // the parameter list is a replacement (modify) / is included (create)
        std::vector<Parameter> parameters;
        std::optional<std::uint8_t> five_qi() const;
    };
    std::vector<Description> list;
    static Result<QosFlowDescriptions> decode(ByteView v);
    Result<Bytes> encode() const;
};

/// §9.11.4.13 QoS rules.
struct QosRules {
    static constexpr std::string_view kRef = "9.11.4.13";
    struct Component {
        std::uint8_t type = 0;   // Table 9.11.4.13.1: 0x01 match-all, 0x10 IPv4 remote address, 0x30 protocol, …
        Bytes value;
    };
    struct PacketFilter {
        std::uint8_t direction = 3;   // 1 downlink only, 2 uplink only, 3 bidirectional
        std::uint8_t id = 0;
        std::vector<Component> components;
    };
    struct Rule {
        std::uint8_t id = 0;
        std::uint8_t operation = 1;   // 1 create, 2 delete, 3 add filters, 4 replace filters, 5 delete filters, 6 modify without filters
        bool default_rule = false;    // DQR
        std::vector<PacketFilter> filters;   // for operation 5: identifiers only
        std::optional<std::uint8_t> precedence;
        bool segregation = false;
        std::optional<std::uint8_t> qfi;
    };
    std::vector<Rule> list;
    static Result<QosRules> decode(ByteView v);
    Result<Bytes> encode() const;
};

/// §9.11.4.14 Session-AMBR: downlink and uplink, in bits per second.
struct SessionAmbr {
    static constexpr std::string_view kRef = "9.11.4.14";
    std::uint8_t dl_unit = 6;     // Table 9.11.4.14.1: 1 1 kbps … 6 1 Mbps … 11 1 Gbps …
    std::uint16_t dl_value = 0;
    std::uint8_t ul_unit = 6;
    std::uint16_t ul_value = 0;
    std::optional<std::uint64_t> dl_bps() const noexcept;
    std::optional<std::uint64_t> ul_bps() const noexcept;
    static Result<SessionAmbr> decode(ByteView v);
    Bytes encode() const;
};

/// §9.11.4.16 SSC mode (type 1).
struct SscMode {
    static constexpr std::string_view kRef = "9.11.4.16";
    std::uint8_t value = 1;
    static Result<SscMode> decode(ByteView v);
    Bytes encode() const { return {value}; }
};

/// §9.11.4.17 Re-attempt indicator: RATC and EPLMNC.
struct ReattemptIndicator {
    static constexpr std::string_view kRef = "9.11.4.17";
    bool ratc = false;     // re-attempt in S1 mode allowed (0) or not (1)
    bool eplmnc = false;   // re-attempt in an equivalent PLMN allowed (0) or not (1)
    static Result<ReattemptIndicator> decode(ByteView v);
    Bytes encode() const;
};

/// §9.11.4.21 5GSM congestion re-attempt indicator: ABO.
struct CongestionReattemptIndicator {
    static constexpr std::string_view kRef = "9.11.4.21";
    bool all_plmns = false;
    static Result<CongestionReattemptIndicator> decode(ByteView v);
    Bytes encode() const { return {static_cast<std::uint8_t>(all_plmns ? 1 : 0)}; }
};

/// The contents of the ePCO containers P1 uses (TS 24.008 §10.5.6.3A):
/// DNS server IPv4 address (000D, network to UE) and IPv4 link MTU (0010).
struct EpcoIpv4Dns {
    static constexpr std::string_view kRef = "9.11.4.6/000D";
    std::array<std::uint8_t, 4> address{};
    static Result<EpcoIpv4Dns> decode(ByteView v);
    Bytes encode() const { return Bytes(address.begin(), address.end()); }
};

struct EpcoIpv4LinkMtu {
    static constexpr std::string_view kRef = "9.11.4.6/0010";
    std::uint16_t mtu = 0;
    static Result<EpcoIpv4LinkMtu> decode(ByteView v);
    Bytes encode() const { return {static_cast<std::uint8_t>(mtu >> 8), static_cast<std::uint8_t>(mtu & 0xFF)}; }
};

} // namespace ksim::nas::ie
