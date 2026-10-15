// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The core stub's AMF, NAS side (P1 N5, ADR 0009 point f): it runs the
// network half of registration, 5G AKA, security mode control and UE
// de-registration for one UE at a time, as a profile tells it to (N10: and
// carries 5GSM between the UE and the stub's SMF in UL and DL NAS TRANSPORT,
// a session's accept going in a PDU SESSION RESOURCE SETUP REQUEST; N12: keeps
// the UE's context across N1 connections, takes the protected initial message
// of a UE that holds one (§4.4.6, the container deciphered), accepts a
// registration it verifies without a new authentication, releases a UE after
// its periodic registration, answers a SERVICE REQUEST with an INITIAL CONTEXT
// SETUP that brings the sessions back, and de-registers a UE from the network
// side when a test asks), and checks
// every uplink message against the spec: the mandatory IEs, the protection
// it must carry, the uplink NAS COUNT, the MAC, and what each procedure
// requires of its content. Each check is recorded with its clause as a
// verdict; a procedure test passes only with no failed verdict.
//
// It judges procedures, not encodings: it uses kaluza-sim's own codecs and
// crypto, so encodings are judged elsewhere (tshark and pycrate on every run
// pcap, and the two real cores; row KS-NAS-B3).

#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "codec/nas/ie/ie.hpp"
#include "codec/nas/nas.hpp"
#include "home.hpp"
#include "smf.hpp"
#include "verdict.hpp"
#include "platform/executor.hpp"
#include "platform/yaml.hpp"
#include "proc/ue/nas_sec/nas_sec.hpp"

namespace ksim::corestub {

/// What the stub does at each step. Built in code by the tests, or read from
/// tests/corestub/profiles/*.yaml.
struct Profile {
    // none: no further challenge after a failure (the UE's T3520 then runs out)
    enum class Challenge : std::uint8_t { ok, bad_mac, stale_sqn, non_5g, lose_response, reject, none };
    std::vector<Challenge> challenges{Challenge::ok};   // one per challenge; the last repeats
    std::uint8_t ea = 2;
    std::uint8_t ia = 2;
    bool imeisv_request = true;
    bool rinmr = false;
    bool tamper_replayed_capabilities = false;
    enum class Registration : std::uint8_t { accept, reject, silent, accept_plain };
    Registration registration = Registration::accept;
    std::uint8_t reject_cause = 0;
    bool reject_unprotected = false;           // the reject at once, before authentication (§5.3.20)
    std::optional<std::uint8_t> rejected_sst;  // a Rejected NSSAI entry with the reject (#62)
    std::optional<int> t3346_s;              // T3346 value in a #22 reject (N12)
    std::uint8_t service_reject_cause = 0;   // a SERVICE REQUEST rejected with this cause (N12)
    bool silent_service_request = false;     // a SERVICE REQUEST left unanswered (T3517)
    std::uint32_t tmsi = 0x00000001;
    std::uint8_t amf_region = 0xCA;
    std::uint16_t amf_set = 1;
    std::uint8_t amf_pointer = 1;
    std::vector<std::uint32_t> tacs{1};
    std::vector<std::uint8_t> allowed_sst{1};
    std::optional<int> t3512_s = 3600;
    std::optional<int> t3502_s;
    enum class Deregistration : std::uint8_t { accept, silent };
    Deregistration deregistration = Deregistration::accept;
    bool reauthenticate = false;   // a registration that verifies is authenticated anyway
    // N18: the UE's context and 5G-GUTI go at its de-registration, as a real AMF
    // may (kaluza-core does); a 5G-GUTI the AMF does not know then gets an
    // IDENTITY REQUEST for the SUCI, plain (§5.4.3, §4.4.4.2), and a new authentication.
    bool forget_on_deregistration = false;
    // EAP-AKA' instead of 5G AKA (TS 33.501 6.1.3.1; the challenge kinds apply as
    // for 5G AKA). The two faults touch the first challenge only.
    bool eap_aka_prime = false;
    std::string eap_network_name;      // AT_KDF_INPUT other than the serving network name
    bool eap_bad_at_mac = false;       // AT_MAC corrupted: the UE answers with a client error
    std::uint16_t eap_kdf = 1;         // the first challenge's AT_KDF (not 1: an incorrect AUTN to the UE)
    bool eap_result_message = false;   // EAP-success in an AUTHENTICATION RESULT before the SMC
    bool sms_subscribed = true;               // N13: SMS over NAS for a UE that asks (§5.5.1.2.4)
    std::string sms_sc = "99900000";          // the SC's address digits (cards/usim-5g.yaml EF.SMSP)
    SessionProfile session;   // the SMF's (N10)

    /// Reads a profile; unknown keys are an error (YamlError with the path).
    static Profile from_yaml(const Yaml& y);
};

class Amf {
public:
    struct Link {
        std::function<void(Bytes)> to_ue;       // a downlink NAS PDU
        std::function<void()> release;          // the network releases the N1 connection
        /// With NGAP below: the REGISTRATION ACCEPT goes in an INITIAL CONTEXT
        /// SETUP REQUEST with K_gNB, instead of to_ue.
        std::function<void(Bytes accept, SecretBytes kgnb)> initial_context;
        /// With NGAP below: a DL NAS TRANSPORT that goes with a session's
        /// resource setup or release, instead of to_ue.
        std::function<void(Bytes nas, ngap::SessionSetupItem item)> session_setup;
        std::function<void(Bytes nas, std::uint8_t psi)> session_release;
        /// N12: the SERVICE ACCEPT in an INITIAL CONTEXT SETUP REQUEST with K_gNB
        /// and the sessions (bit n for PSI n) whose user plane comes back.
        std::function<void(Bytes accept, SecretBytes kgnb, std::uint16_t psis)> service_accept;
        /// N13: the UE's SMS CP messages to the SMSF; whether its subscription has SMS.
        std::function<void(Bytes cp)> sms_uplink;
        std::function<bool()> sms_subscribed;
    };

    Amf(Executor& ex, Home& home, nas::ie::Plmn plmn, Profile p);
    ~Amf();
    Amf(const Amf&) = delete;
    Amf& operator=(const Amf&) = delete;

    void attach(Link link) { link_ = std::move(link); }
    /// The SMF behind this AMF; without one, UL NAS TRANSPORT fails its check.
    void attach_smf(Smf* smf) { smf_ = smf; }
    /// Network-requested release and modification of a session (TS 24.501 §6.3.3, §6.3.2).
    bool release_session(std::uint8_t psi, std::uint8_t cause);
    bool modify_session(std::uint8_t psi, std::uint32_t ambr_mbps);
    /// Network-initiated de-registration (§5.5.2.3.1) of a registered, connected UE.
    /// With a 5GMM cause when not 0 (§5.5.2.3.1). Also while a UE de-registration
    /// waits unanswered (Deregistration::silent), for the collision of §5.5.2.2.6 d.
    bool network_deregister(bool reregistration_required, std::uint8_t cause = 0);
    /// N13: a DL NAS TRANSPORT with an SMS CP message; false unless registered and connected.
    bool send_sms(Bytes cp);
    /// Whether this context is the UE's that `id` (a 5G-GUTI) or `s_tmsi` names.
    bool owns(const nas::ie::MobileIdentity& id) const;
    bool owns_s_tmsi(std::uint64_t s_tmsi) const;
    bool connected() const noexcept { return connected_; }
    std::optional<std::uint64_t> s_tmsi() const;
    int service_requests() const noexcept { return service_requests_; }
    Profile& profile() noexcept { return p_; }

    void on_uplink(ByteView wire, bool initial);
    /// The UE released the N1 connection locally.
    void on_ue_released();

    /// Downlink as a test scripts it: a plain message as is, or protected with
    /// the current context.
    void send_plain(Bytes plain);
    void send_protected(Bytes plain);

    const std::vector<Verdict>& verdicts() const noexcept { return verdicts_; }
    std::vector<Verdict> failures() const;
    /// The uplink messages by name, in order ("REGISTRATION REQUEST", …).
    const std::vector<std::string>& uplink() const noexcept { return uplink_; }
    std::size_t count_uplink(std::string_view name) const;
    std::size_t identity_requests() const noexcept { return identity_requests_; }
    /// The last REGISTRATION REQUEST: whole when it came in a container (N15), else as received.
    const nas::Message* last_registration_request() const noexcept {
        return full_request_ ? &*full_request_ : (initial_.desc != nullptr ? &initial_ : nullptr);
    }
    int challenges() const noexcept { return challenges_; }
    int resyncs() const noexcept { return resyncs_; }
    bool registered() const noexcept { return state_ == State::registered; }
    const std::string& supi() const noexcept { return supi_; }
    std::optional<std::uint32_t> last_ul_count() const noexcept { return last_ul_; }
    const proc::ue::NasSecurityContext* security() const noexcept { return ctx_ ? &*ctx_ : nullptr; }
    /// The UE security capability of its REGISTRATION REQUEST.
    const std::optional<nas::ie::UeSecurityCapability>& ue_capabilities() const noexcept { return ue_caps_; }
    /// K_gNB as TS 33.501 6.8.1.2.2 has it: K_AMF and the SECURITY MODE COMPLETE's uplink COUNT.
    Result<SecretBytes> kgnb() const;

private:
    enum class State : std::uint8_t { idle, identifying, authenticating, securing, accepting, registered, released, deregistering };

    void check(bool ok, const char* clause, const char* what, std::string detail = {});
    void on_message(const nas::Message& m, proc::ue::Sht sht, bool initial, bool verified = false);
    void on_registration_request(const nas::Message& m, bool initial, proc::ue::Sht sht, bool verified);
    void on_service_request(const nas::Message& m, bool initial, bool verified);
    void start_challenge();
    void on_authentication_response(const nas::Message& m);
    void on_identity_response(const nas::Message& m);
public:
    /// A plain IDENTITY REQUEST for the SUCI, now (a test of §4.4.4.2).
    void send_plain_identity_request();
private:
    void forget_if_asked();
    void on_authentication_failure(const nas::Message& m);
    Result<Bytes> eap_challenge(const std::string& snn);
    void on_eap_response(const nas::Message& m);
    void send_security_mode_command();
    void on_security_mode_complete(const nas::Message& m, proc::ue::Sht sht);
    void on_security_mode_reject(const nas::Message& m);
    void send_registration_result();
    void on_deregistration_request(const nas::Message& m);
    void on_ul_nas_transport(const nas::Message& m, proc::ue::Sht sht);
    void sm_actions(std::vector<SmAction> actions);
    Bytes dl_nas_transport(std::uint8_t psi, Bytes sm, std::optional<std::uint8_t> mm_cause);
    Profile::Challenge challenge_kind() const;
    void send(const nas::Message& m, bool protect);
    void downlink(Bytes wire);
    void downlink_protected(Bytes wire);
    void release();
    void start_t3560();
    void stop_t3560();

    Executor& ex_;
    Home& home_;
    nas::ie::Plmn plmn_;
    Profile p_;
    Link link_;
    Smf* smf_ = nullptr;
    std::shared_ptr<bool> alive_;

    State state_ = State::idle;
    std::string supi_;
    std::optional<nas::ie::MobileIdentity> guti_;   // the one assigned
    std::string guti_supi_;                         // and whose it is
    nas::Message initial_;                          // the REGISTRATION REQUEST as received
    std::optional<nas::Message> full_request_;      // and whole, from the SECURITY MODE COMPLETE's container
    bool initial_protected_ = false;                // it came integrity protected (§4.4.6 b)
    bool rinmr_sent_ = false;                       // the SMC asked for it again (§5.4.2.2)
    std::size_t identity_requests_ = 0;
    bool initial_had_context_ = false;
    std::optional<nas::ie::UeSecurityCapability> ue_caps_;
    std::uint8_t next_ngksi_ = 1;
    nas::ie::NgKsi ngksi_;
    std::optional<Av> av_;
    std::optional<Profile::Challenge> av_kind_;
    std::optional<proc::ue::NasSecurityContext> ctx_;
    std::optional<std::uint32_t> last_ul_;
    bool imeisv_asked_ = false;
    std::optional<std::uint32_t> smc_count_;
    Bytes pending_;            // the message T3560 retransmits
    bool pending_plain_ = true;
    int t3560_expiries_ = 0;
    std::optional<TimerId> t3560_;
    int challenges_ = 0;
    int resyncs_ = 0;
    bool lost_one_ = false;
    // N12
    bool connected_ = false;
    std::uint8_t reg_type_ = 1;
    std::uint8_t eap_id_ = 0;      // the last EAP-request's identifier
    bool eap_fault_ = false;       // the last challenge carried a profile fault
    std::uint16_t reg_uplink_ = 0;   // the REGISTRATION REQUEST's Uplink data status
    bool sms_requested_ = false;     // N13: the 5GS update type's SMS requested
    std::uint16_t reg_up_ = 0;       // the sessions whose user plane the accept brought back
    std::optional<std::uint32_t> initial_count_;   // the COUNT of a verified initial message
    int service_requests_ = 0;

    std::vector<Verdict> verdicts_;
    std::vector<std::string> uplink_;
};

} // namespace ksim::corestub
