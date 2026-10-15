// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The UE's 5GMM entity (P1 N5; TS 24.501 j80 §5): one UE's mobility management
// on its actor's executor. N5 covers
//
//  - initial registration with a null-scheme SUCI or the 5G-GUTI (§5.5.1.2),
//    with the abnormal cases of §5.5.1.2.7: T3510, T3511, T3502 and the
//    registration attempt counter;
//  - 5G AKA on the ME side (§5.4.1.3; TS 33.501 §6.1.3.2, Annex A): the card's
//    AUTHENTICATE, RES*, K_AUSF, K_SEAF and K_AMF, the separation bit (#26),
//    MAC and SQN failures (#20, #21 with AUTS), the stored RAND and RES*
//    (T3516), T3520 and the network failing the authentication check;
//  - the security mode control procedure (§5.4.2): the candidate context
//    checked before it is used, the replayed UE security capabilities (#23),
//    5G-IA0 refused (#24), the IMEISV, and the whole REGISTRATION REQUEST in
//    the NAS message container (RINMR, or a UE that had no context);
//  - REGISTRATION ACCEPT and COMPLETE, and the reject causes that end in a
//    state of their own (#3, #6, #7, #11, #12, #13, #15, #27); the forbidden
//    lists, T3346 and the rest are N12;
//  - UE-initiated de-registration, normal (T3521) and switch-off (§5.5.2.2);
//  - 5GMM STATUS both ways (§7).
//
// N10 adds the NAS transport of 5GSM (§5.4.5): UL NAS TRANSPORT with payload
// container type N1 SM, and DL NAS TRANSPORT handed to 5GSM with the PDU
// session ID, or with the 5GMM cause and back-off timer of a message the AMF
// could not forward.
//
// N12 adds:
//  - 5GMM-IDLE: the release of the N1 connection is an event, T3512 runs in
//    idle and its expiry starts a periodic registration (§5.3.7, §5.5.1.3);
//  - the protected initial message of a UE that holds a context (§4.4.6):
//    integrity protected, the whole message ciphered in a NAS message
//    container when it has non-cleartext IEs; K_gNB from its COUNT when no
//    SECURITY MODE COMMAND follows in that connection;
//  - the service request (§5.6.1) for uplink data, for paging, and for 5GSM
//    signalling queued while idle, under T3517; the accept's PDU session
//    status synchronises 5GSM; the reject causes that call for a new
//    registration;
//  - network-initiated de-registration (§5.5.2.3) with re-registration, the
//    configuration update (§5.4.4), identification (§5.4.3);
//  - registration rejects #22 (T3346) and the forbidden lists of #11, #12,
//    #13 and #15 (§5.5.1.2.5), which hold back a new registration;
//  - the USIM (TS 31.102 4.4.11; §4.4.2.1, §5.5.1.2.4): the 5G-GUTI, TAI and
//    update status in EF.5GS3GPPLOCI on every change; the native context in
//    EF.5GS3GPPNSC, marked invalid when an initial registration starts and
//    stored valid on entering 5GMM-DEREGISTERED, and K_AUSF and K_SEAF in
//    EF.5GAUTHKEYS; all read back at power on, which begins from the card
//    alone (nothing of the last power cycle stays in memory).

#pragma once

#include <array>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "codec/nas/ie/ie.hpp"
#include "codec/nas/nas.hpp"
#include "platform/coro.hpp"
#include "platform/event.hpp"
#include "platform/executor.hpp"
#include "platform/rng.hpp"
#include "platform/secret.hpp"
#include "proc/ue/nas_mm/ports.hpp"
#include "proc/ue/nas_mm/state.hpp"
#include "proc/ue/nas_sec/nas_sec.hpp"
#include "uicc/terminal/terminal.hpp"

namespace ksim::proc::ue {

/// The UE's 5GMM timers (§10.2, Table 10.2.2) the entity runs.
enum class MmTimer : std::uint8_t { t3502, t3510, t3511, t3516, t3520, t3521, t3512, t3517, t3346, t3247 };
inline constexpr std::size_t kMmTimerCount = 10;
const char* mm_timer_name(MmTimer t) noexcept;

/// Default values from Table 10.2.2.
struct MmTimerValues {
    Millis t3502 = 720'000;
    Millis t3510 = 15'000;
    Millis t3511 = 10'000;
    Millis t3516 = 30'000;
    Millis t3520 = 15'000;
    Millis t3521 = 15'000;
    Millis t3512 = 3'240'000;   // 54 min, when the network gives none
    Millis t3517 = 15'000;
    Millis t3247_min = 1'800'000;   // §5.3.20.2: uniformly in 30 to 60 minutes
    Millis t3247_max = 3'600'000;
};

/// What 5GMM asks of 5GSM (N12): the sessions it holds, for the PDU session
/// status (§9.11.3.44); a local release of those the network does not hold;
/// a local release of every one (network de-registration).
struct SmHooks {
    std::function<std::uint16_t()> active;                  // bit n: PSI n not PDU SESSION INACTIVE
    std::function<void(std::uint16_t network)> sync;        // keep only these
    std::function<void()> release_all;
};

/// A 5GSM message for UL NAS TRANSPORT (§5.4.5.2.1).
struct SmUplink {
    std::uint8_t psi = 0;
    Bytes sm;
    std::optional<std::uint8_t> request_type;   // §9.11.3.47; establishment: initial request
    std::optional<nas::ie::Snssai> snssai;
    std::optional<std::string> dnn;
    bool sms = false;   // N13: `sm` is an SMS CP message (payload container type SMS, no PSI)
};

/// A DL NAS TRANSPORT with an N1 SM payload (§5.4.5.3.1). With a 5GMM cause,
/// the payload is the UE's own 5GSM message the network could not forward
/// (§5.4.5.2.5, §5.4.5.3.3).
struct SmDownlink {
    std::uint8_t psi = 0;
    Bytes sm;
    std::optional<std::uint8_t> mm_cause;
    std::optional<nas::ie::GprsTimer3> backoff;
};

struct MmConfig {
    std::string id;                                // the events' subject, e.g. "ue-1"
    nas::ie::Plmn plmn;                            // the selected PLMN (fixed camping, ledger A-12)
    nas::ie::UeSecurityCapability security{0xE0, 0x60, std::nullopt, std::nullopt, {}};   // 5G-EA0-2, 128-5G-IA1-2
    std::optional<Bytes> mm_capability;            // N15: the 5GMM capability IE's value, from a persona
    std::vector<nas::ie::Snssai> requested_nssai;
    std::string imeisv;                            // 16 digits
    bool follow_on_request = false;
    bool sms_requested = true;                     // N13: SMS over NAS in the 5GS update type
    std::uint64_t seed = 0;                        // the run's, for T3247's draw (keyed by the SUPI)
    MmTimerValues timers;
    /// Each 5GMM message in clear, as sent before protection and as taken
    /// after its integrity check and deciphering, for the run's Uu capture.
    std::function<void(bool uplink, ByteView plain)> tap;
    /// 5GSM's downlink (N10).
    std::function<void(const SmDownlink&)> sm;
    /// N13: an SMS CP message in a DL NAS TRANSPORT, and SMS over NAS allowed
    /// or not after each REGISTRATION ACCEPT (§5.5.1.2.4).
    std::function<void(ByteView cp)> sms;
    std::function<void(bool allowed)> sms_allowed;
    SmHooks sm_hooks;
};

class Mm {
public:
    Mm(Executor& ex, uicc::Terminal& card, INasLower& lower, IEventSink& events, MmConfig cfg);
    ~Mm();
    Mm(const Mm&) = delete;
    Mm& operator=(const Mm&) = delete;

    // ---- the UE's own commands

    /// Powers the card, selects the USIM and reads the subscription (EF.IMSI,
    /// EF.AD, EF.Routing_Indicator). Ends in 5GMM-DEREGISTERED.NORMAL-SERVICE,
    /// or .NO-SUPI without a usable USIM.
    void power_on();
    /// Initial registration (§5.5.1.2.2), from a 5GMM-DEREGISTERED substate
    /// with a valid USIM; ignored otherwise.
    void register_initial();
    /// UE-initiated de-registration (§5.5.2.2.1). A switch-off sends the
    /// request and powers the UE off (5GMM-NULL) with no accept awaited.
    void deregister(bool switch_off);

    // ---- from the lower layers

    void on_nas(ByteView wire);
    /// The N1 signalling connection was released, or the lower layers failed.
    void on_released();
    /// "RRC Connection failure" from the lower layers, before on_released:
    /// with no signalling pending, a mobility registration follows (§5.5.1.3.2 f)
    /// naming the sessions whose user plane was up (bit n for PSI n).
    void on_connection_failure(std::uint16_t up_psis);
    /// The UICC removed (N12 follow-up): a registered UE de-registers (§5.5.2.2.1,
    /// nothing written to the card), then 5GMM-DEREGISTERED.NO-SUPI; the forbidden
    /// lists, the rejected NSSAI and the §5.3.20 counters go with the UICC.
    void usim_removed();
    /// The UICC inserted again: it is read as at power on.
    void usim_inserted();
    /// The cell the UE camps on: its TAI is the current TAI (§5.3.13).
    void on_camped(std::uint32_t tac);

    // ---- SMS over NAS (N13)

    /// An SMS CP message to the network (§5.4.5.2: payload container type SMS);
    /// from 5GMM-IDLE a service request brings the connection first.
    Result<void> send_sms(Bytes cp);
    bool sms_allowed() const noexcept { return sms_allowed_; }
    /// TS-Service-Centre-Address from EF.SMSP record 1 (TON/NPI and digits), when
    /// the card gives one (TS 31.102 4.2.27); RP-DA comes from it (L7).
    const std::optional<Bytes>& sms_service_centre() const noexcept { return smsc_; }
    /// EF.SMSS as read at power on (TS 31.102 4.2.28).
    const Bytes& smss() const noexcept { return smss_; }
    /// Writes to the SMS files through the card queue: an EF.SMS record, EF.SMSS.
    void store_sms_record(std::uint8_t record, Bytes data);
    void store_smss(Bytes data);
    /// A mobility registration update, e.g. to ask for SMS again (§5.5.1.3.2).
    Result<void> register_update();

    // ---- from 5GSM

    /// UL NAS TRANSPORT (§5.4.5.2.2) in 5GMM-REGISTERED. In 5GMM-IDLE the
    /// message waits for a service request (signalling) to bring the connection.
    Result<void> send_sm(const SmUplink& u);

    // ---- N12

    /// SERVICE REQUEST (§5.6.1.2) from 5GMM-IDLE: `type` a §9.11.3.50 value,
    /// `uplink` the PSIs with uplink data pending. Errc::invalid_argument when
    /// not registered with a 5G-GUTI and a context, or a procedure runs.
    Result<void> service_request(std::uint8_t type, std::uint16_t uplink);
    /// A paging record for this UE from the lower layers (§5.6.2.2.1).
    void on_paged();
    /// Power off without signalling: what is in memory is lost, the card keeps
    /// what it holds (nothing is written).
    void power_off_abrupt();

    // ---- read side

    MmState state() const noexcept { return state_; }
    UpdateStatus update_status() const noexcept { return update_; }
    int attempt_counter() const noexcept { return attempts_; }
    bool usim_valid() const noexcept { return usim_valid_; }
    bool connected() const noexcept { return connected_; }
    const std::string& supi() const noexcept { return supi_; }
    const std::optional<nas::ie::MobileIdentity>& guti() const noexcept { return guti_; }
    const std::optional<nas::ie::TaiList>& tai_list() const noexcept { return tai_list_; }
    const std::vector<nas::ie::Snssai>& allowed_nssai() const noexcept { return allowed_nssai_; }
    std::optional<Millis> t3512() const noexcept { return t3512_; }
    /// The current 5G NAS security context, once a SECURITY MODE COMMAND put one in use.
    const NasSecurityContext* security() const noexcept { return ctx_ ? &*ctx_ : nullptr; }
    /// K_gNB for AS security activation (TS 33.501 A.9): from the current
    /// K_AMF and the uplink NAS COUNT of the most recent SECURITY MODE COMPLETE
    /// (§6.8.1.2.2, §6.8.1.3); without one in this connection, of the initial
    /// NAS message. Errc::invalid_argument without a context.
    Result<SecretBytes> kgnb() const;
    /// The 5G-S-TMSI of the 5G-GUTI (AMF set, pointer, 5G-TMSI: 48 bits), if any.
    std::optional<std::uint64_t> s_tmsi() const noexcept;
    bool running(MmTimer t) const noexcept { return timers_.at(static_cast<std::size_t>(t)).has_value(); }
    /// The PSIs with uplink data a service request is waiting for.
    std::uint16_t pending_uplink() const noexcept { return sr_uplink_; }
    /// Transitions made that mm_transitions() does not list (must stay 0).
    std::uint64_t unlisted_transitions() const noexcept { return unlisted_; }

private:
    struct Partial {   // the new K_AMF of a 5G AKA, not yet taken into use
        nas::ie::NgKsi ngksi;
        SecretBytes kamf;
    };

    coro::Task<void> read_card(std::shared_ptr<bool> alive);
    coro::Task<void> run_aka(std::shared_ptr<bool> alive, std::uint64_t gen, nas::ie::NgKsi ngksi, Bytes rand,
                             Bytes autn, Bytes abba);
    // EAP-AKA' (§5.4.1.2, TS 33.501 6.1.3.1; N12 follow-up)
    void on_eap_request(nas::ie::NgKsi ngksi, Bytes abba, Bytes eap_wire);
    coro::Task<void> run_eap_aka(std::shared_ptr<bool> alive, std::uint64_t gen, nas::ie::NgKsi ngksi, Bytes abba,
                                 Bytes eap_wire);
    /// AUTHENTICATION RESPONSE with an EAP-response; an error response pauses the
    /// retransmission timers and starts T3520 (§5.4.1.2.2.4).
    void send_eap_wire(const Bytes& eap_wire, bool error, const char* subtype, const char* why);
    void on_eap_result(const Bytes& eap_wire);   // EAP-success or EAP-failure (SMC, AUTHENTICATION RESULT)
    void on_authentication_result(const nas::Message& m);

    enum class RegType : std::uint8_t { initial = 1, mobility = 2, periodic = 3 };
    void start_registration(RegType type = RegType::initial);
    /// §4.4.6: the initial message as it goes, protected with the current context.
    Result<Bytes> protect_initial(const nas::Message& m);
    void on_service_accept(const nas::Message& m);
    void on_service_reject(const nas::Message& m, bool integrity_ok);
    void on_network_deregistration(const nas::Message& m);
    void on_configuration_update(const nas::Message& m);
    void on_identity_request(const nas::Message& m);
    void flush_pending_sm();
    void entering_connected();
    void entering_deregistered();
    // The USIM (TS 31.102 4.4.11), written in order by one job at a time.
    struct CardWrite {
        std::uint16_t fid = 0;
        bool record = false;
        std::shared_ptr<SecretBytes> data;   // two of the files hold keys
        std::vector<std::uint16_t> path;     // empty: DF.5GS/fid (N13: the SMS files under ADF.USIM)
        std::uint8_t record_no = 1;
    };
    void card_job(CardWrite w);
    coro::Task<void> run_card_jobs(std::shared_ptr<bool> alive);
    void persist_loci();
    void persist_nsc(bool valid);
    void persist_auth_keys();
    void registration_abnormal(const char* reason);
    void send_authentication_failure(std::uint8_t cause, Bytes auts);
    void network_failed_authentication();
    void resume_retransmission_timers();

    void on_plain(const nas::Message& m, bool integrity_ok);
    void on_security_mode_command(ByteView wire);
    void on_authentication_request(const nas::Message& m);
    void on_authentication_reject(bool integrity_ok);
    void on_registration_accept(const nas::Message& m);
    void on_registration_reject(const nas::Message& m, bool integrity_ok);
    /// §5.3.20.2 for a REGISTRATION REJECT or SERVICE REJECT that came without
    /// integrity protection: true when it handled the cause itself.
    bool unprotected_reject(std::uint8_t cause);
    void forbid_current_ta(bool unprotected);
    void deregistered_with_cause(std::uint8_t cause);   // §5.5.2.3.2, §5.5.2.3.4 b
    void on_deregistration_accept();
    void on_dl_nas_transport(const nas::Message& m);
    void reject_security_mode(std::uint8_t cause);

    nas::ie::MobileIdentity identity() const;
    nas::ie::NgKsi current_ngksi() const;
    /// Sends a 5GMM message: protected with the current context once there is
    /// one (integrity and ciphering; an initial message from idle, integrity
    /// only), plain before.
    void send(const nas::Message& m);
    void send_wire(Bytes wire);
    void send_status(std::uint8_t cause);
    void set_state(MmState to, const char* why);
    void start(MmTimer t, Millis ms);
    void stop(MmTimer t);
    void on_expiry(MmTimer t);
    void clear_stored_challenge();
    void delete_registration_data(bool guti_and_ngksi);

    Executor& ex_;
    uicc::Terminal& card_;
    INasLower& lower_;
    IEventSink& events_;
    MmConfig cfg_;
    std::shared_ptr<bool> alive_;
    Rng rng_;   // T3247's draws

    MmState state_ = MmState::null;
    UpdateStatus update_ = UpdateStatus::u2_not_updated;
    int attempts_ = 0;
    bool usim_valid_ = false;
    bool connected_ = false;
    bool secure_exchange_ = false;   // §4.4.4.2, for the current NAS signalling connection
    std::string supi_;
    std::string msin_;
    nas::ie::Plmn home_;
    std::string routing_indicator_ = "0";

    std::optional<nas::ie::MobileIdentity> guti_;
    std::optional<nas::ie::TaiList> tai_list_;
    std::vector<nas::ie::Snssai> allowed_nssai_;
    std::optional<Millis> t3512_;
    std::optional<Millis> t3502_net_;

    std::optional<NasSecurityContext> ctx_;
    std::optional<Partial> partial_;
    nas::Message initial_;           // the whole REGISTRATION REQUEST last sent
    bool initial_without_context_ = false;
    nas::Message dereg_;             // the DEREGISTRATION REQUEST, for T3521 retransmissions
    bool dereg_switch_off_ = false;
    std::optional<std::uint32_t> kgnb_count_;   // the uplink NAS COUNT K_gNB takes
    int t3521_expiries_ = 0;

    // N12
    RegType reg_type_ = RegType::initial;
    bool recovery_pending_ = false;    // §5.5.1.3.2 f
    std::uint16_t reg_uplink_ = 0;     // the mobility registration's Uplink data status, until accepted
    bool sms_allowed_ = false;         // N13: from the last REGISTRATION ACCEPT
    std::optional<Bytes> smsc_;        // EF.SMSP's service centre address
    Bytes smss_;                       // EF.SMSS
    std::uint16_t recovery_up_ = 0;    // its Uplink data status
    std::optional<nas::ie::Tai> last_tai_;      // the last visited registered TAI
    std::optional<nas::ie::Tai> current_tai_;   // the camped cell's
    std::uint8_t sr_type_ = 0;
    std::uint16_t sr_uplink_ = 0;           // the PSIs the service request asked for
    std::vector<SmUplink> pending_sm_;      // 5GSM messages waiting for the connection
    bool reregister_pending_ = false;
    bool update_registration_pending_ = false;   // a configuration update asked for one
    std::vector<nas::ie::Plmn> forbidden_plmns_;
    std::vector<nas::ie::Tai> forbidden_tais_;
    // §5.3.20.2: the TAs forbidden by non-integrity-protected rejects (T3247
    // takes them off again) and the "SIM/USIM considered invalid for GPRS
    // services" events, at most kMaxInvalidEvents (UE implementation-specific, at most 10).
    std::vector<nas::ie::Tai> unprotected_tais_;
    int invalid_events_ = 0;
    static constexpr int kMaxInvalidEvents = 3;
    bool reject_unprotected_ = false;   // the reject being handled came without integrity protection
    bool usim_present_ = true;          // false from a UICC removal to its insertion
    // §5.5.1.2.5 #62, §4.6.2.2: S-NSSAIs the network rejected, not asked for again
    // until power-off (P1 keeps one list for every rejection cause).
    std::vector<nas::ie::RejectedNssai::Entry> rejected_nssai_;
    SecretBytes kausf_;
    SecretBytes kseaf_;
    struct EapKeys {   // an EAP-AKA' run's anchor keys, valid from its EAP-success (§5.4.1.2.2.3)
        SecretBytes kausf;
        SecretBytes kseaf;
    };
    std::optional<EapKeys> eap_pending_;
    std::deque<CardWrite> card_jobs_;
    bool card_busy_ = false;
    std::size_t nsc_record_size_ = 62;

    Bytes stored_rand_;
    Bytes stored_res_star_;          // RES* is sent in clear; stored with its RAND (§5.4.1.3.3)
    int auth_failures_ = 0;          // consecutive failed challenges (§5.4.1.3.7)
    bool paused_t3510_ = false;
    bool paused_t3521_ = false;
    std::uint64_t gen_ = 0;          // bumped when a procedure is aborted; a stale AKA result is dropped

    std::array<std::optional<TimerId>, kMmTimerCount> timers_{};
    std::uint64_t unlisted_ = 0;
};

} // namespace ksim::proc::ue
