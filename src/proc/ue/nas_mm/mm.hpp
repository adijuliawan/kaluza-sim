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
// N12 adds the service request, idle mode, the periodic update, network
// de-registration, identification, the configuration update and the protected
// initial message of a UE that holds a context (§4.4.6). Until then an initial
// registration starts without a 5G NAS security context.

#pragma once

#include <array>
#include <cstdint>
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
#include "platform/secret.hpp"
#include "proc/ue/nas_mm/ports.hpp"
#include "proc/ue/nas_mm/state.hpp"
#include "proc/ue/nas_sec/nas_sec.hpp"
#include "uicc/terminal/terminal.hpp"

namespace ksim::proc::ue {

/// The UE's 5GMM timers (§10.2, Table 10.2.2) the entity runs in N5.
enum class MmTimer : std::uint8_t { t3502, t3510, t3511, t3516, t3520, t3521 };
inline constexpr std::size_t kMmTimerCount = 6;
const char* mm_timer_name(MmTimer t) noexcept;

/// Default values from Table 10.2.2.
struct MmTimerValues {
    Millis t3502 = 720'000;
    Millis t3510 = 15'000;
    Millis t3511 = 10'000;
    Millis t3516 = 30'000;
    Millis t3520 = 15'000;
    Millis t3521 = 15'000;
};

/// A 5GSM message for UL NAS TRANSPORT (§5.4.5.2.1).
struct SmUplink {
    std::uint8_t psi = 0;
    Bytes sm;
    std::optional<std::uint8_t> request_type;   // §9.11.3.47; establishment: initial request
    std::optional<nas::ie::Snssai> snssai;
    std::optional<std::string> dnn;
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
    std::vector<nas::ie::Snssai> requested_nssai;
    std::string imeisv;                            // 16 digits
    bool follow_on_request = false;
    MmTimerValues timers;
    /// Each 5GMM message in clear, as sent before protection and as taken
    /// after its integrity check and deciphering, for the run's Uu capture.
    std::function<void(bool uplink, ByteView plain)> tap;
    /// 5GSM's downlink (N10).
    std::function<void(const SmDownlink&)> sm;
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

    // ---- from 5GSM

    /// UL NAS TRANSPORT (§5.4.5.2.2), in 5GMM-REGISTERED with an N1 signalling
    /// connection; Errc::closed without one (the service request is N12).
    Result<void> send_sm(const SmUplink& u);

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

    void start_registration();
    void registration_abnormal(const char* reason);
    void send_authentication_failure(std::uint8_t cause, Bytes auts);
    void network_failed_authentication();
    void resume_retransmission_timers();

    void on_plain(const nas::Message& m, bool integrity_ok);
    void on_security_mode_command(ByteView wire);
    void on_authentication_request(const nas::Message& m);
    void on_authentication_reject(bool integrity_ok);
    void on_registration_accept(const nas::Message& m);
    void on_registration_reject(const nas::Message& m);
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

    MmState state_ = MmState::null;
    UpdateStatus update_ = UpdateStatus::u2_not_updated;
    int attempts_ = 0;
    bool usim_valid_ = false;
    bool connected_ = false;
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
