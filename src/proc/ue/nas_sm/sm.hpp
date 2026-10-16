// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The UE's 5GSM entity (P1 N10; TS 24.501 j80 §6): one UE's PDU sessions on
// its actor's executor, carried by 5GMM's NAS transport (§5.4.5). P1 covers
//
//  - UE-requested establishment of an IPv4 session (§6.4.1): the PTI
//    allocated, the lowest free PSI unless one is asked for, the integrity
//    protection maximum data rate, SSC mode 1, and the ePCO requests for the
//    DNS server IPv4 address (000DH) and the IPv4 link MTU (0010H); T3580 with
//    four retransmissions (§6.4.1.6);
//  - the accept (§6.4.1.3): the QoS rules checked for a single default QoS
//    rule (a missing or doubled one is #83 and a release, and a core.anomaly
//    event), the PDU address, the session-AMBR and the ePCO parameters taken;
//  - the reject (§6.4.1.4): the back-off of §6.4.1.4.3 per [PLMN, DNN,
//    S-NSSAI] (or [PLMN, DNN] for #27), T3396 for #26, T3584 for #67 and T3585
//    for #69 (§6.4.1.4.2), the 12-minute default for #8, #32, #33, #70 and #27
//    without a timer, and "deactivated" holding until switch-off;
//  - UE-requested release with T3582 (§6.4.3), network-requested release
//    (§6.3.3, #39 re-establishing), network-requested modification (§6.3.2:
//    QoS rules and session-AMBR applied, then MODIFICATION COMPLETE);
//  - the PTI and PSI checks of §7.3.1 and §7.3.2, 5GSM STATUS both ways
//    (§6.5), and a message the AMF could not forward (§5.4.5.2.5).
//
// Later: IPv6 and IPv4v6, UE-requested modification, the always-on and
// multi-access sessions, secondary authentication (P4), session status sync
// after a service request (N12).

#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "codec/nas/ie/ie.hpp"
#include "codec/nas/nas.hpp"
#include "platform/event.hpp"
#include "platform/executor.hpp"
#include "platform/result.hpp"
#include "proc/ue/nas_mm/mm.hpp"

namespace ksim::proc::ue {

/// §6.1.3.2.1 (UE side).
enum class SmState : std::uint8_t { inactive, active_pending, active, inactive_pending, modification_pending };
const char* sm_state_name(SmState s) noexcept;

/// Table 10.3.2.
struct SmTimerValues {
    Millis t3580 = 16'000;
    Millis t3582 = 16'000;
};

struct SmConfig {
    std::string id;                    // the events' subject
    SmTimerValues timers;
    // P2 Q9 (TS 24.501 9.11.4.7): the UE's maximum data rate for UP integrity, uplink and
    // downlink, as its persona's phone sent it (0x00 64 kbit/s, 0x01 NULL, 0xFF full).
    std::uint8_t ip_max_rate_ul = 0xFF;
    std::uint8_t ip_max_rate_dl = 0xFF;
    Millis default_backoff = 720'000;  // §6.4.1.4.3: 12 minutes with no SM Retry Timer configured
};

struct SessionRequest {
    std::uint8_t psi = 0;              // 0: the lowest free one
    std::string dnn;                   // empty: none sent
    std::optional<nas::ie::Snssai> snssai;
};

/// What the UE knows of a PDU session.
struct SessionInfo {
    std::uint8_t psi = 0;
    SmState state = SmState::inactive;
    std::string dnn;
    std::optional<nas::ie::Snssai> snssai;
    std::optional<std::array<std::uint8_t, 4>> ipv4;
    std::optional<std::array<std::uint8_t, 4>> dns;
    std::optional<std::uint16_t> mtu;
    std::uint8_t default_qfi = 0;      // the QFI of the default QoS rule
    std::vector<std::uint8_t> qfis;    // every QoS rule's
    std::vector<nas::ie::QosRules::Rule> rules;   // P2 Q10: the signalled QoS rules, for the UL classifier
    std::map<std::uint8_t, std::uint16_t> flow_5qi;   // P2 Q10: the QoS flow descriptions (QFI -> 5QI; 0 when none given)
    std::optional<std::uint64_t> ambr_dl_bps;
    std::optional<std::uint64_t> ambr_ul_bps;
};

struct SmUpper {
    std::function<void(const SessionInfo&)> up;        // established, or changed by a modification
    std::function<void(std::uint8_t psi)> down;        // released
};

class Sm {
public:
    Sm(Executor& ex, IEventSink& events, SmConfig cfg, std::function<Result<void>(const SmUplink&)> lower,
       SmUpper upper);
    ~Sm();
    Sm(const Sm&) = delete;
    Sm& operator=(const Sm&) = delete;

    /// UE-requested establishment (§6.4.1.2); the PSI used. Errc::invalid_argument
    /// for a PSI in use or none free, or a back-off still running for the
    /// request's DNN and S-NSSAI; 5GMM's error when it cannot carry the request.
    Result<std::uint8_t> establish(const SessionRequest& r);
    /// UE-requested release (§6.4.3.2), by default with #36 "regular deactivation".
    Result<void> release(std::uint8_t psi, std::uint8_t cause = 36);
    void on_downlink(const SmDownlink& d);
    /// Every session released locally (de-registration, switch-off).
    void release_all_local(const char* why);
    /// The PDU session status (§9.11.3.44): bit n for each PSI not PDU SESSION INACTIVE.
    std::uint16_t active_bitmap() const;
    /// §5.6.1.4, §5.5.1.3.4: sessions the network does not hold are released locally.
    void sync(std::uint16_t network);

    std::vector<SessionInfo> sessions() const;
    const SessionInfo* session(std::uint8_t psi) const;
    /// A back-off blocks a request for this DNN and S-NSSAI.
    bool backed_off(const std::string& dnn, const std::optional<nas::ie::Snssai>& snssai) const;
    bool running(std::uint8_t psi) const;   // T3580 or T3582 for the session

private:
    struct Proc {
        enum class Kind : std::uint8_t { establish, release } kind = Kind::establish;
        std::uint8_t pti = 0;
        SmUplink uplink;               // as sent, for retransmissions
        int expiries = 0;
        std::optional<TimerId> timer;
    };
    struct Session {
        SessionInfo info;
        std::optional<Proc> proc;
        std::vector<nas::ie::QosRules::Rule> rules;
        std::optional<std::uint8_t> released_pti;   // the PTI of the last accepted UE-requested release
    };
    struct Backoff {
        std::string timer;             // "T3396", "T3584", "T3585" or "back-off"
        std::optional<TimerId> id;     // none: deactivated, until switch-off
    };

    void on_accept(Session& s, const nas::Message& m, std::uint8_t pti);
    void on_reject(Session& s, const nas::Message& m, std::uint8_t pti);
    void on_release_command(Session& s, const nas::Message& m, std::uint8_t pti);
    void on_release_reject(Session& s, const nas::Message& m, std::uint8_t pti);
    void on_modification_command(Session& s, const nas::Message& m, std::uint8_t pti);
    void on_status(Session& s, const nas::Message& m, std::uint8_t pti);
    void not_forwarded(Session& s, std::uint8_t mm_cause, const std::optional<nas::ie::GprsTimer3>& backoff);
    void start_backoff(const Session& s, std::uint8_t cause, const std::optional<nas::ie::GprsTimer3>& t);
    void send(Session& s, const nas::Message& m, std::optional<std::uint8_t> request_type);
    void send_status(std::uint8_t psi, std::uint8_t pti, std::uint8_t cause);
    void start_proc_timer(Session& s);
    void stop_proc(Session& s);
    void on_expiry(std::uint8_t psi);
    void release_local(Session& s, const char* why);
    void set_state(Session& s, SmState to);
    bool apply_rules(Session& s, const nas::ie::QosRules& r, bool initial);
    void apply_flows(Session& s, const nas::ie::QosFlowDescriptions& d, bool initial);
    std::uint8_t next_pti();

    Executor& ex_;
    IEventSink& events_;
    SmConfig cfg_;
    std::function<Result<void>(const SmUplink&)> lower_;
    SmUpper upper_;
    std::shared_ptr<bool> alive_;
    std::map<std::uint8_t, Session> sessions_;     // by PSI, 1..15
    std::map<std::string, Backoff> backoffs_;      // by "<dnn>|<s-nssai>", either part "*"
    std::uint8_t pti_ = 0;
};

/// "01" or "01-000001": an S-NSSAI as events and ksim-ctl print it.
std::string snssai_text(const nas::ie::Snssai& s);

} // namespace ksim::proc::ue
