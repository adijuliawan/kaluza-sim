// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The UE's RRC entity and the L2 it configures (P1 N6; TS 38.331 j40 §5.2,
// §5.3; architecture.md §6). It owns the ideal MAC, the RLC and PDCP of SRB0,
// SRB1, SRB2 and the DRBs, and the SDAP entity of each PDU session. Covered:
//
//  - fixed camping (ledger A-12): MIB not barred, SIB1 listing the selected
//    PLMN; its UE timers taken (T300);
//  - connection establishment (§5.3.3): RRCSetupRequest with the 5G-S-TMSI's
//    Part1 or a random value, random access, T300, RRCSetup (SRB1), then
//    RRCSetupComplete with the NAS message (and Part2); RRCReject and T300
//    expiry are a failure the NAS sees as a lower layer failure;
//  - AS security (§5.3.4): K_gNB from the NAS, K_RRCint/K_RRCenc and
//    K_UPint/K_UPenc (TS 33.501 A.8), the command's own MAC-I checked, then
//    integrity at once and ciphering after the SecurityModeComplete, which
//    goes unciphered; NIA0 refused unless the D1 bisect switch allows it;
//  - RRCReconfiguration (§5.3.5): SRB2 and DRBs from the radio bearer config,
//    their logical channels from the masterCellGroup, SDAP per session, the
//    NAS message list forwarded after the RRCReconfigurationComplete;
//  - RRCRelease (§5.3.8), UE capability transfer (§5.6.1), DL/UL information
//    transfer (§5.7.1, §5.7.2) and paging matched on the 5G-S-TMSI (§5.3.2).
//
// Not in P1: re-establishment (an SRB integrity failure releases instead;
// ledger), RRC_INACTIVE (P3b), measurements and handover (P3).

#pragma once

#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "codec/air/kair.hpp"
#include "codec/asn1/msg/rrc.hpp"
#include "codec/sdap/sdap.hpp"
#include "entity/mac/ue_ideal.hpp"
#include "entity/pdcp/pdcp.hpp"
#include "entity/rlc/ideal.hpp"
#include "entity/sdap/sdap.hpp"
#include "platform/event.hpp"
#include "platform/executor.hpp"
#include "platform/rng.hpp"
#include "platform/secret.hpp"
#include "proc/ue/nas_mm/ports.hpp"

namespace ksim::proc::ue {

enum class RrcState : std::uint8_t { idle, connecting, connected };
const char* rrc_state_name(RrcState s) noexcept;

struct RrcConfig {
    std::string id;                         // the events' subject
    rrc::Plmn plmn;                         // the selected PLMN (fixed camping, ledger A-12)
    entity::UeMacConfig mac;                // radio_id and the random access parameters
    bool allow_null_integrity = false;      // D1: NIA0 only as the bisect switch
    Millis t300_default = 1000;             // until SIB1 gives T300
    Millis keepalive = 200;                 // KAIR KEEPALIVE while connected (P1 N12)
    Millis rlf = 1000;                      // no downlink this long while connected: radio link failure
    std::optional<Bytes> nr_capability;     // the persona's UE-NR-Capability; a generic one if absent
    /// Each RRC message in clear as the UE sends or takes it, with Wireshark's
    /// channel name ("nr-rrc.ul.dcch", …) for the run's Uu capture. Broadcast
    /// is reported when it makes the UE camp, not at every period.
    std::function<void(std::string_view channel, ByteView pdu)> tap;
};

/// The NAS and the user plane above RRC, as the UE node wires them.
struct RrcUpper {
    std::function<void(Bytes)> nas;                              // a downlink NAS PDU
    std::function<void()> released;                              // the connection is gone (release or failure)
    /// The RRC connection was never set up (TS 38.331 5.3.3.7, T300, RRCReject),
    /// just before `released`: the initial NAS message never left (TS 24.501 4.4.3.1).
    std::function<void()> establishment_failed;
    std::function<Result<SecretBytes>()> kgnb;                   // TS 33.501 6.8.1.2
    std::function<std::optional<std::uint64_t>()> s_tmsi;        // the 5G-S-TMSI, if the UE has a 5G-GUTI
    std::function<void()> paged;                                 // a paging record for this UE
    std::function<void(std::uint8_t psi, std::optional<sdap::DlHeader>, Bytes)> dl_data;
    std::function<void()> bearers_up;                            // a reconfiguration added DRBs (N12)
    /// N12: "RRC Connection failure" (TS 24.501 5.5.1.3.2 f), just before
    /// `released`; bit n for PSI n whose user plane was up.
    std::function<void(std::uint16_t up_psis)> connection_failure;
    std::function<void(std::uint32_t tac)> camped;               // the UE camps on a cell of its PLMN (N12)
};

class UeRrc final : public INasLower {
public:
    UeRrc(Executor& ex, Rng rng, IEventSink& events, RrcConfig cfg, RrcUpper upper,
          std::function<void(air::Frame)> to_air);
    ~UeRrc() override;
    UeRrc(const UeRrc&) = delete;
    UeRrc& operator=(const UeRrc&) = delete;

    // INasLower
    void send_nas(Bytes pdu) override;
    void release_local() override;

    void on_frame(const air::Frame& f);
    /// Power (N12): off mutes the radio and drops the connection without a word
    /// (no release reported); on starts from finding the cell again.
    void power(bool on);
    /// Switch-off (N12): the radio goes off once the NAS message just handed
    /// down is on the air: at once in RRC_CONNECTED, after RRCSetupComplete
    /// carried it from RRC_IDLE, or when that setup fails.
    void power_off_after_nas();
    /// Uplink user data of QoS flow `qfi` in PDU session `psi`.
    Result<void> send_data(std::uint8_t psi, std::uint8_t qfi, Bytes ip);

    RrcState state() const noexcept { return state_; }
    bool camped() const noexcept { return camped_; }
    std::uint32_t cell() const noexcept { return cell_; }
    bool as_security() const noexcept { return as_security_; }
    std::optional<std::uint16_t> c_rnti() const noexcept { return mac_->c_rnti(); }
    const entity::Pdcp* srb(std::uint8_t id) const;
    const entity::Pdcp* drb(std::uint8_t id) const;
    std::vector<std::uint8_t> drbs() const;
    const entity::UeIdealMac& mac() const noexcept { return *mac_; }

private:
    struct Bearer {
        std::unique_ptr<entity::IdealRlc> rlc;
        std::unique_ptr<entity::Pdcp> pdcp;
        std::uint8_t psi = 0;   // a DRB's PDU session
    };
    struct Lcid {
        std::uint8_t lcid = 0;
        bool am = true;
    };

    void on_mib(const air::Frame& f);
    void on_sib1(const air::Frame& f);
    void on_paging(const air::Frame& f);
    void establish();
    void setup_failed(const char* reason);
    void on_ccch(Bytes sdu);
    void on_dcch(std::uint8_t srb, Bytes sdu);
    void on_security_mode_command(const rrc::SecurityModeCommand& m);
    void on_reconfiguration(const rrc::Reconfiguration& m);
    void on_drb(std::uint8_t drb, Bytes sdu);
    void send_end_markers(const std::vector<entity::Sdap::EndMarker>& markers);   // P2 Q11
    void add_srb(std::uint8_t id);
    Result<void> add_drb(const rrc::DrbAdd& d);
    void send_dcch(Result<Bytes> msg, std::uint8_t srb = 1);
    void ul_nas(Bytes pdu);
    void go_idle();
    void supervise();
    void lost(const char* why);

    Executor& ex_;
    Rng rng_;
    IEventSink& events_;
    RrcConfig cfg_;
    RrcUpper upper_;
    std::shared_ptr<bool> alive_;
    std::unique_ptr<entity::UeIdealMac> mac_;
    std::unique_ptr<entity::IdealRlc> srb0_;

    RrcState state_ = RrcState::idle;
    bool mib_ok_ = false;
    bool camped_ = false;
    bool off_after_setup_ = false;   // power_off_after_nas waits for the setup
    bool radio_on_ = true;           // off: nothing heard, nothing sent
    std::uint32_t cell_ = 0;
    std::uint32_t tac_ = 0;
    std::uint64_t nci_ = 0;
    std::uint8_t plmn_index_ = 1;
    Millis t300_ = 1000;
    std::optional<TimerId> t300_timer_;
    std::optional<TimerId> supervision_;
    Millis last_dl_ = 0;
    std::optional<std::uint16_t> s_tmsi_part2_;
    std::optional<Bytes> pending_nas_;
    std::deque<Bytes> pending_ul_;

    bool as_security_ = false;
    std::optional<crypto::Nia> nia_;
    std::optional<crypto::Nea> nea_;
    SecretBytes rrc_keys_int_;   // K_RRCint and K_RRCenc, for SRBs added after the SMC
    SecretBytes rrc_keys_enc_;
    SecretBytes k_up_int_;
    SecretBytes k_up_enc_;
    std::map<std::pair<bool, std::uint8_t>, Lcid> lcids_;   // (srb?, id) -> its logical channel
    std::map<std::uint8_t, Bearer> srbs_;
    std::map<std::uint8_t, Bearer> drbs_;
    std::map<std::uint8_t, entity::Sdap> sdaps_;
};

} // namespace ksim::proc::ue
