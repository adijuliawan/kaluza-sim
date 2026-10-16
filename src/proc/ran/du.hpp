// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The gNB-DU (P1 N7; TS 38.473 j40 §8; ADR 0003, 0009): one cell, its F1
// association to the CU-CP, and the network side of the ideal MAC over KAIR.
//
//  - F1 Setup once F1 is up, with the served cell and its MIB and SIB1 as
//    gNB-DU System Information; the cell is broadcast (BCH, SI) once the CU
//    activates it. A setup failure is retried after its time to wait.
//  - Random access (TS 38.321 §5.1 at KAIR level): a RAR per PRACH, with one
//    TC-RNTI for every UE that picked the same preamble in the same occasion;
//    the first Msg3 for a TC-RNTI wins, its UL-CCCH goes to the CU in an
//    INITIAL UL RRC MESSAGE TRANSFER with the DU's CellGroupConfig, and the
//    CU's RRCSetup comes back as Msg4 with that Msg3's contention resolution
//    identity. Later Msg3s get no Msg4 and their UEs retry.
//  - SRB PDUs (PDCP is the CU's) between the UE's logical channels and F1 RRC
//    message transfers; UE Context Setup and Modification add SRBs and answer
//    with the CellGroupConfig of their RLC bearers; UE Context Release sends
//    its RRC container, then drops the UE.
//  - Paging: a PCCH frame per F1 PAGING, stamped with its paging frame (T =
//    128, N = T, Ns = 1; TS 38.304 §7.1) but not gated on it (ledger A-11).
//
// Not in P1: DRBs and F1-U (N10), radio link supervision (N12), several cells.

#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>

#include "codec/air/kair.hpp"
#include "codec/asn1/msg/f1ap.hpp"
#include "entity/gtpu/gtpu.hpp"
#include "codec/asn1/msg/rrc.hpp"
#include "platform/event.hpp"
#include "platform/executor.hpp"
#include "platform/transport.hpp"

namespace ksim::proc::ran {

inline constexpr std::uint32_t kF1apPpid = 62;   // TS 38.472 §7


struct DuConfig {
    std::string id = "gnb:du1";        // the events' subject
    std::uint64_t du_id = 0x1A0;
    std::string name = "ksim-du1";
    std::uint32_t cell_handle = 1;     // the cell's KAIR handle
    rrc::Plmn plmn{"001", "01"};
    // NR cell identity (36 bits, TS 38.300 8.2): the gNB ID 0x1A0 in the leftmost
    // 22 bits, then local cell 1.
    std::uint64_t nci = (std::uint64_t{0x1A0} << 14) | 1U;
    std::uint16_t pci = 101;
    std::uint32_t tac = 1;
    std::uint32_t arfcn = 632628;      // n78, 3489.42 MHz
    std::uint32_t ssb_arfcn = 632640;  // its SSB on the sync raster, 3489.6 MHz (P2 Q4, rrc::SsbTiming)
    std::optional<rrc::UeTimers> timers = rrc::UeTimers{};
    Millis mib_period = 80;
    Millis sib1_period = 160;
    std::array<std::uint8_t, 4> f1u_addr{};   // the F1-U tunnel address it advertises (N10)
    std::uint16_t gtpu_port = 2152;
    Millis rlf = 1000;                        // a connected UE silent this long is lost (N12)
    // NR-U DL DATA DELIVERY STATUS (P2 Q4, TS 38.425 5.4.2): the buffer each DRB
    // asks for, and how long after DL data (or a DRB's setup) the report follows.
    std::uint32_t ddds_buffer = 8U << 20;     // bytes
    Millis ddds_delay = 10;
    Millis supervision = 200;                 // how often the DU looks
};

struct DuStats {
    std::uint64_t wrong_ppid = 0;      // P2 Q2: F1-C messages under another PPID, dropped
    std::uint64_t prach = 0;
    std::uint64_t rar = 0;
    std::uint64_t msg3_lost_contention = 0;
    std::uint64_t ul_sdus = 0;
    std::uint64_t dl_sdus = 0;
    std::uint64_t ul_user = 0;         // DRB SDUs sent on F1-U
    std::uint64_t dl_user = 0;         // F1-U PDUs sent to a UE
    std::uint64_t ddds_tx = 0;         // P2 Q4: DL DATA DELIVERY STATUS frames sent
    std::uint64_t si_tx = 0;           // P2 Q4: MIBs and SIB1s put on air
    std::uint64_t f1_errors = 0;       // F1AP messages refused or for no UE
};

class Du {
public:
    /// `f1u`: the F1-U port (none: DRBs are refused).
    Du(Executor& ex, IEventSink& events, DuConfig cfg, IAssoc& f1, std::function<void(air::Frame)> to_air,
       IDatagram* f1u = nullptr);
    ~Du();
    Du(const Du&) = delete;
    Du& operator=(const Du&) = delete;

    /// A frame from a UE.
    void on_frame(const air::Frame& f);

    bool cell_active() const noexcept { return active_; }
    std::size_t ues() const noexcept { return ues_.size(); }
    /// P2 Q10: each UE's DRBs (by C-RNTI) and the QoS flows F1AP mapped to each.
    struct DrbView {
        std::uint16_t rnti = 0;
        std::uint8_t drb = 0;
        std::uint8_t lcid = 0;
        std::vector<std::uint8_t> qfis;
        std::uint64_t gfbr_dl = 0;   // P2 Q11
        std::uint64_t gfbr_ul = 0;
    };
    std::vector<DrbView> drb_list() const;
    const DuStats& stats() const noexcept { return stats_; }
    f1ap::NrCgi cgi() const;

private:
    struct Ue {
        std::uint32_t du_ue = 0;
        std::optional<std::uint32_t> cu_ue;
        std::uint16_t rnti = 0;
        std::uint32_t radio_id = 0;
        std::optional<std::array<std::uint8_t, 6>> contention;   // until Msg4 goes
        std::set<std::uint8_t> srbs{1};
        struct Drb {
            std::uint8_t id = 1;
            std::uint8_t lcid = 4;
            f1ap::GtpTunnel ul;           // the CU-UP's F1-U end
            std::uint32_t dl_teid = 0;    // ours
            std::uint8_t sn_bits = 18;    // the DL PDCP SN length F1AP gave (P2 Q4)
            std::optional<std::uint32_t> highest_sn;   // of the DL PDCP PDUs sent to the UE
            bool report_due = false;      // a DDDS is armed
            std::vector<std::uint8_t> qfis;   // P2 Q10: the QoS flows F1AP mapped to it
            std::uint64_t gfbr_dl = 0;        // P2 Q11: its GBR flows'
            std::uint64_t gfbr_ul = 0;
        };
        std::map<std::uint8_t, Drb> drbs;   // by DRB ID
        Millis last_ul = 0;                 // the last frame from the UE
        bool lost = false;                  // the release request went
    };

    void on_f1_event(LinkEvent e);
    void on_f1(ByteView msg);
    void send_f1(const f1ap::Pdu& p, bool ue_associated);
    void f1_setup();
    void broadcast();
    void send_mib();
    void send_sib1();
    void schedule_si(Millis period, bool mib);
    void on_prach(const air::Frame& f);
    void on_msg3(const air::Frame& f);
    void on_ul_sdu(const air::Frame& f);
    void handle(const f1ap::F1SetupResponse& m);
    void handle(const f1ap::F1SetupFailure& m);
    void handle(const f1ap::DlRrcMessageTransfer& m);
    void handle(const f1ap::UeContextSetupRequest& m);
    void handle(const f1ap::UeContextModificationRequest& m);
    void handle(const f1ap::UeContextReleaseCommand& m);
    void handle(const f1ap::Paging& m);
    void handle(const f1ap::GnbCuConfigurationUpdate& m);
    void set_active(bool on);   // the cell on or off the air
    void dl_sdu(const Ue& ue, std::uint8_t lcid, Bytes sdu);
    void on_dl_user(std::uint32_t du_ue, std::uint8_t drb_id, const entity::gtpu::UserData& u);
    void arm_ddds(std::uint32_t du_ue, std::uint8_t drb_id);
    void send_ddds(Ue::Drb& d, std::optional<std::uint32_t> polling_nru_sn);
    void drop_drbs(Ue& ue);
    void supervise();
    Result<Bytes> cell_group(const std::set<std::uint8_t>& srbs, const std::vector<Ue::Drb>& drbs = {},
                             const std::vector<std::uint8_t>& release_lcids = {}) const;
    /// Sets up and releases DRBs; their F1-U ends and the cell group's RLC bearers.
    std::vector<f1ap::DrbSetup> drbs_change(Ue& ue, const std::vector<f1ap::DrbToSetup>& add,
                                            const std::vector<std::uint8_t>& release, std::vector<Ue::Drb>& added,
                                            std::vector<std::uint8_t>& released_lcids);
    Ue* by_du(std::uint32_t id);
    air::Frame frame(air::FrameType t, std::uint32_t radio_id) const;
    std::uint16_t sfn() const noexcept;

    Executor& ex_;
    IEventSink& events_;
    DuConfig cfg_;
    IAssoc& f1_;
    std::function<void(air::Frame)> to_air_;
    std::shared_ptr<bool> alive_;

    bool active_ = false;
    std::uint8_t transaction_ = 0;
    std::optional<TimerId> setup_retry_;
    std::optional<TimerId> mib_timer_;
    std::optional<TimerId> sib1_timer_;
    std::optional<TimerId> supervision_;
    Bytes mib_frame_;    // BCCH-BCH, as broadcast
    Bytes sib1_frame_;   // BCCH-DL-SCH, as broadcast

    std::uint32_t next_du_ue_ = 1;
    std::uint16_t next_rnti_ = 0x4601;
    struct Ra {
        std::uint16_t tc_rnti = 0;
        Millis at = 0;
    };
    std::map<std::uint32_t, Ra> ra_;   // (RA-RNTI << 8 | preamble) -> the TC-RNTI given
    std::map<std::uint32_t, Ue> ues_;   // by gNB-DU UE F1AP ID
    std::map<std::uint16_t, std::uint32_t> by_rnti_;
    std::unique_ptr<entity::gtpu::Endpoint> f1u_;
    std::uint16_t seq_ = 0;
    std::uint64_t f1_ups_ = 0;   // F1 associations that came up (P2 Q3)
    DuStats stats_;
};

} // namespace ksim::proc::ran
