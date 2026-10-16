// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The gNB-CU-UP (P1 N10; TS 38.401, TS 37.483 j40 (E1AP), TS 38.323 (PDCP),
// TS 37.324 (SDAP), TS 29.281 (GTP-U)). It sets up E1 towards the CU-CP
// (gNB-CU-UP E1 Setup, it initiates) and keeps a bearer context per UE: per
// PDU session an N3 tunnel (its DL end, the UPF's UL end) and per DRB a PDCP
// entity on the UP keys E1 hands it, the SDAP mapping of QoS flows to the DRB,
// and an F1-U tunnel (its UL end, the DU's DL end once the CU-CP tells it).
//
// Downlink: N3 G-PDU (PDU Session Container, QFI) -> the flow's DRB, an SDAP
// header if the DRB has one -> PDCP (ciphered, integrity if the session asks
// for it) -> F1-U G-PDU with the NR-U DL USER DATA header and its sequence
// number. Uplink: F1-U G-PDU -> PDCP -> SDAP header (the QFI) -> N3 G-PDU with
// the UL PDU Session Container. UP security policy (KS-NGAP-B5, ADR 0009 b):
// integrity "required" is honoured with the CU-CP's NIA, "preferred" is off;
// ciphering "not-needed" is off, otherwise on.

#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "codec/asn1/msg/e1ap.hpp"
#include "entity/gtpu/gtpu.hpp"
#include "entity/pdcp/pdcp.hpp"
#include "platform/event.hpp"
#include "platform/executor.hpp"
#include "platform/transport.hpp"

namespace ksim::proc::ran {

inline constexpr std::uint32_t kE1apPpid = 64;

struct CuUpConfig {
    std::string id = "gnb:cuup1";                 // the events' subject
    std::uint64_t cu_up_id = 1;
    std::string name = "ksim-cuup1";
    e1ap::PlmnId plmn{0x00, 0xF1, 0x10};
    std::vector<e1ap::Snssai> slices{e1ap::Snssai{1, std::nullopt}};
    std::array<std::uint8_t, 4> n3_addr{};       // the N3 tunnel address it advertises
    std::array<std::uint8_t, 4> f1u_addr{};      // the F1-U tunnel address it advertises
    std::uint16_t gtpu_port = 2152;
};

/// P2 Q7 (metrics v0): N3's traffic of one QFI.
struct QfiTraffic {
    std::uint64_t ul_bytes = 0;
    std::uint64_t dl_bytes = 0;
    std::uint64_t ul_packets = 0;
    std::uint64_t dl_packets = 0;
};

struct CuUpStats {
    std::uint64_t contexts_setup = 0;
    std::uint64_t dl_packets = 0;      // N3 to F1-U
    std::uint64_t ul_packets = 0;      // F1-U to N3
    std::uint64_t dropped = 0;         // no DRB for the flow, no F1-U DL end yet, …
    std::uint64_t ddds_rx = 0;         // P2 Q4: the DU's DL DATA DELIVERY STATUS frames
    std::uint64_t inactivity_reports = 0;   // P2 Q5: BEARER CONTEXT INACTIVITY NOTIFICATIONs sent
    std::uint64_t e1_errors = 0;
};

class CuUp {
public:
    CuUp(Executor& ex, IEventSink& events, CuUpConfig cfg, IAssoc& e1, IDatagram& n3, IDatagram& f1u);
    ~CuUp();
    CuUp(const CuUp&) = delete;
    CuUp& operator=(const CuUp&) = delete;

    bool e1_ready() const noexcept { return e1_ready_; }
    std::size_t contexts() const noexcept { return ctx_.size(); }
    /// P2 Q10: each DRB with its QoS flows and its packets (the bearers view).
    struct DrbStat {
        std::uint32_t cu_up_ue = 0;
        std::uint8_t psi = 0;
        std::uint8_t drb = 0;
        bool default_drb = false;
        std::vector<std::uint8_t> qfis;
        std::uint64_t ul_packets = 0;
        std::uint64_t dl_packets = 0;
    };
    std::vector<DrbStat> drb_stats() const;
    const CuUpStats& stats() const noexcept { return stats_; }
    /// N3's traffic per QFI (P2 Q7, metrics v0).
    const std::map<std::uint8_t, QfiTraffic>& per_qfi() const noexcept { return per_qfi_; }
    /// The DU's last DL DATA DELIVERY STATUS, any DRB (P2 Q4).
    const std::optional<entity::gtpu::DeliveryStatus>& last_ddds() const noexcept { return last_ddds_; }
    entity::gtpu::Endpoint& n3() noexcept { return n3_; }

private:
    struct Drb {
        std::uint8_t id = 1;
        std::unique_ptr<entity::Pdcp> pdcp;
        std::uint32_t f1u_ul_teid = 0;
        std::optional<e1ap::GtpTunnel> f1u_dl;
        bool sdap_ul = true;
        bool sdap_dl = true;
        std::vector<std::uint8_t> qfis;
        std::uint32_t nru_sn = 0;
        std::uint64_t ul_packets = 0;   // P2 Q10: per DRB
        std::uint64_t dl_packets = 0;
    };
    struct Session {
        std::uint8_t psi = 1;
        e1ap::GtpTunnel ng_ul;
        std::uint32_t ng_dl_teid = 0;
        bool integrity = false;
        bool ciphering = true;
        std::map<std::uint8_t, Drb> drbs;
        std::map<std::uint8_t, std::uint8_t> qfi_to_drb;
        std::optional<std::uint8_t> default_drb;
        std::optional<std::uint64_t> dl_ambr;   // P2 Q10: from E1, recorded (not enforced, KS-NGAP-G4)
    };
    struct Context {
        std::uint32_t cu_cp_ue = 0;
        std::uint32_t cu_up_ue = 0;
        std::uint8_t nea = 2;
        std::optional<std::uint8_t> nia;
        SecretBytes k_enc;
        SecretBytes k_int;
        std::map<std::uint8_t, Session> sessions;
        // P2 Q5 (TS 37.483 8.3.1.2, 8.6.3): inactivity monitoring at activity level "ue".
        std::optional<Millis> inactivity;     // the UE Inactivity Timer
        Millis last_activity = 0;             // the last UL or DL user data
        bool reported_inactive = false;
    };

    void on_e1_event(LinkEvent e);
    void on_e1(ByteView msg);
    void send_e1(const e1ap::Pdu& p, bool ue);
    void handle(const e1ap::E1SetupResponse& m);
    void handle(const e1ap::E1SetupFailure& m);
    void handle(const e1ap::BearerContextSetupRequest& m);
    void handle(const e1ap::BearerContextModificationRequest& m);
    void handle(const e1ap::BearerContextReleaseCommand& m);
    void activity(Context& c);                        // user data passed: the UE is active
    void watch_inactivity(std::uint32_t cu_up_ue);    // arms the check at last_activity + the timer

    Result<e1ap::SessionSetup> setup_session(Context& c, const e1ap::SessionToSetup& s);
    Result<e1ap::DrbSetup> add_drb(Context& c, Session& sess, const e1ap::DrbToSetup& d);
    void remove_drb(Session& s, std::uint8_t drb_id);
    void remap(Session& s, Drb& d, const std::vector<e1ap::QosFlow>& flows);
    void release_session(Session& s);
    void on_n3(std::uint32_t cu_up_ue, std::uint8_t psi, const entity::gtpu::UserData& d);
    void on_f1u(std::uint32_t cu_up_ue, std::uint8_t psi, std::uint8_t drb, const entity::gtpu::UserData& d);
    Context* by_up(std::uint32_t id);

    Executor& ex_;
    IEventSink& events_;
    CuUpConfig cfg_;
    IAssoc& e1_;
    entity::gtpu::Endpoint n3_;
    entity::gtpu::Endpoint f1u_;
    std::shared_ptr<bool> alive_;
    bool e1_ready_ = false;
    std::uint8_t transaction_ = 0;
    std::map<std::uint32_t, Context> ctx_;   // by gNB-CU-UP UE E1AP ID
    std::uint32_t next_ue_ = 1;
    CuUpStats stats_;
    std::optional<entity::gtpu::DeliveryStatus> last_ddds_;
    std::map<std::uint8_t, QfiTraffic> per_qfi_;
};

} // namespace ksim::proc::ran
