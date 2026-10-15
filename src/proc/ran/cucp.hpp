// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The gNB-CU-CP (P1 N7; TS 38.413 j40, TS 38.473 j40, TS 38.331 j40; ADR 0009
// point h): one DU over F1, one AMF over NG-C, and each UE's RRC with the
// PDCP of its SRB1 and SRB2.
//
//  - F1 Setup answered with the DU's cell activated; NG Setup sent once NG-C
//    is up, with the TAs of that cell, and repeated after a failure's time to
//    wait. Both are sent again when their association comes back.
//  - A UE: INITIAL UL RRC MESSAGE TRANSFER (RRCSetupRequest) answered with
//    RRCSetup; RRCSetupComplete becomes an INITIAL UE MESSAGE (with the
//    5G-S-TMSI rebuilt from Part1 and Part2); NAS both ways in DL/UL NAS
//    TRANSPORT and DL/UL InformationTransfer.
//  - INITIAL CONTEXT SETUP: K_gNB taken into SecretBytes at once; the DU asked
//    for SRB2 (UE CONTEXT SETUP); the AS security mode command with the first
//    preferred algorithms the UE supports (128-NIA2/NEA2 by default, D1;
//    NIA0/NEA0 only with the bisect switch); a capability enquiry when the
//    request carried no UE radio capability, reported to the AMF; then
//    RRCReconfiguration with SRB2 and the NAS PDU; the response once the UE
//    completes it. A failure on the way answers INITIAL CONTEXT SETUP FAILURE.
//  - UE CONTEXT RELEASE COMMAND: RRCRelease inside the F1 UE CONTEXT RELEASE
//    COMMAND, then UE CONTEXT RELEASE COMPLETE. An F1 release request (the
//    DU lost the UE) becomes UE CONTEXT RELEASE REQUEST.
//  - PAGING to the DU when its TAI is listed; NG RESET (whole or partial)
//    releases the UEs locally and is acknowledged; AMF STATUS INDICATION is an
//    event; AMF CONFIGURATION UPDATE is acknowledged.
//  - TS 38.413 §10: a PDU that does not decode, a procedure outside the P1 set
//    with criticality reject, an IE missing, or a UE-associated message for an
//    unknown RAN UE NGAP ID is answered with an ERROR INDICATION; nothing an
//    AMF sends ends the process (L15).
//
//  - PDU sessions (P1 N10), one procedure at a time per UE: a PDU SESSION
//    RESOURCE SETUP REQUEST (or the sessions of an INITIAL CONTEXT SETUP
//    REQUEST, after its first reconfiguration) gets a DRB per session (all its
//    flows, the default DRB), the CU-UP's bearer context over E1 (BEARER
//    CONTEXT SETUP, then MODIFICATION to add), the DU's DRB over F1 (UE
//    CONTEXT MODIFICATION with the CU-UP's F1-U end), the DU's F1-U end back to
//    the CU-UP, then RRCReconfiguration with the DRB and the session's NAS, and
//    the response with the CU-UP's N3 end once the UE completes it. A release
//    reconfigures the UE first, then the DU and the CU-UP. E1 is the CU-UP's
//    association (it sends gNB-CU-UP E1 SETUP).
//
// Not in P1: handover (P3), several DUs, CU-UPs or AMFs.

#pragma once

#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "codec/asn1/msg/e1ap.hpp"
#include "codec/asn1/msg/f1ap.hpp"
#include "proc/ran/du.hpp"
#include "codec/asn1/msg/ngap.hpp"
#include "codec/asn1/msg/rrc.hpp"
#include "entity/pdcp/pdcp.hpp"
#include "platform/event.hpp"
#include "platform/executor.hpp"
#include "platform/secret.hpp"
#include "platform/transport.hpp"

namespace ksim::proc::ran {

inline constexpr std::uint32_t kNgapPpid = 60;   // TS 38.412 §7

struct CuCpConfig {
    std::string id = "gnb:cucp1";       // the events' subject
    std::string name = "ksim-gnb1";     // RAN node name and gNB-CU name
    rrc::Plmn plmn{"001", "01"};
    std::uint32_t gnb_id = 0x1A0;
    std::uint8_t gnb_id_bits = 22;
    std::vector<ngap::Snssai> slices{ngap::Snssai{1, std::nullopt}};
    std::vector<std::uint8_t> nea_preference{2, 1, 0};
    std::vector<std::uint8_t> nia_preference{2, 1};
    bool allow_null = false;            // D1: NIA0/NEA0 only as the bisect switch
    std::string paging_drx = "v128";
};

struct CuCpStats {
    std::uint64_t ngap_rx = 0;
    std::uint64_t ngap_errors = 0;       // ERROR INDICATIONs sent
    std::uint64_t wrong_ppid = 0;        // P2 Q2: messages under another protocol's PPID, dropped
    std::uint64_t error_indications_rx = 0;
    std::uint64_t f1_errors = 0;
    std::uint64_t ics_ok = 0;
    std::uint64_t ics_failed = 0;
};

/// A RAN UE context as ksim-ctl's ue-list shows it (cli.md §4).
struct CuCpUeView {
    std::uint32_t ran_ue = 0;
    std::optional<std::uint64_t> amf_ue;
    std::uint16_t c_rnti = 0;
    const char* phase = "";
};

class CuCp {
public:
    /// `e1`: the CU-UP's association (none: sessions are refused).
    CuCp(Executor& ex, IEventSink& events, CuCpConfig cfg, IAssoc& ngap, IAssoc& f1, IAssoc* e1 = nullptr);
    ~CuCp();
    CuCp(const CuCp&) = delete;
    CuCp& operator=(const CuCp&) = delete;

    bool ng_ready() const noexcept { return ng_ready_; }
    bool f1_ready() const noexcept { return du_.has_value(); }
    std::size_t ues() const noexcept { return ues_.size(); }
    const CuCpStats& stats() const noexcept { return stats_; }
    std::vector<CuCpUeView> ue_list() const;
    bool e1_ready() const noexcept { return e1_ready_; }
    /// The PDU sessions the RAN holds for the UE with this RAN UE NGAP ID.
    std::vector<std::uint8_t> sessions_of(std::uint32_t ran_ue) const;
    /// A gNB-initiated release (TS 38.413 §8.3.2; `ksim-ctl gnb ue-release`):
    /// UE CONTEXT RELEASE REQUEST with a radio network cause ("user-inactivity").
    /// Errc::invalid_argument for a UE the AMF does not know yet.
    Result<void> request_release(std::uint32_t ran_ue, const std::string& cause = "user-inactivity");
    /// The AMF Name of the last NG SETUP RESPONSE, "" before one.
    const std::string& amf_name() const noexcept { return amf_name_; }

    /// For tests and fuzzing: an NG-C message as if it came from the AMF.
    void on_ngap(ByteView msg);

private:
    /// P2 Q2: whether a message's PPID is the link's (TS 38.412, 38.472, 37.482 §7); counted and evented if not.
    bool ppid_ok(const SctpMeta& m, std::uint32_t want, const char* link);
    enum class Phase : std::uint8_t { setup, connected, securing, capability, reconfiguring, active, releasing };
    static const char* phase_name(Phase p) noexcept;

    struct Ue {
        std::uint32_t cu_ue = 0;
        std::uint32_t du_ue = 0;
        bool du_gone = false;            // P2 Q2: F1 was lost while the AMF knew the UE
        std::uint32_t ran_ue = 0;
        std::optional<std::uint64_t> amf_ue;
        std::uint16_t c_rnti = 0;
        Phase phase = Phase::setup;
        rrc::EstablishmentCause cause = rrc::EstablishmentCause::mo_signalling;
        std::optional<std::uint64_t> s_tmsi_part1;
        std::unique_ptr<entity::Pdcp> srb1;
        std::unique_ptr<entity::Pdcp> srb2;
        std::uint8_t tid = 0;
        std::optional<Bytes> ics_nas;
        std::optional<Bytes> nr_capability;
        std::optional<rrc::CellGroup> srb2_cell_group;
        std::optional<std::uint8_t> nea;
        std::optional<std::uint8_t> nia;
        SecretBytes kgnb;
        SecretBytes k_rrc_int;
        SecretBytes k_rrc_enc;
        bool capture = false;            // the next SRB1 PDU goes into a release command
        std::optional<Bytes> captured;
        // PDU sessions (N10)
        struct Session {
            ngap::SessionSetupItem item;
            std::uint8_t drb_id = 1;
            std::optional<e1ap::SessionSetup> up;       // the CU-UP's answer (N3 DL end, F1-U UL ends)
            std::optional<f1ap::DrbSetup> du;           // the DU's answer (F1-U DL end)
            bool integrity = false;
        };
        std::map<std::uint8_t, Session> sessions;       // set up, by PSI
        std::optional<std::uint32_t> cu_up_ue;
        std::optional<ngap::Ambr> ue_ambr;
        struct Job {
            enum class Kind : std::uint8_t { setup, release } kind = Kind::setup;
            bool ics = false;                           // the sessions of an INITIAL CONTEXT SETUP
            std::vector<ngap::SessionSetupItem> items;
            std::optional<Bytes> nas;                   // the message's own NAS PDU
            std::vector<ngap::SessionCause> release;
            enum class Stage : std::uint8_t { waiting, e1, f1, e1_mod, rrc } stage = Stage::waiting;
            std::map<std::uint8_t, Session> pending;    // being set up
            std::vector<ngap::SessionCause> failed;
            std::optional<rrc::CellGroup> cell_group;   // the DU's, for the new DRBs
        };
        std::deque<Job> jobs;
    };

    void on_ng_event(LinkEvent e);
    void on_f1_event(LinkEvent e);
    void on_f1(ByteView msg);
    void send_ngap(const ngap::Pdu& p, std::optional<std::uint32_t> ran_ue);
    void send_f1(const f1ap::Pdu& p, bool ue_associated);
    void ng_setup();
    void error_indication(ngap::UeIds ids, const char* group, const char* value);

    // F1
    void handle(const f1ap::F1SetupRequest& m);
    void handle(const f1ap::InitialUlRrcMessageTransfer& m);
    void handle(const f1ap::UlRrcMessageTransfer& m);
    void handle(const f1ap::UeContextSetupResponse& m);
    void handle(const f1ap::UeContextSetupFailure& m);
    void handle(const f1ap::UeContextReleaseRequest& m);
    void handle(const f1ap::UeContextReleaseComplete& m);

    // NG-C
    void handle(const ngap::NgSetupResponse& m);
    void handle(const ngap::NgSetupFailure& m);
    void handle(const ngap::DownlinkNasTransport& m);
    void handle(ngap::InitialContextSetupRequest& m);
    void handle(const ngap::UeContextReleaseCommand& m);
    void handle(const ngap::UeContextModificationRequest& m);
    void handle(const ngap::Paging& m);
    void handle(const ngap::NgReset& m);

    // E1 and sessions (N10)
    void on_e1(ByteView msg);
    void on_e1_event(LinkEvent e);
    void send_e1(const e1ap::Pdu& p, bool ue_associated);
    void handle(const ngap::PduSessionResourceSetupRequest& m);
    void handle(const ngap::PduSessionResourceReleaseCommand& m);
    void handle(const ngap::PduSessionResourceModifyRequest& m);
    void handle(const f1ap::UeContextModificationResponse& m);
    void handle(const e1ap::BearerContextSetupResponse& m);
    void handle(const e1ap::BearerContextModificationResponse& m);
    void start_job(Ue& ue);
    void job_failed(Ue& ue, const char* group, const char* value);
    void job_rrc(Ue& ue);
    void job_done(Ue& ue);
    void finish_ics(Ue& ue, std::vector<ngap::SessionSetupOk> ok, std::vector<ngap::SessionCause> failed);
    Ue* by_cu_up(std::uint32_t id);

    // RRC
    void on_dcch(std::uint32_t cu_ue, Bytes sdu);
    void on_srb_integrity_failure(std::uint32_t cu_ue);
    void start_security(Ue& ue);
    void after_security(Ue& ue);
    void reconfigure(Ue& ue);
    void ics_failed(Ue& ue, const char* group, const char* value);
    std::unique_ptr<entity::Pdcp> make_srb(std::uint32_t cu_ue, std::uint8_t srb);
    void dl_dcch(Ue& ue, Result<Bytes> msg, std::uint8_t srb = 0);
    void release_locally(Ue& ue);

    Ue* by_cu(std::uint32_t id);
    Ue* by_ran(std::uint32_t id);
    ngap::NrCgi nr_cgi() const;
    ngap::Tai tai() const;
    std::uint8_t next_tid(Ue& ue);

    Executor& ex_;
    IEventSink& events_;
    CuCpConfig cfg_;
    IAssoc& ng_;
    IAssoc& f1_;
    std::shared_ptr<bool> alive_;

    IAssoc* e1_ = nullptr;
    bool e1_ready_ = false;
    bool ng_ready_ = false;
    std::string amf_name_;
    std::optional<TimerId> ng_retry_;
    struct DuInfo {
        std::uint64_t du_id = 0;
        f1ap::NrCgi cgi;
        std::uint32_t tac = 0;
    };
    std::optional<DuInfo> du_;
    std::map<std::uint32_t, Ue> ues_;   // by gNB-CU UE F1AP ID
    std::uint32_t next_ue_ = 1;
    CuCpStats stats_;
};

} // namespace ksim::proc::ran
