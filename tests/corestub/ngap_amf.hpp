// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The core stub's AMF, NGAP side (P1 N7, ADR 0009 point f): NG Setup, then one
// NAS-side Amf per UE behind INITIAL UE MESSAGE, DL/UL NAS TRANSPORT, INITIAL
// CONTEXT SETUP (the REGISTRATION ACCEPT with K_gNB) and UE CONTEXT RELEASE.
// It checks what the gNB sends at NGAP level (the TAI and cell of the user
// location, the establishment cause, consistent UE NGAP IDs, the gNB ID and
// TAs of NG Setup, the response to each context setup and release) and keeps
// the verdicts with the NAS side's.
//
// N10: one SMF for every UE and, with an N3 port, a UPF behind it; a session's
// accept goes to the gNB in PDU SESSION RESOURCE SETUP REQUEST (the gNB's N3
// end comes back to the UPF), a release in PDU SESSION RESOURCE RELEASE
// COMMAND, both answers checked.
//
// N12: a UE's NAS context outlives its N2 connection: a returning UE (its
// 5G-S-TMSI in the INITIAL UE MESSAGE, or the 5G-GUTI or 5G-S-TMSI of its
// initial message) gets its context back under a new AMF UE NGAP ID. A
// release (UE CONTEXT RELEASE COMPLETE) deactivates the UE's user plane;
// downlink held for an idle UE pages it; a SERVICE ACCEPT goes in an INITIAL
// CONTEXT SETUP REQUEST with the sessions brought back. A new association
// (the gNB or this AMF restarted) or a second NG SETUP drops every N2
// connection but keeps every NAS context.
//
// P3 R2 (ADR 0013 point 6): several gNBs at once, each its own association in
// an IAssocPool, with the TAs its NG Setup (or RAN Configuration Update) gave.
// Every TA of the AMF counts (Profile::tacs), not the first only; a UE keeps the
// gNB it came through; paging goes to every gNB serving a TA of the UE's; an
// association that goes, or a second NG SETUP on it, drops the N2 connections
// of that gNB's UEs only.

#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "amf.hpp"
#include "smf.hpp"
#include "smsf.hpp"
#include "upf.hpp"
#include "codec/asn1/msg/ngap.hpp"
#include "platform/assoc_pool.hpp"
#include "platform/transport.hpp"

namespace ksim::corestub {

class NgapAmf {
public:
    /// `n3`: the UPF's GTP-U port (none: sessions get no user plane), advertised as `n3_addr`.
    NgapAmf(Executor& ex, Home& home, nas::ie::Plmn plmn, Profile p, IAssoc& ng, IDatagram* n3 = nullptr,
            std::array<std::uint8_t, 4> n3_addr = {127, 0, 0, 1});
    /// P3 R2: several gNBs, each an association of `ng`.
    NgapAmf(Executor& ex, Home& home, nas::ie::Plmn plmn, Profile p, IAssocPool& ng, IDatagram* n3 = nullptr,
            std::array<std::uint8_t, 4> n3_addr = {127, 0, 0, 1});
    NgapAmf(const NgapAmf&) = delete;
    NgapAmf& operator=(const NgapAmf&) = delete;

    bool ng_setup_done() const noexcept { return ng_setup_; }
    /// P3 R2: the gNBs set up now, and the TACs each serves.
    std::size_t gnbs() const noexcept { return gnbs_.size(); }
    std::vector<std::uint32_t> gnb_tacs(std::uint32_t gnb_id) const;
    /// P3 R4: each gNB with NG set up, its ID and the TACs it serves now (the report's GNB.*).
    std::vector<std::pair<std::uint32_t, std::vector<std::uint32_t>>> gnb_list() const;
    std::size_t ues() const noexcept { return ues_.size(); }
    /// The UE Radio Capability the gNB indicated for a UE (N15), if any.
    std::optional<Bytes> radio_capability(std::uint64_t amf_ue);
    /// The NAS side of the n-th UE that came (0 first), or nullptr.
    Amf* nas(std::size_t n = 0);
    /// The NAS side of the latest UE with this SUPI, or nullptr.
    Amf* nas_by_supi(const std::string& supi);
    std::vector<Verdict> failures() const;
    const std::vector<std::string>& received() const noexcept { return received_; }
    std::size_t count(std::string_view message) const;
    std::uint64_t error_indications() const noexcept { return error_indications_; }
    std::uint64_t notifies() const noexcept { return notifies_; }   // P2 Q10: PDU SESSION RESOURCE NOTIFYs
    std::uint64_t notify_fulfilled() const noexcept { return notify_fulfilled_; }   // P2 Q11
    std::uint64_t notify_not_fulfilled() const noexcept { return notify_not_fulfilled_; }
    std::uint64_t refused_flows() const noexcept { return refused_flows_; }   // setups with flows not admitted
    /// The cause of the last UE CONTEXT RELEASE REQUEST, "" before one (P2 Q5: a peer
    /// CU-CP's release is seen here only).
    const std::string& last_release_cause() const noexcept { return last_release_cause_; }
    /// P2 Q14 prep (KS-PLAT-D20): the UE CONTEXT RELEASE COMMAND comes `ms` late, after a
    /// de-registration and in answer to a UE CONTEXT RELEASE REQUEST, as a loaded core's may.
    void set_release_delay(Millis ms) noexcept { release_delay_ = ms; }
    Millis release_delay() const noexcept { return release_delay_; }
    /// How the last NG association ended: "shutdown" (SCTP's graceful SHUTDOWN), "lost" (an
    /// ABORT or a lost peer), "-" while none has.
    const std::string& ng_end() const noexcept { return ng_end_; }
    /// UE CONTEXT RELEASE REQUESTs for a UE that had asked already, or whose release the AMF
    /// had begun: TS 38.413 §8.3.2 wants one, the command its answer.
    std::uint64_t repeated_release_requests() const noexcept { return repeated_requests_; }
    std::optional<ngap::Cause> last_error_cause() const { return last_error_; }

    /// Downlink NGAP as a test scripts it (raw octets), to the gNB the last message came from.
    void send_raw(ByteView pdu, std::uint16_t stream = 0);
    void send(const ngap::Pdu& p, std::uint16_t stream = 0);
    /// UE CONTEXT RELEASE COMMAND for the n-th UE.
    void release(std::size_t n, ngap::Cause cause);
    /// A new association replaces the old one (N12); the NAS contexts stay.
    void rebind(IAssoc& ng);
    /// AMF STATUS INDICATION: this AMF's GUAMI unavailable (a draining AMF, row amf-ueransim.063).
    void status_indication();
    /// Network-initiated de-registration of the UE with this SUPI.
    bool deregister(const std::string& supi, bool reregistration_required);
    /// T3512 for the accepts from now on (a subscription change).
    void set_t3512(std::optional<int> seconds);
    /// P2 Q8: the NAS algorithms the next SECURITY MODE COMMAND selects (row ksim-p2.nas-nea1-nia1).
    void set_nas_algorithms(std::uint8_t ea, std::uint8_t ia);
    std::size_t pagings() const noexcept { return pagings_; }
    struct UeIds {
        std::uint64_t amf = 0;
        std::uint32_t ran = 0;
    };
    std::optional<UeIds> ids(std::size_t n) const;
    Smf& smf() noexcept { return smf_; }
    Smsf& smsf() noexcept { return smsf_; }
    /// N13: SMS in a UE's subscription or not (ksim-ctl stub sms-sub); the next accept says so.
    void set_sms_subscribed(const std::string& supi, bool on);
    Upf* upf() noexcept { return upf_.get(); }

private:
    struct Ue {
        std::uint64_t amf_ue = 0;
        std::uint32_t ran_ue = 0;
        LinkId link = 1;                       // P3 R2: the gNB's association
        std::unique_ptr<Amf> nas;
        bool ics_sent = false;
        bool ics_answered = false;
        bool ambr_sent = false;                // the UE AMBR went in this UE's NG connection (P2 Q4)
        bool releasing = false;
        bool asked = false;                    // a UE CONTEXT RELEASE REQUEST came (P2 Q14 prep)
        std::optional<Bytes> radio_capability;
        std::vector<std::uint8_t> setups;      // PSIs with a resource setup awaiting its response
        std::vector<std::uint8_t> releases;    // and with a release awaiting its response
        std::vector<std::uint8_t> modifies;    // P2 Q10: and with a modification awaiting its response
        bool connected = true;                 // the N2 connection is up
        std::optional<Millis> paged_at;
    };

    void on_message(ByteView msg);
    void check(bool ok, const char* clause, const char* what, std::string detail = {});
    Ue* by_amf(std::uint64_t id);
    void attach_nas(Ue& ue);
    void relink(Ue& ue);
    Ue* returning(const ngap::InitialUeMessage& m);
    void send_ics(Ue& ue, Bytes nas, SecretBytes kgnb, std::vector<ngap::SessionSetupItem> sessions);
    static std::optional<ngap::Ambr> first_ambr(Ue& u);
    static constexpr ngap::Ambr kUeAmbr{1'000'000'000, 1'000'000'000};   // bit/s DL, UL
    void page(const std::string& supi);
    void drop_n2(Ue& ue);
    std::uint16_t stream_of(const Ue& ue) const;
    void send_to(LinkId link, const ngap::Pdu& p, std::uint16_t stream);
    void send_ue(const Ue& ue, const ngap::Pdu& p);
    /// A TAC of this AMF (Profile::tacs; 1 when the profile names none).
    bool serves(std::uint32_t tac) const;
    NgapAmf(Executor& ex, Home& home, nas::ie::Plmn plmn, Profile p, std::unique_ptr<IAssocPool> own, IAssocPool* ng,
            IDatagram* n3, std::array<std::uint8_t, 4> n3_addr);
    struct Gnb {
        std::uint32_t gnb_id = 0;
        std::vector<std::uint32_t> tacs;
    };

    Executor& ex_;
    Home& home_;
    nas::ie::Plmn plmn_;
    Profile p_;
    std::unique_ptr<IAssocPool> own_ng_;   // one gNB's association, seen as a pool of one
    IAssocPool* ng_ = nullptr;
    LinkId rx_link_ = 1;                   // the association the message being handled came on
    std::map<LinkId, Gnb> gnbs_;
    std::unique_ptr<Upf> upf_;
    Smf smf_;
    Smsf smsf_;
    std::map<std::string, bool> sms_sub_;   // per SUPI, over the profile's sms_subscribed
    bool ng_setup_ = false;
    std::map<std::uint64_t, Ue> ues_;   // by AMF UE NGAP ID
    std::vector<std::uint64_t> order_;  // AMF UE NGAP IDs in arrival order
    std::uint64_t next_amf_ue_ = 7;
    std::vector<Verdict> verdicts_;
    std::vector<std::string> received_;
    std::uint64_t error_indications_ = 0;
    std::uint64_t notifies_ = 0;
    std::uint64_t notify_fulfilled_ = 0;
    std::uint64_t notify_not_fulfilled_ = 0;
    std::uint64_t refused_flows_ = 0;
    std::string last_release_cause_;
    Millis release_delay_ = 0;
    std::string ng_end_ = "-";
    std::uint64_t repeated_requests_ = 0;
    void on_ng_event(LinkId link, LinkEvent e);
    void wire_ng();
    /// The UE's UE CONTEXT RELEASE COMMAND, at once or release_delay_ late (if it is still there
    /// and not released by then).
    void command_release(std::uint64_t amf_ue, const ngap::Cause& cause);
    std::optional<ngap::Cause> last_error_;
    std::size_t pagings_ = 0;
};

} // namespace ksim::corestub
