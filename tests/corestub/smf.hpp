// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The core stub's SMF (P1 N10, ADR 0009 point f): the network half of 5GSM for
// every UE of the stub, as its session profile says. It answers PDU SESSION
// ESTABLISHMENT REQUEST with an accept (an IPv4 address from its pool, the
// default QoS rule with a match-all filter on QFI 1, the session-AMBR, the
// DNS server and link MTU in ePCO) and the N2 information for the gNB, or a
// reject with a cause and back-off timer; answers PDU SESSION RELEASE
// REQUEST with a RELEASE COMMAND; releases or modifies a session when a test
// asks. Each UE message is checked (the PTI, the session type, the ePCO
// requests, the release complete's PTI) and the checks are kept as verdicts.
//
// P2 Q10: a session can have QoS flows beyond the default one, each with a QoS rule
// (precedence, packet filters) and a flow description (5QI): from the profile at
// establishment, or added and deleted at run time by a network-requested modification
// (the 5GSM command inside a PDU SESSION RESOURCE MODIFY REQUEST, TS 23.502 4.3.3.2).
// The UPF gets the session's rules once the gNB answered, to check the uplink QFIs and
// mark the downlink. A flow the gNB released itself (PDU SESSION RESOURCE NOTIFY) has
// its rule deleted at the UE.

#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "codec/asn1/msg/ngap.hpp"
#include "codec/ip/ipv4.hpp"
#include "codec/nas/ie/ie.hpp"
#include "codec/nas/nas.hpp"
#include "platform/yaml.hpp"
#include "verdict.hpp"

namespace ksim::corestub {

class Upf;

/// A QoS flow beyond the session's default one (P2 Q10).
struct FlowSpec {
    std::uint8_t qfi = 2;
    std::uint16_t five_qi = 9;
    std::uint8_t precedence = 10;
    std::uint8_t direction = 3;    // TS 24.501 9.11.4.13: 1 downlink only, 2 uplink only, 3 bidirectional
    std::vector<nas::ie::QosRules::Component> components;
    std::string filter;            // the components as written (parse_filter)
};
/// A packet filter written as comma-separated components (Table 9.11.4.13.1): all,
/// remote=A.B.C.D[/N], local=A.B.C.D[/N], proto=N, lport=N, lports=N-M, rport=N,
/// rports=N-M, spi=N, tos=V[/M] (numbers in decimal or 0x hex).
Result<std::vector<nas::ie::QosRules::Component>> parse_filter(const std::string& text);
/// "uplink", "downlink" or "bidirectional" as 9.11.4.13's direction value.
Result<std::uint8_t> parse_direction(const std::string& text);

struct SessionProfile {
    enum class Establishment : std::uint8_t { accept, reject, silent };
    Establishment establishment = Establishment::accept;
    std::uint8_t reject_cause = 26;
    std::optional<int> backoff_s;                  // the reject's Back-off timer value
    int rejects = 0;                               // with reject: that many, then accepts; 0: always
    std::vector<std::string> dnns{"internet", "ims"};
    // A DNN the stub rejects `backoff_dnn_rejects` times with #29 and a back-off
    // of `backoff_dnn_s`, then accepts (the ksim-p1.backoff row on the stub).
    std::string backoff_dnn = "ksim-backoff";
    int backoff_dnn_s = 6;
    int backoff_dnn_rejects = 1;
    ip::Addr pool{10, 60, 0, 2};                   // the first address given
    ip::Addr dns{10, 60, 0, 1};
    ip::Addr dn{10, 60, 0, 1};                     // the DN reflector's address (any address is answered)
    std::uint16_t mtu = 1400;
    std::uint8_t qfi = 1;
    std::uint16_t five_qi = 9;
    std::uint32_t ambr_mbps = 1000;                // session-AMBR, both ways
    bool default_rule = true;                      // false: the accept's rules carry none (a UE check)
    // The gNB's UP Security Indication (TS 38.413 9.3.1.27; P2 Q9): each "required",
    // "preferred" or "not-needed"; "absent" for either leaves the IE out (kaluza-core's
    // SMF today). The maximum integrity-protected data rates, when set: "bitrate64kbs"
    // or "maximum-UE-rate".
    std::string up_integrity = "not-needed";
    std::string up_confidentiality = "required";
    std::optional<std::string> up_rate_ul;
    std::optional<std::string> up_rate_dl;
    // P2 Q10: the flows every new session gets beside the default one
    // (flows: [{qfi, five_qi, precedence, direction, filter}]).
    std::vector<FlowSpec> flows;

    static SessionProfile from_yaml(const Yaml& y);
};

/// What the AMF sends for the SMF.
struct SmAction {
    std::uint8_t psi = 0;
    Bytes sm;                                        // the 5GSM message for DL NAS TRANSPORT
    std::optional<ngap::SessionSetupItem> setup;     // with it: PDU SESSION RESOURCE SETUP REQUEST
    bool release_resources = false;                  // PDU SESSION RESOURCE RELEASE COMMAND with it
    std::optional<ngap::SessionModifyItem> modify;   // P2 Q10: with it, PDU SESSION RESOURCE MODIFY REQUEST
};

class Smf {
public:
    Smf(SessionProfile p, Upf* upf);
    Smf(const Smf&) = delete;
    Smf& operator=(const Smf&) = delete;

    SessionProfile& profile() noexcept { return p_; }

    /// A 5GSM message out of UL NAS TRANSPORT (the AMF checked the transport).
    std::vector<SmAction> on_uplink(const std::string& supi, std::uint8_t psi, ByteView sm,
                                    std::optional<std::uint8_t> request_type, const std::optional<std::string>& dnn,
                                    const std::optional<nas::ie::Snssai>& snssai);
    /// Whether the UE holds a session with this PSI (§7.3.2 c, for the AMF).
    bool known(const std::string& supi, std::uint8_t psi) const;
    void on_setup_response(const std::string& supi, std::uint8_t psi, const ngap::GtpTunnel& dl);
    void on_setup_failed(const std::string& supi, std::uint8_t psi);
    /// Network-requested release (§6.3.3.2), PTI 0.
    std::optional<SmAction> release(const std::string& supi, std::uint8_t psi, std::uint8_t cause);
    /// Network-requested modification (§6.3.2.2): a new session-AMBR.
    std::optional<SmAction> modify(const std::string& supi, std::uint8_t psi, std::uint32_t ambr_mbps);
    /// P2 Q10: a network-requested modification adding a QoS flow with its rule, or deleting
    /// one (not the default rule's); Errc::invalid_argument when the session cannot.
    Result<SmAction> qos_add(const std::string& supi, std::uint8_t psi, const FlowSpec& f);
    Result<SmAction> qos_del(const std::string& supi, std::uint8_t psi, std::uint8_t qfi);
    /// The gNB's answer to a modification: the UPF takes the rules of the flows it set up.
    void on_modify_response(const std::string& supi, std::uint8_t psi, const ngap::ModifyResponseTransfer& t);
    void on_modify_failed(const std::string& supi, std::uint8_t psi);
    /// QoS flows the gNB released itself (PDU SESSION RESOURCE NOTIFY, TS 23.502 4.3.3.2 1e):
    /// the UE is told to delete their rules (a 5GSM command alone, no N2).
    std::optional<SmAction> on_notify(const std::string& supi, std::uint8_t psi, const std::vector<std::uint8_t>& released);
    /// A DN ping to the UE's address in this session.
    Result<void> ping_ue(const std::string& supi, std::uint8_t psi, std::uint16_t seq);

    // N12: the user plane follows the UE between CM-CONNECTED and CM-IDLE.
    /// Every session of the UE loses its N3 downlink end (the N2 connection went).
    void deactivate(const std::string& supi);
    /// The sessions to bring back in an INITIAL CONTEXT SETUP (TS 23.502
    /// 4.2.3.2): `psis` (bit n for PSI n), each with the transfer it was set up with.
    std::vector<ngap::SessionSetupItem> reactivate(const std::string& supi, std::uint16_t psis) const;
    /// Bit n for each PSI the SMF holds for the UE (the PDU session status).
    std::uint16_t sessions_of(const std::string& supi) const;
    /// The sessions with downlink waiting (bit n for PSI n).
    std::uint16_t pending_of(const std::string& supi) const;
    /// Every session of the UE goes without signalling (network de-registration).
    void release_all(const std::string& supi);
    /// Downlink waits for a session of this UE: the AMF pages it.
    void on_page(std::function<void(const std::string& supi, std::uint8_t psi)> f) { on_page_ = std::move(f); }

    struct Session {
        std::uint8_t psi = 0;
        std::string dnn;
        ip::Addr ip{};
        std::uint32_t ul_teid = 0;
        std::optional<ngap::GtpTunnel> dl;
        bool active = false;                       // the UE has the accept and the gNB the resources
        std::optional<std::uint8_t> release_pti;   // a RELEASE COMMAND awaits its COMPLETE
        std::optional<ngap::SessionSetupItem> setup;   // as first set up, for a reactivation
        bool pending = false;                      // downlink waits (the UE is paged)
        // P2 Q10: the QoS rules and flows the UE and the gNB have, and a modification on its way.
        std::vector<nas::ie::QosRules::Rule> rules;
        std::uint8_t next_rule = 2;
        struct Pending {
            std::vector<nas::ie::QosRules::Rule> rules;    // the session's rules once it is done
            std::vector<ngap::QosFlowRequest> flows;
            std::vector<std::uint8_t> added;
            std::vector<std::uint8_t> released;
        };
        std::optional<Pending> modifying;
        int modifications = 0;                     // answered by the gNB
    };
    const Session* session(const std::string& supi, std::uint8_t psi) const;
    std::size_t sessions() const;
    int requests() const noexcept { return requests_; }
    int completes() const noexcept { return completes_; }
    const std::vector<Verdict>& verdicts() const noexcept { return verdicts_; }

private:
    std::vector<SmAction> on_establishment(const std::string& supi, std::uint8_t psi, const nas::Message& m,
                                           std::optional<std::uint8_t> request_type, const std::optional<std::string>& dnn,
                                           const std::optional<nas::ie::Snssai>& snssai);
    std::vector<SmAction> on_release_request(const std::string& supi, std::uint8_t psi, const nas::Message& m);
    void on_release_complete(const std::string& supi, std::uint8_t psi, const nas::Message& m);
    void check(bool ok, const char* clause, const char* what, std::string detail = {});
    ip::Addr next_address();
    Result<SmAction> modification(Session& s, Session::Pending p, ngap::ModifyRequestTransfer t,
                                  const nas::ie::QosRules& rules, const nas::ie::QosFlowDescriptions& flows);

    SessionProfile p_;
    Upf* upf_;
    std::map<std::pair<std::string, std::uint8_t>, Session> sessions_;
    std::uint32_t next_host_ = 0;
    int requests_ = 0;
    int rejected_ = 0;
    std::map<std::string, int> backoff_rejected_;   // by SUPI
    int completes_ = 0;
    std::uint32_t fake_teid_ = 0x51000001;           // without a UPF
    std::function<void(const std::string&, std::uint8_t)> on_page_;
    std::vector<Verdict> verdicts_;
};

} // namespace ksim::corestub
