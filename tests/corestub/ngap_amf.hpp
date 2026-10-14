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

#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "amf.hpp"
#include "codec/asn1/msg/ngap.hpp"
#include "platform/transport.hpp"

namespace ksim::corestub {

class NgapAmf {
public:
    NgapAmf(Executor& ex, Home& home, nas::ie::Plmn plmn, Profile p, IAssoc& ng);
    NgapAmf(const NgapAmf&) = delete;
    NgapAmf& operator=(const NgapAmf&) = delete;

    bool ng_setup_done() const noexcept { return ng_setup_; }
    std::size_t ues() const noexcept { return ues_.size(); }
    /// The NAS side of the n-th UE that came (0 first), or nullptr.
    Amf* nas(std::size_t n = 0);
    std::vector<Verdict> failures() const;
    const std::vector<std::string>& received() const noexcept { return received_; }
    std::size_t count(std::string_view message) const;
    std::uint64_t error_indications() const noexcept { return error_indications_; }
    std::optional<ngap::Cause> last_error_cause() const { return last_error_; }

    /// Downlink NGAP as a test scripts it (raw octets).
    void send_raw(ByteView pdu, std::uint16_t stream = 0);
    void send(const ngap::Pdu& p, std::uint16_t stream = 0);
    /// UE CONTEXT RELEASE COMMAND for the n-th UE.
    void release(std::size_t n, ngap::Cause cause);
    struct UeIds {
        std::uint64_t amf = 0;
        std::uint32_t ran = 0;
    };
    std::optional<UeIds> ids(std::size_t n) const;

private:
    struct Ue {
        std::uint64_t amf_ue = 0;
        std::uint32_t ran_ue = 0;
        std::unique_ptr<Amf> nas;
        bool ics_sent = false;
        bool ics_answered = false;
        bool releasing = false;
        std::optional<Bytes> radio_capability;
    };

    void on_message(ByteView msg);
    void check(bool ok, const char* clause, const char* what, std::string detail = {});
    Ue* by_amf(std::uint64_t id);
    void attach_nas(Ue& ue);
    std::uint16_t stream_of(const Ue& ue) const;

    Executor& ex_;
    Home& home_;
    nas::ie::Plmn plmn_;
    Profile p_;
    IAssoc& ng_;
    bool ng_setup_ = false;
    std::map<std::uint64_t, Ue> ues_;   // by AMF UE NGAP ID
    std::vector<std::uint64_t> order_;  // AMF UE NGAP IDs in arrival order
    std::uint64_t next_amf_ue_ = 7;
    std::vector<Verdict> verdicts_;
    std::vector<std::string> received_;
    std::uint64_t error_indications_ = 0;
    std::optional<ngap::Cause> last_error_;
};

} // namespace ksim::corestub
