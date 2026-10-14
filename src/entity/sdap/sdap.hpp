// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The UE's SDAP entity for one PDU session (P1 N6; TS 37.324 j00 §5): uplink
// QoS flows to DRBs by the configured mapping, or the default DRB (§5.2.1);
// the UL header added and the DL header read where RRC configured them.
// Reflective QoS (RDI, RQI) is reported, not acted on (P3; ADR 0003 lists it).

#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <vector>

#include "codec/sdap/sdap.hpp"
#include "platform/buf.hpp"
#include "platform/result.hpp"

namespace ksim::entity {

struct SdapDrb {
    std::uint8_t drb_id = 1;
    bool header_ul = false;
    bool header_dl = false;
    bool default_drb = false;
    std::vector<std::uint8_t> qfis;   // mappedQoS-FlowsToAdd
};

class Sdap {
public:
    explicit Sdap(std::uint8_t pdu_session) : psi_(pdu_session) {}

    void configure(const SdapDrb& d);   // add or modify (mappings add up, §5.3.1)
    void release(std::uint8_t drb_id);

    struct Ul {
        std::uint8_t drb_id = 0;
        Bytes pdu;
    };
    /// An uplink SDU of QoS flow `qfi`: its DRB and the SDAP PDU; nullopt when
    /// the flow maps to no DRB and there is no default DRB (§5.2.1: discarded).
    std::optional<Ul> map_ul(std::uint8_t qfi, Bytes sdu) const;

    struct Dl {
        Bytes sdu;
        std::optional<sdap::DlHeader> header;
    };
    Result<Dl> on_dl(std::uint8_t drb_id, Bytes pdu) const;

    std::uint8_t pdu_session() const noexcept { return psi_; }
    std::optional<std::uint8_t> default_drb() const;

private:
    std::uint8_t psi_;
    std::map<std::uint8_t, SdapDrb> drbs_;
    std::map<std::uint8_t, std::uint8_t> qfi_to_drb_;
};

} // namespace ksim::entity
