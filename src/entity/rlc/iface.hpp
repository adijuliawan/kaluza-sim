// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The RLC seam (P1 N6; architecture.md §2.3, ADR 0003): what PDCP and RRC see
// below them. P1 binds IdealRlc; phase 2 binds TS 38.322 TM, UM and AM behind
// the same interface.

#pragma once

#include <cstdint>
#include <functional>

#include "codec/air/kair.hpp"
#include "platform/buf.hpp"

namespace ksim::entity {

using RlcMode = air::RlcMode;

class IRlcBearer {
public:
    virtual ~IRlcBearer() = default;
    /// An SDU from PDCP (or a CCCH message from RRC on SRB0).
    virtual void write_sdu(Bytes sdu) = 0;
    virtual RlcMode mode() const noexcept = 0;
    virtual std::uint8_t lcid() const noexcept = 0;
    /// Where received SDUs go.
    virtual void set_upper(std::function<void(Bytes)> upper) = 0;
    /// What the MAC received for this logical channel (the ideal MAC hands
    /// over whole SDUs; a TS 38.322 RLC would take PDUs here).
    virtual void receive(Bytes pdu) = 0;
};

} // namespace ksim::entity
