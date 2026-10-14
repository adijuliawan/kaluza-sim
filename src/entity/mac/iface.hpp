// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The MAC seam (P1 N6; architecture.md §2.3, ADR 0003): what RLC sees below
// it. P1 binds an ideal MAC over KAIR; phase 2 binds TS 38.321 MAC with a DU
// scheduler behind the same interface.

#pragma once

#include <cstdint>

#include "entity/rlc/iface.hpp"

namespace ksim::entity {

class IMacSap {
public:
    virtual ~IMacSap() = default;
    /// An RLC SDU for logical channel `lcid`.
    virtual void send(std::uint8_t lcid, RlcMode mode, Bytes sdu) = 0;
    /// Received SDUs for `lcid` go to `bearer` (nullptr detaches it).
    virtual void attach(std::uint8_t lcid, IRlcBearer* bearer) = 0;
};

} // namespace ksim::entity
