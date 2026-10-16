// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// How the CU-CP maps a PDU session's QoS flows to DRBs (P2 Q10; TS 38.300 12, TS 37.324
// 5.3; cucp {drb_map} in a topology): one DRB per 5QI, the default DRB the one of the
// session's first flow (OCUDU's CU-CP does the same), or every flow of a session on one
// DRB (P1's way).
#pragma once

#include <cstdint>

namespace ksim::proc::ran {

enum class DrbMap : std::uint8_t { per_5qi, per_session };
const char* drb_map_name(DrbMap m) noexcept;

} // namespace ksim::proc::ran
