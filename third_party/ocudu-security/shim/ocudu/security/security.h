// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Minimal stand-in for OCUDU's ocudu/security/security.h: the only names the
// verbatim SNOW 3G copy (third_party/ocudu-security) uses from it. Written by us;
// not copied from OCUDU.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace ocudu::security {

constexpr std::size_t sec_mac_len = 4;
using sec_mac = std::array<std::uint8_t, sec_mac_len>;

} // namespace ocudu::security
