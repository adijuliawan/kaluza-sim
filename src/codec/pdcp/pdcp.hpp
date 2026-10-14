// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// PDCP PDU formats (P1 N6; TS 38.323 j10 §6.2, §6.3): the Data PDU header of
// an SRB (four reserved bits and a 12-bit SN, always followed by a MAC-I),
// of a DRB with a 12-bit or 18-bit SN (the D/C bit set), and the Control PDU
// carrying a PDCP status report (FMC and bitmap). The header only: ciphering,
// integrity and the state variables belong to the PDCP entity.

#pragma once

#include <cstdint>

#include "platform/buf.hpp"
#include "platform/result.hpp"

namespace ksim::pdcp {

enum class SnSize : std::uint8_t { len12 = 12, len18 = 18 };

inline constexpr std::size_t kMacILength = 4;

inline std::uint32_t sn_mask(SnSize s) noexcept { return (std::uint32_t{1} << static_cast<unsigned>(s)) - 1; }
std::size_t data_header_size(bool srb, SnSize s) noexcept;

/// The Data PDU header for SN `sn` (only its low SN-size bits are written).
Bytes data_header(bool srb, SnSize s, std::uint32_t sn);

struct Header {
    bool data = true;           // D/C (an SRB PDU is always data)
    std::uint32_t sn = 0;       // a Data PDU's SN
    std::uint8_t pdu_type = 0;  // a Control PDU's type (Table 6.3.8-1)
    std::size_t length = 0;     // the header's octets
};

/// Reads a PDU's header. The reserved bits are ignored as §6.3.1 says.
Result<Header> parse(bool srb, SnSize s, ByteView pdu);

/// A PDCP status report (§6.2.3.1): the first missing COUNT, then one bit per
/// following COUNT, 1 = received.
struct StatusReport {
    std::uint32_t fmc = 0;
    Bytes bitmap;
};
Bytes encode_status_report(const StatusReport& r);
Result<StatusReport> decode_status_report(ByteView control_pdu);

} // namespace ksim::pdcp
