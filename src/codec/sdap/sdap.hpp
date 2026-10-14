// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// SDAP headers (P1 N6; TS 37.324 j00 §6.2, §6.3): one octet, present when
// RRC configures sdap-HeaderDL or sdap-HeaderUL. Downlink: RDI, RQI, QFI.
// Uplink: D/C, R, QFI; a Control PDU (D/C 0) is the end-marker.

#pragma once

#include <cstdint>

namespace ksim::sdap {

struct DlHeader {
    bool rdi = false;   // reflective QoS flow to DRB mapping indication
    bool rqi = false;   // reflective QoS indication
    std::uint8_t qfi = 0;
    friend bool operator==(const DlHeader&, const DlHeader&) = default;
};

struct UlHeader {
    bool data = true;   // D/C: 1 data, 0 the end-marker control PDU
    std::uint8_t qfi = 0;
    friend bool operator==(const UlHeader&, const UlHeader&) = default;
};

inline std::uint8_t encode(DlHeader h) noexcept {
    return static_cast<std::uint8_t>((h.rdi ? 0x80 : 0) | (h.rqi ? 0x40 : 0) | (h.qfi & 0x3F));
}
inline std::uint8_t encode(UlHeader h) noexcept {
    return static_cast<std::uint8_t>((h.data ? 0x80 : 0) | (h.qfi & 0x3F));
}
inline DlHeader decode_dl(std::uint8_t o) noexcept {
    return {(o & 0x80) != 0, (o & 0x40) != 0, static_cast<std::uint8_t>(o & 0x3F)};
}
inline UlHeader decode_ul(std::uint8_t o) noexcept {   // the R bit is ignored
    return {(o & 0x80) != 0, static_cast<std::uint8_t>(o & 0x3F)};
}

} // namespace ksim::sdap
