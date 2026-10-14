// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "codec/pdcp/pdcp.hpp"

namespace ksim::pdcp {

std::size_t data_header_size(bool srb, SnSize s) noexcept { return !srb && s == SnSize::len18 ? 3 : 2; }

Bytes data_header(bool srb, SnSize s, std::uint32_t sn) {
    sn &= sn_mask(srb ? SnSize::len12 : s);
    if (srb) {
        return {static_cast<std::uint8_t>((sn >> 8) & 0x0F), static_cast<std::uint8_t>(sn & 0xFF)};
    }
    if (s == SnSize::len12) {
        return {static_cast<std::uint8_t>(0x80 | ((sn >> 8) & 0x0F)), static_cast<std::uint8_t>(sn & 0xFF)};
    }
    return {static_cast<std::uint8_t>(0x80 | ((sn >> 16) & 0x03)), static_cast<std::uint8_t>((sn >> 8) & 0xFF),
            static_cast<std::uint8_t>(sn & 0xFF)};
}

Result<Header> parse(bool srb, SnSize s, ByteView pdu) {
    if (pdu.empty()) {
        return make_error(Errc::truncated, 0, "PDCP: empty PDU");
    }
    Header h;
    if (srb) {
        if (pdu.size() < 2 + kMacILength) {
            return make_error(Errc::truncated, 0, "PDCP: an SRB PDU shorter than its header and MAC-I");
        }
        h.sn = static_cast<std::uint32_t>((pdu[0] & 0x0F) << 8 | pdu[1]);
        h.length = 2;
        return h;
    }
    h.data = (pdu[0] & 0x80) != 0;
    if (!h.data) {
        h.pdu_type = static_cast<std::uint8_t>((pdu[0] >> 4) & 0x07);
        h.length = 1;
        return h;
    }
    const std::size_t n = data_header_size(false, s);
    if (pdu.size() < n) {
        return make_error(Errc::truncated, 0, "PDCP: a DRB PDU shorter than its header");
    }
    h.sn = s == SnSize::len12 ? static_cast<std::uint32_t>((pdu[0] & 0x0F) << 8 | pdu[1])
                              : static_cast<std::uint32_t>((pdu[0] & 0x03) << 16 | pdu[1] << 8 | pdu[2]);
    h.length = n;
    return h;
}

Bytes encode_status_report(const StatusReport& r) {
    ByteWriter w(5 + r.bitmap.size());
    w.u8(0x00);   // D/C 0, PDU type 000, R
    w.u32(r.fmc);
    w.bytes(r.bitmap);
    return std::move(w).take();
}

Result<StatusReport> decode_status_report(ByteView pdu) {
    if (pdu.size() < 5) {
        return make_error(Errc::truncated, 0, "PDCP: a status report shorter than its FMC");
    }
    if ((pdu[0] & 0x80) != 0 || ((pdu[0] >> 4) & 0x07) != 0) {
        return make_error(Errc::malformed, 0, "PDCP: not a status report");
    }
    StatusReport r;
    r.fmc = static_cast<std::uint32_t>(pdu[1]) << 24 | static_cast<std::uint32_t>(pdu[2]) << 16 |
            static_cast<std::uint32_t>(pdu[3]) << 8 | pdu[4];
    r.bitmap.assign(pdu.begin() + 5, pdu.end());
    return r;
}

} // namespace ksim::pdcp
