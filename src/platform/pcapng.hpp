// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// pcapng capture writers (plan M13, architecture §8 "Captures"), written from
// the pcapng specification (IETF draft-ietf-opsawg-pcapng): a Section Header
// Block, one Interface Description Block per link type (nanosecond
// timestamps), and Enhanced Packet Blocks with an optional comment. With them
// the framings the captures use:
//   - Exported-PDU (link type 252) records that name the Wireshark dissector
//     (EXP_PDU_TAG_PROTO_NAME): nr-rrc.*, nas-5gs, ngap, f1ap, e1ap, xnap;
//   - IPv4 (link type 228) with a synthesized UDP header: GTP-U on 2152 (the
//     gtp dissector then reads NR-U and the PDU Session Container), GSMTAP on
//     4729 (GSMTAP-SIM for APDUs).
// Blocks are little-endian. Packet bytes go out as given: callers never pass
// key material (SecretBytes has no path here).

#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <string_view>

#include "platform/buf.hpp"
#include "platform/result.hpp"

namespace ksim::pcap {

enum class LinkType : std::uint16_t { upper_pdu = 252, ipv4 = 228 };

constexpr std::uint16_t kGtpuPort = 2152;
constexpr std::uint16_t kGsmtapPort = 4729;
constexpr std::uint8_t kGsmtapSim = 4;   // GSMTAP_TYPE_SIM

class PcapngWriter {
public:
    using Sink = std::function<void(ByteView block)>;

    /// Writes the Section Header Block at once.
    explicit PcapngWriter(Sink sink, std::string_view application = "kaluza-sim");

    /// An Interface Description Block; returns the interface id for write().
    std::uint32_t add_interface(LinkType type, std::string_view name);

    /// An Enhanced Packet Block. ts_ns: nanoseconds since the Unix epoch. `original`:
    /// the packet's length on the wire when `packet` is the front of it (P2 Q8, a
    /// headers-only capture); by default the packet is whole.
    Result<void> write(std::uint32_t interface_id, std::int64_t ts_ns, ByteView packet,
                       std::string_view comment = {}, std::size_t original = 0);

private:
    Sink sink_;
    std::uint32_t interfaces_ = 0;
};

/// An Exported-PDU record: the dissector name tag, the end tag, the PDU.
Bytes exported_pdu(std::string_view dissector, ByteView pdu);

struct Udp4 {
    std::array<std::uint8_t, 4> src{10, 0, 0, 1};
    std::array<std::uint8_t, 4> dst{10, 0, 0, 2};
    std::uint16_t src_port = 40000;
    std::uint16_t dst_port = 0;
};

/// An IPv4 header (with its checksum) and a UDP header (checksum 0) around payload.
Result<Bytes> ipv4_udp(const Udp4& a, ByteView payload);

/// A GSMTAP version 2 header (16 octets) before payload.
Bytes gsmtap(std::uint8_t type, std::uint8_t sub_type, ByteView payload);

} // namespace ksim::pcap
