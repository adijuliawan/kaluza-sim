// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The QoS rules' packet filters over a packet (P2 Q10; TS 24.501 6.2.5.1.1.2, 9.11.4.13,
// Table 9.11.4.13.1; TS 23.501 5.7.1.5, 5.7.6): the UE's uplink classifier, and the stub
// UPF's downlink one.
//
//  - The rules are evaluated in increasing precedence value; the first that matches gives
//    the QFI. A rule matches when one of its packet filters for the packet's direction
//    (uplink only, downlink only or bidirectional) matches; a filter matches when every one
//    of its components does.
//  - "local" and "remote" are the UE's end and the far end: in the uplink the source and
//    the destination, in the downlink the other way round. The same holds for the MAC
//    addresses of an Ethernet frame (the destination MAC type is the remote one).
//  - IPv4 and IPv6 packets: addresses with mask or prefix, protocol / next header (IPv6
//    extension headers walked), ports of TCP, UDP and SCTP, the IPsec SPI of ESP and AH,
//    type of service / traffic class with mask, the IPv6 flow label. Ethernet frames: MAC
//    addresses and ranges, the outermost C-TAG and S-TAG VID and PCP/DEI (and the extended
//    forms), the ethertype. A component the packet cannot have (a port in an ICMP packet,
//    a MAC in an IP packet) does not match.
//  - The (S)RTP multiplexed media identification type (0x91) is not matched: a filter with
//    it never matches (KS-NAS-G5, a declared gap).
#pragma once

#include <cstdint>
#include <vector>

#include "codec/nas/ie/ie.hpp"
#include "platform/buf.hpp"

namespace ksim::proc::ue {

enum class QosDirection : std::uint8_t { uplink, downlink };
enum class PduKind : std::uint8_t { ip, ethernet };

/// Whether `f` matches `packet` travelling in `dir` (its direction field allows it).
bool filter_matches(const nas::ie::QosRules::PacketFilter& f, ByteView packet, QosDirection dir, PduKind kind = PduKind::ip);

/// The rule `packet` maps to: the matching one with the lowest precedence value (a rule
/// without precedence comes last), or nullptr when none matches (TS 24.501 6.2.5.1.1.2:
/// the UE does not send it).
const nas::ie::QosRules::Rule* classify(const std::vector<nas::ie::QosRules::Rule>& rules, ByteView packet,
                                        QosDirection dir, PduKind kind = PduKind::ip);

} // namespace ksim::proc::ue
