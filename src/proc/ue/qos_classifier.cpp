// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "proc/ue/qos_classifier.hpp"

#include <algorithm>
#include <array>
#include <optional>

#include "platform/mutation.hpp"

namespace ksim::proc::ue {

namespace {

using Filter = nas::ie::QosRules::PacketFilter;
using Component = nas::ie::QosRules::Component;

// Table 9.11.4.13.1
constexpr std::uint8_t kMatchAll = 0x01;
constexpr std::uint8_t kIpv4Remote = 0x10;
constexpr std::uint8_t kIpv4Local = 0x11;
constexpr std::uint8_t kIpv6Remote = 0x21;
constexpr std::uint8_t kIpv6Local = 0x23;
constexpr std::uint8_t kProtocol = 0x30;
constexpr std::uint8_t kLocalPort = 0x40;
constexpr std::uint8_t kLocalPortRange = 0x41;
constexpr std::uint8_t kRemotePort = 0x50;
constexpr std::uint8_t kRemotePortRange = 0x51;
constexpr std::uint8_t kSpi = 0x60;
constexpr std::uint8_t kTos = 0x70;
constexpr std::uint8_t kFlowLabel = 0x80;
constexpr std::uint8_t kDstMac = 0x81;
constexpr std::uint8_t kSrcMac = 0x82;
constexpr std::uint8_t kCTagVid = 0x83;
constexpr std::uint8_t kSTagVid = 0x84;
constexpr std::uint8_t kCTagPcpDei = 0x85;
constexpr std::uint8_t kSTagPcpDei = 0x86;
constexpr std::uint8_t kEthertype = 0x87;
constexpr std::uint8_t kDstMacRange = 0x88;
constexpr std::uint8_t kSrcMacRange = 0x89;
constexpr std::uint8_t kCTagPcpDeiExt = 0x8A;
constexpr std::uint8_t kSTagPcpDeiExt = 0x8B;

std::uint16_t be16(ByteView b, std::size_t at) { return static_cast<std::uint16_t>(b[at] << 8 | b[at + 1]); }
std::uint32_t be32(ByteView b, std::size_t at) {
    return std::uint32_t{b[at]} << 24 | std::uint32_t{b[at + 1]} << 16 | std::uint32_t{b[at + 2]} << 8 | b[at + 3];
}

/// What the components look at, from the UE's point of view (local is the UE's end).
struct View {
    bool ipv4 = false;
    bool ipv6 = false;
    std::array<std::uint8_t, 16> local{};
    std::array<std::uint8_t, 16> remote{};
    std::optional<std::uint8_t> protocol;
    std::optional<std::uint16_t> local_port;
    std::optional<std::uint16_t> remote_port;
    std::optional<std::uint32_t> spi;
    std::uint8_t tos = 0;
    std::uint32_t flow_label = 0;
    // Ethernet
    bool ethernet = false;
    std::array<std::uint8_t, 6> remote_mac{};
    std::array<std::uint8_t, 6> local_mac{};
    std::optional<std::uint16_t> c_tag;   // the outermost tag's TCI
    std::optional<std::uint16_t> s_tag;
    std::optional<std::uint16_t> ethertype;
};

void transport(View& v, ByteView p, std::size_t at, bool uplink) {
    if (!v.protocol) {
        return;
    }
    const std::uint8_t proto = *v.protocol;
    if ((proto == 6 || proto == 17 || proto == 132) && at + 4 <= p.size()) {   // TCP, UDP, SCTP
        const std::uint16_t src = be16(p, at);
        const std::uint16_t dst = be16(p, at + 2);
        v.local_port = uplink ? src : dst;
        v.remote_port = uplink ? dst : src;
    } else if (proto == 50 && at + 4 <= p.size()) {   // ESP: the SPI first
        v.spi = be32(p, at);
    } else if (proto == 51 && at + 8 <= p.size()) {   // AH: after next header, length, reserved
        v.spi = be32(p, at + 4);
    }
}

std::optional<View> parse_ip(ByteView p, bool uplink) {
    View v;
    if (p.empty()) {
        return std::nullopt;
    }
    const unsigned version = p[0] >> 4;
    if (version == 4) {
        if (p.size() < 20) {
            return std::nullopt;
        }
        const std::size_t ihl = static_cast<std::size_t>(p[0] & 0x0F) * 4;
        if (ihl < 20 || ihl > p.size()) {
            return std::nullopt;
        }
        v.ipv4 = true;
        v.tos = p[1];
        v.protocol = p[9];
        std::copy(p.begin() + (uplink ? 12 : 16), p.begin() + (uplink ? 16 : 20), v.local.begin());
        std::copy(p.begin() + (uplink ? 16 : 12), p.begin() + (uplink ? 20 : 16), v.remote.begin());
        const bool first_fragment = (be16(p, 6) & 0x1FFF) == 0;
        if (first_fragment) {
            transport(v, p, ihl, uplink);
        }
        return v;
    }
    if (version == 6) {
        if (p.size() < 40) {
            return std::nullopt;
        }
        v.ipv6 = true;
        v.tos = static_cast<std::uint8_t>((p[0] & 0x0F) << 4 | p[1] >> 4);
        v.flow_label = (std::uint32_t{p[1]} & 0x0F) << 16 | std::uint32_t{p[2]} << 8 | p[3];
        std::copy(p.begin() + (uplink ? 8 : 24), p.begin() + (uplink ? 24 : 40), v.local.begin());
        std::copy(p.begin() + (uplink ? 24 : 8), p.begin() + (uplink ? 40 : 24), v.remote.begin());
        // The upper layer after the extension headers (hop-by-hop, routing, fragment, options).
        std::uint8_t next = p[6];
        std::size_t at = 40;
        for (int i = 0; i < 8; ++i) {
            if (next == 0 || next == 43 || next == 60) {
                if (at + 2 > p.size()) {
                    return v;
                }
                const std::uint8_t n = p[at];
                at += (static_cast<std::size_t>(p[at + 1]) + 1) * 8;
                next = n;
            } else if (next == 44) {
                if (at + 8 > p.size()) {
                    return v;
                }
                const bool first = (be16(p, at + 2) & 0xFFF8) == 0;
                const std::uint8_t n = p[at];
                at += 8;
                next = n;
                if (!first) {
                    v.protocol = next;
                    return v;   // no transport header in a later fragment
                }
            } else {
                break;
            }
        }
        v.protocol = next;
        transport(v, p, at, uplink);
        return v;
    }
    return std::nullopt;
}

std::optional<View> parse_ethernet(ByteView p, bool uplink) {
    if (p.size() < 14) {
        return std::nullopt;
    }
    View v;
    v.ethernet = true;
    // The frame's destination is the remote end in the uplink, the UE in the downlink.
    std::copy(p.begin() + (uplink ? 0 : 6), p.begin() + (uplink ? 6 : 12), v.remote_mac.begin());
    std::copy(p.begin() + (uplink ? 6 : 0), p.begin() + (uplink ? 12 : 6), v.local_mac.begin());
    std::size_t at = 12;
    for (int i = 0; i < 4 && at + 4 <= p.size(); ++i) {
        const std::uint16_t type = be16(p, at);
        if (type == 0x88A8 && !v.s_tag) {
            v.s_tag = be16(p, at + 2);
        } else if (type == 0x8100 && !v.c_tag) {
            v.c_tag = be16(p, at + 2);
        } else if (type != 0x88A8 && type != 0x8100) {
            break;
        }
        at += 4;
    }
    if (at + 2 <= p.size()) {
        v.ethertype = be16(p, at);
    }
    return v;
}

bool masked4(const std::array<std::uint8_t, 16>& a, ByteView value) {
    for (std::size_t i = 0; i < 4; ++i) {
        if ((a[i] & value[4 + i]) != (value[i] & value[4 + i])) {
            return false;
        }
    }
    return true;
}

bool prefix6(const std::array<std::uint8_t, 16>& a, ByteView value) {
    const unsigned len = std::min<unsigned>(value[16], 128);
    for (unsigned bit = 0; bit < len; ++bit) {
        const unsigned byte = bit / 8;
        const auto mask = static_cast<std::uint8_t>(0x80U >> (bit % 8));
        if ((a[byte] & mask) != (value[byte] & mask)) {
            return false;
        }
    }
    return true;
}

bool mac_in(const std::array<std::uint8_t, 6>& m, ByteView value) {
    const auto lo = std::lexicographical_compare(m.begin(), m.end(), value.begin(), value.begin() + 6);
    const auto hi = std::lexicographical_compare(value.begin() + 6, value.begin() + 12, m.begin(), m.end());
    return !lo && !hi;   // low <= m <= high
}

/// One PCP/DEI component, plain or extended (24.501 figures 9.11.4.13.7, .8), over a TCI.
bool pcp_dei(std::uint16_t tci, std::uint8_t value, bool extended) {
    const auto pcp = static_cast<std::uint8_t>(tci >> 13);
    const auto dei = static_cast<std::uint8_t>((tci >> 12) & 1);
    const auto want_pcp = static_cast<std::uint8_t>((value >> 1) & 0x07);
    const auto want_dei = static_cast<std::uint8_t>(value & 1);
    if (!extended) {
        return pcp == want_pcp && dei == want_dei;
    }
    return ((value & 0x20) == 0 || pcp == want_pcp) && ((value & 0x10) == 0 || dei == want_dei);
}

bool component(const Component& c, const View& v) {
    const ByteView x(c.value);
    auto need = [&x](std::size_t n) { return x.size() >= n; };
    switch (c.type) {
    case kMatchAll:
        return true;
    case kIpv4Remote:
        return v.ipv4 && need(8) && masked4(v.remote, x);
    case kIpv4Local:
        return v.ipv4 && need(8) && masked4(v.local, x);
    case kIpv6Remote:
        return v.ipv6 && need(17) && prefix6(v.remote, x);
    case kIpv6Local:
        return v.ipv6 && need(17) && prefix6(v.local, x);
    case kProtocol:
        return need(1) && v.protocol && *v.protocol == x[0];
    case kLocalPort:
        return need(2) && v.local_port && *v.local_port == be16(x, 0);
    case kLocalPortRange:
        return need(4) && v.local_port && *v.local_port >= be16(x, 0) && *v.local_port <= be16(x, 2);
    case kRemotePort:
        return need(2) && v.remote_port && *v.remote_port == be16(x, 0);
    case kRemotePortRange:
        return need(4) && v.remote_port && *v.remote_port >= be16(x, 0) && *v.remote_port <= be16(x, 2);
    case kSpi:
        return need(4) && v.spi && *v.spi == be32(x, 0);
    case kTos:
        return (v.ipv4 || v.ipv6) && need(2) && (v.tos & x[1]) == (x[0] & x[1]);
    case kFlowLabel:
        return v.ipv6 && need(3) && v.flow_label == ((std::uint32_t{x[0]} & 0x0F) << 16 | std::uint32_t{x[1]} << 8 | x[2]);
    case kDstMac:
        return v.ethernet && need(6) && std::equal(v.remote_mac.begin(), v.remote_mac.end(), x.begin());
    case kSrcMac:
        return v.ethernet && need(6) && std::equal(v.local_mac.begin(), v.local_mac.end(), x.begin());
    case kDstMacRange:
        return v.ethernet && need(12) && mac_in(v.remote_mac, x);
    case kSrcMacRange:
        return v.ethernet && need(12) && mac_in(v.local_mac, x);
    case kCTagVid:
        return need(2) && v.c_tag && (*v.c_tag & 0x0FFF) == (be16(x, 0) & 0x0FFF);
    case kSTagVid:
        return need(2) && v.s_tag && (*v.s_tag & 0x0FFF) == (be16(x, 0) & 0x0FFF);
    case kCTagPcpDei:
        return need(1) && v.c_tag && pcp_dei(*v.c_tag, x[0], false);
    case kSTagPcpDei:
        return need(1) && v.s_tag && pcp_dei(*v.s_tag, x[0], false);
    case kCTagPcpDeiExt:
        return need(1) && v.c_tag && pcp_dei(*v.c_tag, x[0], true);
    case kSTagPcpDeiExt:
        return need(1) && v.s_tag && pcp_dei(*v.s_tag, x[0], true);
    case kEthertype:
        return need(2) && v.ethertype && *v.ethertype == be16(x, 0);
    default:
        return false;   // (S)RTP multiplexed media (0x91) and reserved values: never matched
    }
}

bool direction_ok(std::uint8_t d, QosDirection dir) {
    // 9.11.4.13: 1 downlink only, 2 uplink only, 3 bidirectional (0 is reserved).
    return d == 3 || (d == 2 && dir == QosDirection::uplink) || (d == 1 && dir == QosDirection::downlink);
}

} // namespace

std::optional<Filter> derive_ul_filter(ByteView dl) {
    // The view of a DL packet from the UE's side: local is the destination, remote the source.
    const auto v = parse_ip(dl, false);
    if (!v || !v->protocol || (*v->protocol != 6 && *v->protocol != 17) || !v->local_port || !v->remote_port) {
        return std::nullopt;   // not TCP or UDP (ESP: no uplink SA is known)
    }
    std::vector<Component> c;
    if (v->ipv4) {
        Bytes remote(v->remote.begin(), v->remote.begin() + 4);
        remote.insert(remote.end(), 4, 0xFF);
        Bytes local(v->local.begin(), v->local.begin() + 4);
        local.insert(local.end(), 4, 0xFF);
        c.push_back({kIpv4Remote, std::move(remote)});
        c.push_back({kIpv4Local, std::move(local)});
    } else {
        Bytes remote(v->remote.begin(), v->remote.end());
        remote.push_back(128);
        Bytes local(v->local.begin(), v->local.end());
        local.push_back(128);
        c.push_back({kIpv6Remote, std::move(remote)});
        c.push_back({kIpv6Local, std::move(local)});
    }
    c.push_back({kProtocol, Bytes{*v->protocol}});
    c.push_back({kLocalPort, Bytes{static_cast<std::uint8_t>(*v->local_port >> 8), static_cast<std::uint8_t>(*v->local_port)}});
    c.push_back({kRemotePort, Bytes{static_cast<std::uint8_t>(*v->remote_port >> 8), static_cast<std::uint8_t>(*v->remote_port)}});
    return Filter{2, 0, std::move(c)};   // uplink only
}

bool same_filter(const Filter& a, const Filter& b) {
    if (a.direction != b.direction || a.components.size() != b.components.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.components.size(); ++i) {
        if (a.components[i].type != b.components[i].type || a.components[i].value != b.components[i].value) {
            return false;
        }
    }
    return true;
}

bool filter_matches(const Filter& f, ByteView packet, QosDirection dir, PduKind kind) {
    if (!direction_ok(f.direction, dir) || f.components.empty()) {
        return false;
    }
    const bool up = dir == QosDirection::uplink;
    const auto view = kind == PduKind::ethernet ? parse_ethernet(packet, up) : parse_ip(packet, up);
    if (!view) {
        // Not a packet the components can look at: only match-all matches it.
        return std::all_of(f.components.begin(), f.components.end(), [](const Component& c) { return c.type == kMatchAll; });
    }
    return std::all_of(f.components.begin(), f.components.end(), [&view](const Component& c) { return component(c, *view); });
}

const nas::ie::QosRules::Rule* classify(const std::vector<nas::ie::QosRules::Rule>& rules, ByteView packet,
                                        QosDirection dir, PduKind kind) {
    std::vector<const nas::ie::QosRules::Rule*> order;
    order.reserve(rules.size());
    for (const auto& r : rules) {
        order.push_back(&r);
    }
    // Increasing precedence value; a rule without one last (mutant precedence_reversed:
    // the highest value first, row ksim-p2.ul-classifier-precedence).
    const bool reversed = KSIM_MUTANT("precedence_reversed");
    std::stable_sort(order.begin(), order.end(), [reversed](const auto* a, const auto* b) {
        const int pa = a->precedence ? *a->precedence : 256;
        const int pb = b->precedence ? *b->precedence : 256;
        return reversed ? pa > pb : pa < pb;
    });
    for (const auto* r : order) {
        if (KSIM_MUTANT("classifier_default_only") && !r->default_rule) {
            continue;   // the mutant: every packet on the default rule (row ksim-p2.ul-classifier)
        }
        if (std::any_of(r->filters.begin(), r->filters.end(),
                        [&](const auto& f) { return filter_matches(f, packet, dir, kind); })) {
            return r;
        }
    }
    return nullptr;
}

} // namespace ksim::proc::ue
