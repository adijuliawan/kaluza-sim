// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// IPv4 and ICMP echo, as much as the inject-mode ping and the core stub's DN
// reflector need (P1 N10): an IPv4 header without options (RFC 791 §3.1), its
// header checksum, and ICMP echo request and reply (RFC 792). The TUN data
// plane of N11 carries the kernel's own packets and does not use this.

#pragma once

#include <array>
#include <cstdint>
#include <optional>

#include "platform/buf.hpp"
#include "platform/result.hpp"

namespace ksim::ip {

using Addr = std::array<std::uint8_t, 4>;

inline constexpr std::uint8_t kIcmp = 1;
inline constexpr std::uint8_t kUdp = 17;

struct Ipv4 {
    std::uint8_t tos = 0;
    std::uint16_t id = 0;
    bool dont_fragment = false;
    std::uint8_t ttl = 64;
    std::uint8_t protocol = kIcmp;
    Addr src{};
    Addr dst{};
    Bytes payload;
};

/// The RFC 1071 Internet checksum of `in`.
std::uint16_t checksum(ByteView in) noexcept;

Bytes encode(const Ipv4& p);
/// Errc::malformed for a version other than 4, a bad header length or
/// checksum, or a total length the octets do not hold; Errc::unsupported for
/// a fragment.
Result<Ipv4> decode(ByteView in);

struct Echo {
    bool reply = false;
    std::uint16_t id = 0;
    std::uint16_t seq = 0;
    Bytes data;
};

Bytes encode_icmp(const Echo& e);
/// An ICMP echo request or reply, its checksum checked; nullopt for any other ICMP message.
Result<std::optional<Echo>> decode_icmp(ByteView in);

/// An echo request from `src` to `dst`, `size` octets of data (a counting pattern).
Bytes ping(const Addr& src, const Addr& dst, std::uint16_t id, std::uint16_t seq, std::size_t size);

} // namespace ksim::ip
