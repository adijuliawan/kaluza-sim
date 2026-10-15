// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The ports protocol code sends and receives through (P1 N2, ADR 0009): an SCTP
// association (IAssoc), a datagram socket (IDatagram) and a byte stream
// (IStream). net/ implements them over kernel sockets; memlink implements them
// in memory, for F1 and E1 inside the all-in-one `ksim` and for procedure tests
// in virtual time. Code above them (proc, node) cannot tell the two apart.
//
// Every handler runs on the executor that owns the port, never on another
// thread, and never re-entrantly from inside send().

#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

#include "platform/buf.hpp"
#include "platform/result.hpp"

namespace ksim {

/// A numeric IPv4 or IPv6 address and a port.
struct Endpoint {
    enum class Family : std::uint8_t { none, v4, v6 };

    Family family = Family::none;
    std::array<std::uint8_t, 16> addr{};   // IPv4 in the first four octets
    std::uint16_t port = 0;

    /// "172.30.30.1", "::1" (numeric only, no name lookup).
    static Result<Endpoint> parse(std::string_view host, std::uint16_t port);
    /// "172.30.30.1:38412" or "[::1]:38412".
    static Result<Endpoint> parse(std::string_view host_port);
    static Endpoint v4(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d, std::uint16_t port) noexcept;

    bool valid() const noexcept { return family != Family::none; }
    /// The address without the port.
    std::string host() const;
    /// "172.30.30.1:38412" or "[::1]:38412".
    std::string to_string() const;
    /// Whether the address lies in `prefix`/`bits` (same family only).
    bool in(const Endpoint& prefix, unsigned bits) const noexcept;

    friend bool operator==(const Endpoint&, const Endpoint&) = default;
};

/// An SCTP message's stream and payload protocol identifier (host order; the
/// socket layer converts it to network order on the wire).
struct SctpMeta {
    std::uint32_t ppid = 0;
    std::uint16_t stream = 0;
};

enum class LinkEvent : std::uint8_t {
    up,        // established; the stream counts are known
    restart,   // the peer restarted the association (SCTP_RESTART); up again
    shutdown,  // ended gracefully
    lost,      // ended by an abort, a failure or a lost peer
    refused,   // could not be established (a client retries)
};

const char* link_event_name(LinkEvent e) noexcept;

/// The stream a UE's signalling keeps for its whole context (P2 Q2; TS 38.412,
/// 38.472 and 37.482 §7): stream 0 is for non-UE-associated messages, so a UE
/// takes one of the others by its own AP ID; with one stream, stream 0.
inline std::uint16_t ue_stream(std::uint16_t out_streams, std::uint32_t ue_id) noexcept {
    return out_streams > 1 ? static_cast<std::uint16_t>(1 + ue_id % (out_streams - 1U)) : std::uint16_t{0};
}

class IAssoc {
public:
    using OnMessage = std::function<void(ByteView msg, SctpMeta meta)>;
    using OnEvent = std::function<void(LinkEvent event)>;

    virtual ~IAssoc() = default;

    /// Set before the association can deliver anything.
    virtual void set_handlers(OnMessage on_message, OnEvent on_event) = 0;
    /// Errc::closed when not up; Errc::out_of_range for a stream at or above
    /// out_streams() (the negotiated count, TS 38.412 §7).
    virtual Result<void> send(ByteView msg, SctpMeta meta) = 0;
    virtual bool up() const noexcept = 0;
    virtual std::uint16_t out_streams() const noexcept = 0;
    virtual std::uint16_t in_streams() const noexcept = 0;
    /// Ends it gracefully (the peer sees `shutdown`) or at once (`lost`).
    virtual void shutdown() = 0;
    virtual void abort() = 0;
    virtual Endpoint peer() const = 0;
};

class IDatagram {
public:
    using OnDatagram = std::function<void(ByteView payload, const Endpoint& from)>;

    virtual ~IDatagram() = default;
    virtual void set_handler(OnDatagram on_datagram) = 0;
    /// Best effort, as UDP: a datagram the network cannot take is dropped and
    /// counted, not an error. Errc::invalid_argument for a family mismatch.
    virtual Result<void> send_to(ByteView payload, const Endpoint& to) = 0;
    virtual Endpoint local() const = 0;
    virtual std::uint64_t dropped() const noexcept = 0;
};

/// A packet port (P1 N11): a UE session's TUN device, or an in-memory one in
/// tests. One IP packet per call each way.
class IPacketPort {
public:
    using OnPacket = std::function<void(ByteView packet)>;

    virtual ~IPacketPort() = default;
    virtual void set_handler(OnPacket on_packet) = 0;
    /// Best effort: a packet the device cannot take is dropped and counted.
    virtual Result<void> write(ByteView packet) = 0;
    virtual std::uint64_t dropped() const noexcept = 0;
};

/// A message channel (P2 Q2, ADR 0011 point 2): each send arrives whole, as
/// one message, in order. UNIX SOCK_SEQPACKET between the UE farm and the DU
/// when they are separate processes (net/seqpacket).
class IChannel {
public:
    using OnMessage = std::function<void(ByteView message)>;
    using OnClosed = std::function<void()>;

    virtual ~IChannel() = default;
    virtual void set_handlers(OnMessage on_message, OnClosed on_closed) = 0;
    /// Queues the message when the peer cannot take it yet; Errc::closed once closed.
    virtual Result<void> send(ByteView message) = 0;
    virtual bool open() const noexcept = 0;
    virtual void close() = 0;
};

class IStream {
public:
    using OnData = std::function<void(ByteView data)>;
    using OnClosed = std::function<void()>;

    virtual ~IStream() = default;
    virtual void set_handlers(OnData on_data, OnClosed on_closed) = 0;
    /// Queues the bytes in order; Errc::closed once closed.
    virtual Result<void> send(ByteView data) = 0;
    virtual bool open() const noexcept = 0;
    virtual void close() = 0;
    virtual Endpoint peer() const = 0;
};

} // namespace ksim
