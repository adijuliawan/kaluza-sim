// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The rtnetlink requests ksim-netd sends (P1 N9; ADR 0009 point 3), written
// from the kernel's UAPI (linux/rtnetlink.h, if_link.h, if_addr.h,
// fib_rules.h): an ipvlan link created straight into a network namespace, an
// IPv4 address, a link set up, a link deleted; from P1 N10 for the UE's
// namespaces a link's MTU, a default route through a link in a table, and a
// rule sending a source address to a table. Each builder's output is checked against the bytes
// iproute2 sends for the same request (tests/unit/net/netlink_test.cpp). Rtnl
// is a NETLINK_ROUTE socket in the calling thread's network namespace that
// sends one request and waits for its acknowledgement.

#pragma once

#include <array>
#include <cstdint>
#include <string>

#include "platform/buf.hpp"
#include "platform/result.hpp"
#include "platform/reactor.hpp"

namespace ksim::net::nl {

struct Ipvlan {
    std::string name;          // the link's name in its namespace (IFNAMSIZ - 1 at most)
    int parent_ifindex = 0;    // in the caller's namespace
    int netns_fd = -1;         // the namespace it is created in
};

/// RTM_NEWLINK, NLM_F_REQUEST|ACK|CREATE|EXCL: an L2 ipvlan on a parent, in a namespace.
Result<Bytes> new_ipvlan(std::uint32_t seq, const Ipvlan& v);
/// RTM_NEWADDR, NLM_F_REQUEST|ACK|CREATE|EXCL: IFA_LOCAL and IFA_ADDRESS.
Bytes new_addr_v4(std::uint32_t seq, int ifindex, std::array<std::uint8_t, 4> addr, std::uint8_t prefix);
/// RTM_NEWLINK, NLM_F_REQUEST|ACK: IFF_UP set (ifi_change IFF_UP).
Bytes set_link_up(std::uint32_t seq, int ifindex);
/// RTM_DELLINK, NLM_F_REQUEST|ACK.
Bytes del_link(std::uint32_t seq, int ifindex);
/// RTM_NEWLINK, NLM_F_REQUEST|ACK: IFLA_MTU (`ip link set dev X mtu N`).
Bytes set_mtu(std::uint32_t seq, int ifindex, std::uint32_t mtu);
/// RTM_NEWROUTE, NLM_F_REQUEST|ACK|CREATE|EXCL: a default IPv4 route through
/// `oif`, scope link, in `table` (1..255; 254 is main) (`ip route add default dev X table T`).
Result<Bytes> new_default_route(std::uint32_t seq, int oif, std::uint32_t table);
/// RTM_NEWRULE, NLM_F_REQUEST|ACK|CREATE|EXCL: from <addr>/32 to `table` (`ip rule add from A table T`).
Result<Bytes> new_rule_from(std::uint32_t seq, std::array<std::uint8_t, 4> addr, std::uint32_t table);
/// RTM_DELRULE, NLM_F_REQUEST|ACK: the same rule (`ip rule del from A table T`).
Result<Bytes> del_rule_from(std::uint32_t seq, std::array<std::uint8_t, 4> addr, std::uint32_t table);

/// The answer to request `seq` in `reply`: 0 for an ACK, a negative errno for
/// an error, Errc::malformed when the reply is not a netlink error message for it.
Result<int> ack_of(ByteView reply, std::uint32_t seq);

class Rtnl {
public:
    /// A NETLINK_ROUTE socket in the calling thread's network namespace.
    static Result<Rtnl> open();
    /// Sends `msg` (its seq must be next_seq()) and waits for its ACK; an
    /// error ACK is Errc::io with the errno.
    Result<void> request(const Bytes& msg);
    std::uint32_t next_seq() noexcept { return ++seq_; }

private:
    explicit Rtnl(Fd fd) : fd_(std::move(fd)) {}
    Fd fd_;
    std::uint32_t seq_ = 0;
};

} // namespace ksim::net::nl
