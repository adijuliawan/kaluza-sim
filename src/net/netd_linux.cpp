// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// ksim-netd's operations on the system (P1 N9): named namespaces (netns.cpp)
// and rtnetlink requests (netlink.cpp). Root only. A node's namespace gets lo
// up and, with a parent, an L2 ipvlan "ksim0" created straight into it
// (IFLA_NET_NS_FD) carrying the node's address; a failure half way removes
// the namespace again.

#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <cerrno>

#include "net/netd.hpp"
#include "net/netlink.hpp"
#include "net/netns.hpp"

namespace ksim::net::netd {

namespace {

constexpr const char* kLink = "ksim0";

Result<void> request(nl::Rtnl& rt, const Bytes& msg) { return rt.request(msg); }

Result<void> link_up(nl::Rtnl& rt, const char* name) {
    const unsigned idx = ::if_nametoindex(name);
    if (idx == 0) {
        return make_error(Errc::io, static_cast<std::uint32_t>(errno), "netd: no such link in the namespace");
    }
    return request(rt, nl::set_link_up(rt.next_seq(), static_cast<int>(idx)));
}

} // namespace

Result<void> LinuxOps::setup_node(const std::string& netns, const std::string& parent, std::array<std::uint8_t, 4> addr,
                                  std::uint8_t prefix) {
    if (auto r = netns::add(netns); !r) {
        return r;
    }
    auto undo = [&](Error e) -> Result<void> {
        (void)netns::del(netns);
        return e;
    };
    auto ns = netns::open(netns);
    if (!ns) {
        return undo(ns.error());
    }
    if (!parent.empty()) {
        const unsigned parent_idx = ::if_nametoindex(parent.c_str());
        if (parent_idx == 0) {
            return undo(make_error(Errc::io, static_cast<std::uint32_t>(errno), "netd: no such parent link"));
        }
        auto rt = nl::Rtnl::open();
        if (!rt) {
            return undo(rt.error());
        }
        auto msg = nl::new_ipvlan(rt->next_seq(), nl::Ipvlan{kLink, static_cast<int>(parent_idx), ns->get()});
        if (!msg) {
            return undo(msg.error());
        }
        if (auto r = rt->request(*msg); !r) {
            return undo(r.error());
        }
    }
    auto inside = netns::run_in(ns->get(), [&]() -> Result<void> {
        auto rt = nl::Rtnl::open();
        if (!rt) {
            return rt.error();
        }
        if (auto r = link_up(*rt, "lo"); !r) {
            return r;
        }
        if (parent.empty()) {
            return {};
        }
        const unsigned idx = ::if_nametoindex(kLink);
        if (idx == 0) {
            return make_error(Errc::io, static_cast<std::uint32_t>(errno), "netd: the ipvlan is not in the namespace");
        }
        if (auto r = request(*rt, nl::new_addr_v4(rt->next_seq(), static_cast<int>(idx), addr, prefix)); !r) {
            return r;
        }
        return link_up(*rt, kLink);
    });
    if (!inside) {
        return undo(inside.error());
    }
    return {};
}

Result<void> LinuxOps::teardown(const std::string& netns) { return netns::del(netns); }

Result<Fd> LinuxOps::socket(const std::string& netns, SockKind kind, int family) {
    auto ns = netns::open(netns);
    if (!ns) {
        return ns.error();
    }
    Fd out;
    auto r = netns::run_in(ns->get(), [&]() -> Result<void> {
        const int type = (kind == SockKind::sctp ? SOCK_STREAM : SOCK_DGRAM) | SOCK_NONBLOCK | SOCK_CLOEXEC;
        const int proto = kind == SockKind::sctp ? IPPROTO_SCTP : IPPROTO_UDP;
        Fd fd(::socket(family, type, proto));
        if (!fd) {
            return make_error(Errc::io, static_cast<std::uint32_t>(errno), "netd: socket in the namespace");
        }
        out = std::move(fd);
        return {};
    });
    if (!r) {
        return r.error();
    }
    return out;
}

std::vector<std::string> LinuxOps::list() { return netns::list(); }

} // namespace ksim::net::netd
