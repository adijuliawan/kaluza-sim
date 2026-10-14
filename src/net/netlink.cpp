// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "net/netlink.hpp"

#include <linux/if.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

namespace ksim::net::nl {

namespace {

constexpr std::uint16_t kCreate = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
constexpr std::uint16_t kChange = NLM_F_REQUEST | NLM_F_ACK;

/// A netlink message in host order (netlink is host-endian), attributes
/// aligned to 4 octets; nest() returns the attribute's offset for close().
class Msg {
public:
    Msg(std::uint16_t type, std::uint16_t flags, std::uint32_t seq) {
        put32(0);   // nlmsg_len, set by done()
        put16(type);
        put16(flags);
        put32(seq);
        put32(0);   // nlmsg_pid: the kernel
    }
    void put8(std::uint8_t v) { b_.push_back(v); }
    void put16(std::uint16_t v) { raw(&v, 2); }
    void put32(std::uint32_t v) { raw(&v, 4); }
    void raw(const void* p, std::size_t n) {
        const auto* c = static_cast<const std::uint8_t*>(p);
        b_.insert(b_.end(), c, c + n);
    }
    void align() {
        while (b_.size() % 4 != 0) {
            b_.push_back(0);
        }
    }
    void attr(std::uint16_t type, const void* p, std::size_t n) {
        put16(static_cast<std::uint16_t>(4 + n));
        put16(type);
        raw(p, n);
        align();
    }
    void attr32(std::uint16_t type, std::uint32_t v) { attr(type, &v, 4); }
    void attr16(std::uint16_t type, std::uint16_t v) { attr(type, &v, 2); }
    void attr_str(std::uint16_t type, const std::string& s) { attr(type, s.c_str(), s.size() + 1); }
    std::size_t nest(std::uint16_t type) {
        const std::size_t at = b_.size();
        put16(0);
        put16(type);
        return at;
    }
    void close(std::size_t at) {
        const auto len = static_cast<std::uint16_t>(b_.size() - at);
        std::memcpy(b_.data() + at, &len, 2);
    }
    Bytes done() {
        const auto len = static_cast<std::uint32_t>(b_.size());
        std::memcpy(b_.data(), &len, 4);
        return std::move(b_);
    }

private:
    Bytes b_;
};

void ifinfo(Msg& m, int index, unsigned flags, unsigned change) {
    ifinfomsg i{};
    i.ifi_family = AF_UNSPEC;
    i.ifi_index = index;
    i.ifi_flags = flags;
    i.ifi_change = change;
    m.raw(&i, sizeof(i));
}

} // namespace

Result<Bytes> new_ipvlan(std::uint32_t seq, const Ipvlan& v) {
    if (v.name.empty() || v.name.size() >= IFNAMSIZ || v.parent_ifindex <= 0 || v.netns_fd < 0) {
        return make_error(Errc::invalid_argument, 0, "netlink: an ipvlan needs a name, a parent and a namespace");
    }
    Msg m(RTM_NEWLINK, kCreate, seq);
    ifinfo(m, 0, 0, 0);
    m.attr32(IFLA_NET_NS_FD, static_cast<std::uint32_t>(v.netns_fd));
    m.attr32(IFLA_LINK, static_cast<std::uint32_t>(v.parent_ifindex));
    m.attr_str(IFLA_IFNAME, v.name);
    const std::size_t info = m.nest(IFLA_LINKINFO);
    m.attr(IFLA_INFO_KIND, "ipvlan", 7);
    const std::size_t data = m.nest(IFLA_INFO_DATA);
    m.attr16(IFLA_IPVLAN_MODE, IPVLAN_MODE_L2);
    m.attr16(IFLA_IPVLAN_FLAGS, 0);
    m.close(data);
    m.close(info);
    return m.done();
}

Bytes new_addr_v4(std::uint32_t seq, int ifindex, std::array<std::uint8_t, 4> addr, std::uint8_t prefix) {
    Msg m(RTM_NEWADDR, kCreate, seq);
    ifaddrmsg a{};
    a.ifa_family = AF_INET;
    a.ifa_prefixlen = prefix;
    a.ifa_index = static_cast<std::uint32_t>(ifindex);
    m.raw(&a, sizeof(a));
    m.attr(IFA_LOCAL, addr.data(), 4);
    m.attr(IFA_ADDRESS, addr.data(), 4);
    return m.done();
}

Bytes set_link_up(std::uint32_t seq, int ifindex) {
    Msg m(RTM_NEWLINK, kChange, seq);
    ifinfo(m, ifindex, IFF_UP, IFF_UP);
    return m.done();
}

Bytes del_link(std::uint32_t seq, int ifindex) {
    Msg m(RTM_DELLINK, kChange, seq);
    ifinfo(m, ifindex, 0, 0);
    return m.done();
}

Result<int> ack_of(ByteView reply, std::uint32_t seq) {
    if (reply.size() < sizeof(nlmsghdr) + sizeof(nlmsgerr)) {
        return make_error(Errc::malformed, 0, "netlink: short reply");
    }
    nlmsghdr h{};
    std::memcpy(&h, reply.data(), sizeof(h));
    if (h.nlmsg_type != NLMSG_ERROR || h.nlmsg_seq != seq || h.nlmsg_len > reply.size()) {
        return make_error(Errc::malformed, 0, "netlink: not the acknowledgement of the request");
    }
    nlmsgerr e{};
    std::memcpy(&e, reply.data() + sizeof(h), sizeof(e));
    return e.error;
}

Result<Rtnl> Rtnl::open() {
    Fd fd(::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE));
    if (!fd) {
        return make_error(Errc::io, static_cast<std::uint32_t>(errno), "netlink: socket");
    }
    sockaddr_nl local{};
    local.nl_family = AF_NETLINK;
    if (::bind(fd.get(), reinterpret_cast<const sockaddr*>(&local), sizeof(local)) != 0) {
        return make_error(Errc::io, static_cast<std::uint32_t>(errno), "netlink: bind");
    }
    return Rtnl(std::move(fd));
}

Result<void> Rtnl::request(const Bytes& msg) {
    std::uint32_t seq = 0;
    std::memcpy(&seq, msg.data() + 8, 4);
    sockaddr_nl kernel{};
    kernel.nl_family = AF_NETLINK;
    if (::sendto(fd_.get(), msg.data(), msg.size(), 0, reinterpret_cast<const sockaddr*>(&kernel), sizeof(kernel)) !=
        static_cast<ssize_t>(msg.size())) {
        return make_error(Errc::io, static_cast<std::uint32_t>(errno), "netlink: send");
    }
    Bytes buf(8192);
    for (;;) {
        const ssize_t n = ::recv(fd_.get(), buf.data(), buf.size(), 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return make_error(Errc::io, static_cast<std::uint32_t>(errno), "netlink: recv");
        }
        auto ack = ack_of(ByteView(buf.data(), static_cast<std::size_t>(n)), seq);
        if (!ack) {
            continue;   // not ours (a late answer to an earlier request)
        }
        if (*ack != 0) {
            return make_error(Errc::io, static_cast<std::uint32_t>(-*ack), "netlink: the kernel refused the request");
        }
        return {};
    }
}

} // namespace ksim::net::nl
