// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// ksim-netd's operations on the system (P1 N9): named namespaces (netns.cpp)
// and rtnetlink requests (netlink.cpp). Root only. A node's namespace gets lo
// up and, with a parent, an L2 ipvlan "ksim0" created straight into it
// (IFLA_NET_NS_FD) carrying the node's address; a failure half way removes
// the namespace again.
//
// P1 N11, a UE's namespace: IPv6 off (all and default) and ping_group_range
// open, written before any link is up so the kernel never makes an IPv6
// address or sends a router solicitation (L13), then lo up. A session's TUN
// (IFF_TUN | IFF_NO_PI) is opened on a thread inside the namespace, so the
// device lives there and goes when ksim closes its descriptor; it gets the
// MTU, the address /32, up, a default route in the session's table and a
// rule from the address to that table. exec forks a helper that joins the
// namespace and a mount namespace of its own (as `ip netns exec` does: /
// made a slave, /sys remounted, /etc/netns/<netns>/resolv.conf bound over
// /etc/resolv.conf), drops to the asking uid and gid with no new privileges
// and a process group of its own, starts the command, waits for it and writes
// its wait status to the status pipe.
//
// P2 Q6 (netd v3): ksim-mid is a bridge with no address and no uplink; a node's
// leg is a veth pair made with its peer straight in the namespace ("mid0"), the
// host end mastered to the bridge. A DN namespace is set up as a UE's; its TUN
// "dn0" carries the DN's address /32 and a route to the UE pool. gc removes the
// bridge and any ksim-m… host end a namespace's removal left (none, normally:
// a veth pair goes with either end).

#include <fcntl.h>
#include <grp.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <memory>

#include "net/netd.hpp"
#include "net/netlink.hpp"
#include "net/netns.hpp"

namespace ksim::net::netd {

namespace {

constexpr const char* kLink = "ksim0";
constexpr std::uint32_t kMainTable = 254;   // RT_TABLE_MAIN (linux/rtnetlink.h clashes with net/if.h)

Result<void> request(nl::Rtnl& rt, const Bytes& msg) { return rt.request(msg); }

Result<void> request(nl::Rtnl& rt, const Result<Bytes>& msg) {
    if (!msg) {
        return msg.error();
    }
    return rt.request(*msg);
}

Result<void> write_file(const char* path, const std::string& text) {
    Fd fd(::open(path, O_WRONLY | O_CLOEXEC | O_TRUNC));
    if (!fd || ::write(fd.get(), text.data(), text.size()) != static_cast<ssize_t>(text.size())) {
        return make_error(Errc::io, static_cast<std::uint32_t>(errno), "netd: a sysctl could not be written");
    }
    return {};
}

std::string dotted(const std::array<std::uint8_t, 4>& a) {
    return std::to_string(a[0]) + "." + std::to_string(a[1]) + "." + std::to_string(a[2]) + "." + std::to_string(a[3]);
}

/// Closes every descriptor from 3 up except those in `keep`.
void close_all_but(std::vector<int> keep) {
    std::sort(keep.begin(), keep.end());
    unsigned from = 3;
    for (int k : keep) {
        if (k < 3) {
            continue;
        }
        if (static_cast<unsigned>(k) > from) {
            ::close_range(from, static_cast<unsigned>(k) - 1, 0);
        }
        from = static_cast<unsigned>(k) + 1;
    }
    ::close_range(from, ~0U, 0);
}

/// The exec helper, in the child of netd: never returns.
[[noreturn]] void exec_helper(int ns_fd, const std::string& netns, const std::vector<std::string>& argv, const Peer& peer,
                              const std::array<int, 4>& fds) {
    if (::setns(ns_fd, CLONE_NEWNET) != 0 || ::unshare(CLONE_NEWNS) != 0 ||
        ::mount(nullptr, "/", nullptr, MS_SLAVE | MS_REC, nullptr) != 0) {
        ::_exit(125);
    }
    ::close(ns_fd);
    // As `ip netns exec`: /sys for this namespace, the namespace's resolv.conf.
    if (::umount2("/sys", MNT_DETACH) == 0) {
        (void)::mount(netns.c_str(), "/sys", "sysfs", 0, nullptr);
    }
    const std::string resolv = "/etc/netns/" + netns + "/resolv.conf";
    struct stat st {};
    if (::stat(resolv.c_str(), &st) == 0) {
        (void)::mount(resolv.c_str(), "/etc/resolv.conf", "none", MS_BIND, nullptr);
    }
    if (::setgroups(0, nullptr) != 0 || ::setresgid(peer.gid, peer.gid, peer.gid) != 0 ||
        ::setresuid(peer.uid, peer.uid, peer.uid) != 0 || ::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
        ::getuid() == 0) {
        ::_exit(126);
    }
    (void)::setpgid(0, 0);   // ksim may end the command and this helper together
    close_all_but({fds[0], fds[1], fds[2], fds[3]});
    const pid_t child = ::fork();
    if (child == 0) {
        if (::dup2(fds[0], 0) < 0 || ::dup2(fds[1], 1) < 0 || ::dup2(fds[2], 2) < 0) {
            ::_exit(127);
        }
        ::close_range(3, ~0U, 0);
        std::vector<char*> args;
        args.reserve(argv.size() + 1);
        for (const auto& a : argv) {
            args.push_back(const_cast<char*>(a.c_str()));   // NOLINT(cppcoreguidelines-pro-type-const-cast): execve's signature
        }
        args.push_back(nullptr);
        static const char* env[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C",
                                    "HOME=/", nullptr};
        ::execvpe(args[0], args.data(), const_cast<char* const*>(env));   // NOLINT(cppcoreguidelines-pro-type-const-cast)
        // Why the command did not start goes to its stderr (W1: EPERM from the bounding set).
        const int e = errno;
        const std::string why = "ksim-netd: exec " + argv[0] + ": " + std::strerror(e) + "\n";
        (void)!::write(2, why.data(), why.size());
        ::_exit(127);
    }
    ::close(fds[0]);
    ::close(fds[1]);
    ::close(fds[2]);
    int status = 0x7F00;   // as if exit 127, when the fork failed
    if (child > 0) {
        while (::waitpid(child, &status, 0) < 0 && errno == EINTR) {
        }
    }
    // ksim reads no status when this fails, and treats the command as unfinished.
    const bool told = ::write(fds[3], &status, sizeof(status)) == static_cast<ssize_t>(sizeof(status));
    ::_exit(told ? 0 : 1);
}

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

Result<void> LinuxOps::teardown(const std::string& netns) {
    // A UE's resolv.conf goes with its namespace.
    const std::string dir = std::string("/etc/netns/") + netns;
    ::unlink((dir + "/resolv.conf").c_str());
    ::rmdir(dir.c_str());
    return netns::del(netns);
}

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

// ---- the UEs' namespaces (P1 N11) -----------------------------------------------------------

// A namespace with IPv6 off and the echo sockets open, then lo up (L13): a UE's, and
// from P2 Q6 a DN's.
namespace {
Result<void> setup_isolated(const std::string& netns);
} // namespace

Result<void> LinuxOps::setup_ue(const std::string& netns) { return setup_isolated(netns); }

Result<void> LinuxOps::setup_dn(const std::string& netns) { return setup_isolated(netns); }

namespace {

Result<void> setup_isolated(const std::string& netns) {
    if (auto r = netns::add(netns); !r) {
        return r;
    }
    auto ns = netns::open(netns);
    if (!ns) {
        (void)netns::del(netns);
        return ns.error();
    }
    auto inside = netns::run_in(ns->get(), [&]() -> Result<void> {
        // L13: before any link is up.
        for (const char* p : {"/proc/sys/net/ipv6/conf/all/disable_ipv6", "/proc/sys/net/ipv6/conf/default/disable_ipv6"}) {
            if (auto r = write_file(p, "1"); !r) {
                return r;
            }
        }
        if (auto r = write_file("/proc/sys/net/ipv4/ping_group_range", "0 2147483647"); !r) {
            return r;
        }
        auto rt = nl::Rtnl::open();
        if (!rt) {
            return rt.error();
        }
        return link_up(*rt, "lo");
    });
    if (!inside) {
        (void)netns::del(netns);
        return inside.error();
    }
    return {};
}

} // namespace

Result<Fd> LinuxOps::tun(const std::string& netns, const TunSpec& t) {
    auto ns = netns::open(netns);
    if (!ns) {
        return ns.error();
    }
    Fd out;
    auto r = netns::run_in(ns->get(), [&]() -> Result<void> {
        Fd fd(::open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC));
        if (!fd) {
            return make_error(Errc::io, static_cast<std::uint32_t>(errno), "netd: /dev/net/tun");
        }
        ifreq ifr{};
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        std::memcpy(ifr.ifr_name, t.ifname.c_str(), std::min(t.ifname.size(), std::size_t{IFNAMSIZ - 1}));
        if (::ioctl(fd.get(), TUNSETIFF, &ifr) != 0) {
            return make_error(Errc::io, static_cast<std::uint32_t>(errno), "netd: TUNSETIFF");
        }
        const int idx = static_cast<int>(::if_nametoindex(t.ifname.c_str()));
        if (idx == 0) {
            return make_error(Errc::io, static_cast<std::uint32_t>(errno), "netd: the TUN has no index");
        }
        auto rt = nl::Rtnl::open();
        if (!rt) {
            return rt.error();
        }
        if (auto e = request(*rt, nl::set_mtu(rt->next_seq(), idx, t.mtu)); !e) {
            return e;
        }
        if (auto e = request(*rt, nl::new_addr_v4(rt->next_seq(), idx, t.addr, 32)); !e) {
            return e;
        }
        if (auto e = request(*rt, nl::set_link_up(rt->next_seq(), idx)); !e) {
            return e;
        }
        if (auto e = request(*rt, nl::new_default_route(rt->next_seq(), idx, t.table)); !e) {
            return e;
        }
        if (auto e = request(*rt, nl::new_rule_from(rt->next_seq(), t.addr, t.table)); !e) {
            return e;
        }
        if (t.main_default) {
            if (auto e = request(*rt, nl::new_default_route(rt->next_seq(), idx, kMainTable)); !e) {
                return e;
            }
        }
        out = std::move(fd);
        return {};
    });
    if (!r) {
        return r.error();
    }
    return out;
}

Result<void> LinuxOps::tun_down(const std::string& netns, const TunSpec& t) {
    auto ns = netns::open(netns);
    if (!ns) {
        return ns.error();
    }
    return netns::run_in(ns->get(), [&]() -> Result<void> {
        auto rt = nl::Rtnl::open();
        if (!rt) {
            return rt.error();
        }
        // The device goes with ksim's descriptor; the rule is netd's to remove.
        if (const unsigned idx = ::if_nametoindex(t.ifname.c_str()); idx != 0) {
            (void)rt->request(nl::del_link(rt->next_seq(), static_cast<int>(idx)));
        }
        auto e = request(*rt, nl::del_rule_from(rt->next_seq(), t.addr, t.table));
        if (!e && e.error().offset != ENOENT) {
            return e;
        }
        return {};
    });
}

Result<void> LinuxOps::resolv(const std::string& netns, std::array<std::uint8_t, 4> dns) {
    const std::string dir = std::string("/etc/netns/") + netns;
    if ((::mkdir("/etc/netns", 0755) != 0 && errno != EEXIST) || (::mkdir(dir.c_str(), 0755) != 0 && errno != EEXIST)) {
        return make_error(Errc::io, static_cast<std::uint32_t>(errno), "netd: /etc/netns");
    }
    Fd fd(::open((dir + "/resolv.conf").c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0644));
    const std::string text = "# ksim-netd: the PDU session's DNS server (ePCO 000DH)\nnameserver " + dotted(dns) + "\n";
    if (!fd || ::write(fd.get(), text.data(), text.size()) != static_cast<ssize_t>(text.size())) {
        return make_error(Errc::io, static_cast<std::uint32_t>(errno), "netd: resolv.conf");
    }
    return {};
}

Result<std::uint32_t> LinuxOps::exec(const std::string& netns, const std::vector<std::string>& argv, const Peer& peer,
                                     std::vector<Fd> fds) {
    auto ns = netns::open(netns);
    if (!ns) {
        return ns.error();
    }
    const std::array<int, 4> raw{fds[0].get(), fds[1].get(), fds[2].get(), fds[3].get()};
    const pid_t pid = ::fork();
    if (pid < 0) {
        return make_error(Errc::io, static_cast<std::uint32_t>(errno), "netd: fork");
    }
    if (pid == 0) {
        exec_helper(ns->get(), netns, argv, peer, raw);
    }
    return static_cast<std::uint32_t>(pid);   // the descriptors close here, in netd
}

// ---- netd v3 (P2 Q6) ------------------------------------------------------------------------

Result<void> LinuxOps::bridge() {
    auto rt = nl::Rtnl::open();
    if (!rt) {
        return rt.error();
    }
    if (::if_nametoindex(kMidBridge) == 0) {
        if (auto r = request(*rt, nl::new_bridge(rt->next_seq(), kMidBridge)); !r) {
            return r;
        }
    }
    return link_up(*rt, kMidBridge);
}

Result<void> LinuxOps::veth(const std::string& netns, std::array<std::uint8_t, 4> addr, std::uint8_t prefix) {
    if (auto r = bridge(); !r) {
        return r;
    }
    auto ns = netns::open(netns);
    if (!ns) {
        return ns.error();
    }
    auto rt = nl::Rtnl::open();
    if (!rt) {
        return rt.error();
    }
    const std::string host = mid_host_link(netns);
    if (auto r = request(*rt, nl::new_veth(rt->next_seq(), nl::Veth{host, kMidLink, ns->get()})); !r) {
        return r;
    }
    auto undo = [&](Error e) -> Result<void> {
        if (const unsigned i = ::if_nametoindex(host.c_str()); i != 0) {
            (void)rt->request(nl::del_link(rt->next_seq(), static_cast<int>(i)));   // its peer goes with it
        }
        return e;
    };
    const unsigned host_idx = ::if_nametoindex(host.c_str());
    const unsigned br_idx = ::if_nametoindex(kMidBridge);
    if (host_idx == 0 || br_idx == 0) {
        return undo(make_error(Errc::io, static_cast<std::uint32_t>(errno), "netd: the veth or ksim-mid has no index"));
    }
    if (auto r = request(*rt, nl::set_master(rt->next_seq(), static_cast<int>(host_idx), static_cast<int>(br_idx))); !r) {
        return undo(r.error());
    }
    if (auto r = link_up(*rt, host.c_str()); !r) {
        return undo(r.error());
    }
    auto inside = netns::run_in(ns->get(), [&]() -> Result<void> {
        auto in = nl::Rtnl::open();
        if (!in) {
            return in.error();
        }
        const unsigned idx = ::if_nametoindex(kMidLink);
        if (idx == 0) {
            return make_error(Errc::io, static_cast<std::uint32_t>(errno), "netd: the leg is not in the namespace");
        }
        if (auto r = request(*in, nl::new_addr_v4(in->next_seq(), static_cast<int>(idx), addr, prefix)); !r) {
            return r;
        }
        return link_up(*in, kMidLink);
    });
    if (!inside) {
        return undo(inside.error());
    }
    return {};
}

Result<Fd> LinuxOps::dn_tun(const std::string& netns, const DnTunSpec& t) {
    auto ns = netns::open(netns);
    if (!ns) {
        return ns.error();
    }
    Fd out;
    auto r = netns::run_in(ns->get(), [&]() -> Result<void> {
        Fd fd(::open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC));
        if (!fd) {
            return make_error(Errc::io, static_cast<std::uint32_t>(errno), "netd: /dev/net/tun");
        }
        ifreq ifr{};
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        std::memcpy(ifr.ifr_name, kDnLink, std::strlen(kDnLink));
        if (::ioctl(fd.get(), TUNSETIFF, &ifr) != 0) {
            return make_error(Errc::io, static_cast<std::uint32_t>(errno), "netd: TUNSETIFF");
        }
        const int idx = static_cast<int>(::if_nametoindex(kDnLink));
        if (idx == 0) {
            return make_error(Errc::io, static_cast<std::uint32_t>(errno), "netd: the TUN has no index");
        }
        auto rt = nl::Rtnl::open();
        if (!rt) {
            return rt.error();
        }
        if (auto e = request(*rt, nl::set_mtu(rt->next_seq(), idx, t.mtu)); !e) {
            return e;
        }
        if (auto e = request(*rt, nl::new_addr_v4(rt->next_seq(), idx, t.addr, 32)); !e) {
            return e;
        }
        if (auto e = request(*rt, nl::set_link_up(rt->next_seq(), idx)); !e) {
            return e;
        }
        if (auto e = request(*rt, nl::new_prefix_route(rt->next_seq(), idx, t.pool, t.pool_prefix)); !e) {
            return e;
        }
        out = std::move(fd);
        return {};
    });
    if (!r) {
        return r.error();
    }
    return out;
}

std::vector<std::string> LinuxOps::gc_links() {
    std::vector<std::string> gone;
    auto rt = nl::Rtnl::open();
    if (!rt) {
        return gone;
    }
    std::vector<std::string> names;
    if (struct if_nameindex* all = ::if_nameindex(); all != nullptr) {
        for (struct if_nameindex* i = all; i->if_index != 0; ++i) {
            const std::string n = i->if_name;
            if (n == kMidBridge || (n.rfind("ksim-m", 0) == 0 && n.size() == 12)) {
                names.push_back(n);
            }
        }
        ::if_freenameindex(all);
    }
    for (const auto& n : names) {
        if (const unsigned idx = ::if_nametoindex(n.c_str()); idx != 0 &&
            rt->request(nl::del_link(rt->next_seq(), static_cast<int>(idx)))) {
            gone.push_back(n);
        }
    }
    return gone;
}

void reap_children() {
    while (::waitpid(-1, nullptr, WNOHANG) > 0) {
    }
}

} // namespace ksim::net::netd
