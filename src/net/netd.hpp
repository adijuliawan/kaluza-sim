// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// ksim-netd, the privilege boundary (P1 N9; ADR 0009 points 3 and 4): a root
// helper on /run/ksim/netd.sock (SOCK_SEQPACKET) that does the few things
// ksim may not, for ksim's own uid only (SO_PEERCRED), within an allowlist:
//
//   setup_node <netns> <parent> <addr>/<prefix>  a namespace "ksim-…" with lo up and,
//                                                given a parent, an L2 ipvlan "ksim0"
//                                                on it carrying the address
//   teardown <netns>                             the namespace and its links go
//   socket <netns> sctp|udp v4|v6                a socket made inside the namespace,
//                                                handed back over SCM_RIGHTS
//   list, gc                                     the "ksim-" namespaces; remove them all
//
// and from P1 N11 for the UEs' namespaces "ksim-ue-<n>" (data-plane.md):
//
//   setup_ue <netns>                             a namespace with IPv6 off and the ICMP
//                                                echo sockets open to every group, both
//                                                set before any link is up (L13), lo up
//   tun <netns> pdu<psi> <addr> <mtu> <table>    a TUN device in it carrying the session's
//       [main]                                   address and MTU, up, a default route in
//                                                the session's table and a rule from the
//                                                address to it (and with main, the main
//                                                table's default route); its fd handed back
//   tun_down <netns> pdu<psi> <addr> <table>     the device and its rule go
//   resolv <netns> <dns>                         /etc/netns/<netns>/resolv.conf
//   exec <netns> <argv…> + 4 fds                 a command run inside it as the asking
//                                                uid and gid (never root), stdin, stdout,
//                                                stderr from the fds passed, its wait
//                                                status written to the fourth; the pid
//                                                comes back
//
// and from P2 Q6 (netd v3, ADR 0011):
//
//   bridge                                       kaluza-uesim only (--mid): the bridge
//                                                "ksim-mid", up, no address, no uplink
//   veth <netns> <addr>/<prefix>                 a node namespace's leg on it: a veth
//                                                pair, "ksim-m<6 hex>" on the bridge,
//                                                "mid0" in the namespace with the
//                                                address (in the --mid range)
//   setup_dn <netns>                             a DN namespace "ksim-dn-…" (--dn): IPv6
//                                                off, lo up, as a UE's
//   dn_tun <netns> <addr> <mtu> <pool>/<len>     a TUN "dn0" in it carrying the DN's
//                                                address (in the --dn range) and a route
//                                                to the UE pool; its fd handed back (the
//                                                stub's UPF reads and writes it)
//
// exec runs in any namespace netd made (a UE's, a node's for an interop peer,
// a DN's for a traffic server), still as the asking uid; gc also removes
// ksim-mid and any "ksim-m…" link left on the host.
//
// A socket keeps the namespace it was made in, so ksim binds, connects and
// uses it in its own namespace and never calls setns (point 4). Requests and
// replies are a small binary format (a root process parses as little as it
// can): version 1, the op, then length-prefixed fields; see encode() below.
// The policy: names ^ksim-[a-z0-9][a-z0-9-]{0,26}$, the parent only the one
// configured (none on the dev PC), addresses only inside the configured range;
// the UE operations only on "ksim-ue-" namespaces netd lists, a device name
// pdu1..pdu15, an MTU 576..9000, a table 101..115.

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "platform/buf.hpp"
#include "platform/reactor.hpp"
#include "platform/result.hpp"

namespace ksim::net::netd {

inline constexpr const char* kSocketPath = "/run/ksim/netd.sock";
inline constexpr std::size_t kMaxMessage = 1024;

enum class Op : std::uint8_t {
    setup_node = 1, teardown = 2, socket = 3, list = 4, gc = 5,
    setup_ue = 6, tun = 7, tun_down = 8, resolv = 9, exec = 10,
    bridge = 11, veth = 12, setup_dn = 13, dn_tun = 14,
};
inline constexpr const char* kMidBridge = "ksim-mid";   // P2 Q6
inline constexpr const char* kMidLink = "mid0";         // a node's leg, in its namespace
inline constexpr const char* kDnLink = "dn0";           // a DN namespace's TUN
enum class SockKind : std::uint8_t { sctp = 1, udp = 2 };
enum class Status : std::uint8_t { ok = 0, refused = 1, failed = 2, malformed = 3 };

struct Request {
    Op op = Op::list;
    std::string netns;
    std::string parent;                   // setup_node: "" for no link
    std::array<std::uint8_t, 4> addr{};   // setup_node; tun, tun_down: the UE's; resolv: the DNS server
    std::uint8_t prefix = 0;              // setup_node
    SockKind kind = SockKind::udp;        // socket
    std::uint8_t family = 4;              // socket: 4 or 6
    std::string ifname;                   // tun, tun_down: pdu1..pdu15
    std::uint16_t mtu = 0;                // tun
    std::uint8_t table = 0;               // tun, tun_down: 101..115
    bool main_default = false;            // tun: the main table's default route too
    std::vector<std::string> argv;        // exec: 1..16 words
    std::array<std::uint8_t, 4> pool{};   // dn_tun: the UE pool the DN routes to dn0
    std::uint8_t pool_prefix = 0;         // dn_tun: 8..30
};

/// The asking process, from SO_PEERCRED.
struct Peer {
    unsigned uid = 0;
    unsigned gid = 0;
};

/// A TUN device for a session (op tun).
struct TunSpec {
    std::string ifname;
    std::array<std::uint8_t, 4> addr{};
    std::uint16_t mtu = 1500;
    std::uint8_t table = 101;
    bool main_default = false;
};

/// A DN namespace's TUN (op dn_tun, P2 Q6).
struct DnTunSpec {
    std::array<std::uint8_t, 4> addr{};   // the DN's address, /32 on dn0
    std::uint16_t mtu = 1500;
    std::array<std::uint8_t, 4> pool{};   // routed to dn0
    std::uint8_t pool_prefix = 16;
};

struct Reply {
    Status status = Status::ok;
    std::uint32_t err = 0;                // errno, when failed
    std::string message;
    std::vector<std::string> names;       // list
    std::uint32_t pid = 0;                // exec
};

Bytes encode(const Request& r);
Result<Request> decode_request(ByteView in);
Bytes encode(const Reply& r);
Result<Reply> decode_reply(ByteView in);

struct Policy {
    unsigned uid = 0;                     // the only peer uid served
    std::string parent;                   // the one parent link allowed; "" = none
    std::array<std::uint8_t, 4> first{};  // the address range allowed
    std::array<std::uint8_t, 4> last{};
    std::uint8_t prefix = 24;
    // P2 Q6: ksim-mid and its legs (kaluza-uesim only; none on the dev PC, P-64).
    bool mid = false;
    std::array<std::uint8_t, 4> mid_first{};
    std::array<std::uint8_t, 4> mid_last{};
    std::uint8_t mid_prefix = 24;
    // P2 Q6: DN namespaces and the addresses their TUN may carry.
    bool dn = false;
    std::array<std::uint8_t, 4> dn_first{};
    std::array<std::uint8_t, 4> dn_last{};
};

bool valid_name(const std::string& n);
/// A UE's namespace: valid_name and "ksim-ue-…".
bool ue_name(const std::string& n);
/// A DN namespace: valid_name and "ksim-dn-…" (P2 Q6).
bool dn_name(const std::string& n);
/// The host end of a node's ksim-mid leg: "ksim-m" and six hex digits of the
/// namespace's name (P2 Q6).
std::string mid_host_link(const std::string& netns);

/// What netd does to the system; the real one needs root (ops_linux.cpp),
/// tests use a fake.
class INetOps {
public:
    virtual ~INetOps() = default;
    virtual Result<void> setup_node(const std::string& netns, const std::string& parent,
                                    std::array<std::uint8_t, 4> addr, std::uint8_t prefix) = 0;
    virtual Result<void> teardown(const std::string& netns) = 0;
    virtual Result<Fd> socket(const std::string& netns, SockKind kind, int family) = 0;
    virtual std::vector<std::string> list() = 0;
    // The UEs' namespaces (P1 N11).
    virtual Result<void> setup_ue(const std::string& netns) = 0;
    virtual Result<Fd> tun(const std::string& netns, const TunSpec& t) = 0;
    virtual Result<void> tun_down(const std::string& netns, const TunSpec& t) = 0;
    virtual Result<void> resolv(const std::string& netns, std::array<std::uint8_t, 4> dns) = 0;
    /// Starts `argv` in the namespace as `peer`; fds: stdin, stdout, stderr, the status pipe. The pid.
    virtual Result<std::uint32_t> exec(const std::string& netns, const std::vector<std::string>& argv, const Peer& peer,
                                       std::vector<Fd> fds) = 0;
    // P2 Q6.
    virtual Result<void> bridge() = 0;
    virtual Result<void> veth(const std::string& netns, std::array<std::uint8_t, 4> addr, std::uint8_t prefix) = 0;
    virtual Result<void> setup_dn(const std::string& netns) = 0;
    virtual Result<Fd> dn_tun(const std::string& netns, const DnTunSpec& t) = 0;
    /// Removes ksim-mid and any ksim-m… link on the host; the names removed.
    virtual std::vector<std::string> gc_links() = 0;
};

/// The request handler: policy first, then the operation.
class Server {
public:
    Server(Policy p, INetOps& ops) : p_(std::move(p)), ops_(ops) {}
    /// The reply to one request from `peer`, with the descriptors it passed
    /// (exec's four; any others are closed); a socket or TUN goes in `fd`.
    Reply handle(ByteView request, const Peer& peer, std::vector<Fd> in, std::optional<Fd>& fd);
    /// The same with no descriptors passed and the uid as gid.
    Reply handle(ByteView request, unsigned uid, std::optional<Fd>& fd);

private:
    Reply refuse(const char* why) const;
    Policy p_;
    INetOps& ops_;
};

/// Reads one request on a connected SOCK_SEQPACKET socket, takes the peer's
/// uid from SO_PEERCRED, and answers (a socket goes along over SCM_RIGHTS).
/// False when the peer has gone or the socket failed.
bool serve_one(int conn, Server& s);

/// Serves `path` (its directory is created 0755; the socket is 0666, since
/// SO_PEERCRED decides who is served) until `stop` is set or a signal
/// interrupts it, at most 8 connections at a time; removes the socket after.
Result<void> run_server(const std::string& path, Server& s, const volatile int& stop);

/// The real operations (root only).
class LinuxOps final : public INetOps {
public:
    Result<void> setup_node(const std::string& netns, const std::string& parent, std::array<std::uint8_t, 4> addr,
                            std::uint8_t prefix) override;
    Result<void> teardown(const std::string& netns) override;
    Result<Fd> socket(const std::string& netns, SockKind kind, int family) override;
    std::vector<std::string> list() override;
    Result<void> setup_ue(const std::string& netns) override;
    Result<Fd> tun(const std::string& netns, const TunSpec& t) override;
    Result<void> tun_down(const std::string& netns, const TunSpec& t) override;
    Result<void> resolv(const std::string& netns, std::array<std::uint8_t, 4> dns) override;
    Result<std::uint32_t> exec(const std::string& netns, const std::vector<std::string>& argv, const Peer& peer,
                               std::vector<Fd> fds) override;
    Result<void> bridge() override;
    Result<void> veth(const std::string& netns, std::array<std::uint8_t, 4> addr, std::uint8_t prefix) override;
    Result<void> setup_dn(const std::string& netns) override;
    Result<Fd> dn_tun(const std::string& netns, const DnTunSpec& t) override;
    std::vector<std::string> gc_links() override;
};

/// Reaps the exec helpers that ended (run_server calls it each turn).
void reap_children();

/// ksim's side: one connection, one request at a time.
class Client {
public:
    static Result<Client> connect(const std::string& path = kSocketPath);
    /// A client on a connected SOCK_SEQPACKET socket (tests: a socketpair).
    static Client adopt(Fd fd) { return Client(std::move(fd)); }
    Result<void> setup_node(const std::string& netns, const std::string& parent, std::array<std::uint8_t, 4> addr,
                            std::uint8_t prefix);
    Result<void> teardown(const std::string& netns);
    Result<Fd> socket(const std::string& netns, SockKind kind, int family);
    Result<std::vector<std::string>> list();
    Result<void> gc();
    Result<void> setup_ue(const std::string& netns);
    Result<Fd> tun(const std::string& netns, const TunSpec& t);
    Result<void> tun_down(const std::string& netns, const TunSpec& t);
    Result<void> resolv(const std::string& netns, std::array<std::uint8_t, 4> dns);
    /// fds: stdin, stdout, stderr and the status pipe's write end (netd writes
    /// the command's wait status there, four octets in host order, then closes it).
    Result<std::uint32_t> exec(const std::string& netns, const std::vector<std::string>& argv, const std::vector<int>& fds);
    // P2 Q6.
    Result<void> bridge();
    Result<void> veth(const std::string& netns, std::array<std::uint8_t, 4> addr, std::uint8_t prefix);
    Result<void> setup_dn(const std::string& netns);
    Result<Fd> dn_tun(const std::string& netns, const DnTunSpec& t);
    /// netd's message for the last request that did not succeed.
    const std::string& last_error() const noexcept { return last_; }

private:
    explicit Client(Fd fd) : fd_(std::move(fd)) {}
    Result<Reply> call(const Request& r, std::optional<Fd>* fd, const std::vector<int>& pass = {});
    Fd fd_;
    std::string last_;
};

} // namespace ksim::net::netd
