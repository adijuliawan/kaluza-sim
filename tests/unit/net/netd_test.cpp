// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// ksim-netd without root (P1 N9; ADR 0009 point 3): the request and reply
// format, what the policy refuses, and the client and server over a
// socketpair with a fake set of operations, a socket passed over SCM_RIGHTS.
// P1 N11: the UE operations, a TUN handed back, exec's four descriptors
// passed the other way.

#include <gtest/gtest.h>

#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <set>
#include <thread>

#include "net/netd.hpp"

namespace ksim::net::netd {
namespace {

class FakeOps final : public INetOps {
public:
    Result<void> setup_node(const std::string& n, const std::string& parent, std::array<std::uint8_t, 4> addr,
                            std::uint8_t prefix) override {
        names.insert(n);
        last_parent = parent;
        last_addr = addr;
        last_prefix = prefix;
        return {};
    }
    Result<void> teardown(const std::string& n) override {
        names.erase(n);
        return {};
    }
    Result<Fd> socket(const std::string&, SockKind kind, int family) override {
        Fd fd(::socket(family, kind == SockKind::udp ? SOCK_DGRAM : SOCK_STREAM, 0));
        if (!fd) {
            return make_error(Errc::io, 0, "fake: socket");
        }
        return fd;
    }
    std::vector<std::string> list() override { return {names.begin(), names.end()}; }
    Result<void> setup_ue(const std::string& n) override {
        names.insert(n);
        return {};
    }
    Result<Fd> tun(const std::string&, const TunSpec& t) override {
        last_tun = t;
        int sv[2];
        if (::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) != 0) {
            return make_error(Errc::io, 0, "fake: socketpair");
        }
        tun_peer = Fd(sv[1]);   // the "kernel" side
        return Fd(sv[0]);
    }
    Result<void> tun_down(const std::string&, const TunSpec& t) override {
        downs.push_back(t.ifname);
        return {};
    }
    Result<void> resolv(const std::string&, std::array<std::uint8_t, 4> dns) override {
        last_dns = dns;
        return {};
    }
    Result<std::uint32_t> exec(const std::string&, const std::vector<std::string>& argv, const Peer& peer,
                               std::vector<Fd> fds) override {
        last_argv = argv;
        last_peer = peer;
        const std::string out = "ran " + argv.front() + "\n";
        const int status = 0;
        if (::write(fds[1].get(), out.data(), out.size()) != static_cast<ssize_t>(out.size()) ||
            ::write(fds[3].get(), &status, sizeof(status)) != static_cast<ssize_t>(sizeof(status))) {
            return make_error(Errc::io, 0, "fake: write");
        }
        return 4242;
    }
    std::set<std::string> names{"other-ns"};
    TunSpec last_tun;
    Fd tun_peer;
    std::vector<std::string> downs;
    std::array<std::uint8_t, 4> last_dns{};
    std::vector<std::string> last_argv;
    Peer last_peer;
    std::string last_parent;
    std::array<std::uint8_t, 4> last_addr{};
    std::uint8_t last_prefix = 0;
};

Policy lab() {
    Policy p;
    p.uid = ::getuid();
    p.parent = "ens19";
    p.first = {172, 30, 30, 30};
    p.last = {172, 30, 30, 39};
    p.prefix = 24;
    return p;
}

Request setup(const std::string& n, const std::string& parent, std::array<std::uint8_t, 4> addr, std::uint8_t prefix = 24) {
    Request r;
    r.op = Op::setup_node;
    r.netns = n;
    r.parent = parent;
    r.addr = addr;
    r.prefix = prefix;
    return r;
}

Reply ask(Server& s, const Request& r, unsigned uid = ::getuid()) {
    std::optional<Fd> fd;
    return s.handle(encode(r), uid, fd);
}

TEST(Netd, RequestsAndRepliesRoundTrip) {
    Request s = setup("ksim-cucp", "ens19", {172, 30, 30, 30});
    auto back = decode_request(encode(s));
    ASSERT_TRUE(back);
    EXPECT_EQ(back->netns, "ksim-cucp");
    EXPECT_EQ(back->parent, "ens19");
    EXPECT_EQ(back->addr, (std::array<std::uint8_t, 4>{172, 30, 30, 30}));
    Request k;
    k.op = Op::socket;
    k.netns = "ksim-cuup";
    k.kind = SockKind::udp;
    k.family = 6;
    back = decode_request(encode(k));
    ASSERT_TRUE(back);
    EXPECT_EQ(back->kind, SockKind::udp);
    EXPECT_EQ(back->family, 6);
    Reply r;
    r.status = Status::failed;
    r.err = 17;
    r.message = "exists";
    r.names = {"ksim-a", "ksim-b"};
    auto rb = decode_reply(encode(r));
    ASSERT_TRUE(rb);
    EXPECT_EQ(rb->err, 17u);
    EXPECT_EQ(rb->names.size(), 2u);
}

TEST(Netd, MalformedRequestsAreRefusedBeforeAnythingRuns) {
    Bytes ok = encode(setup("ksim-cucp", "ens19", {172, 30, 30, 30}));
    for (std::size_t cut = 0; cut < ok.size(); ++cut) {
        EXPECT_FALSE(decode_request(ByteView(ok.data(), cut))) << cut;
    }
    Bytes trailing = ok;
    trailing.push_back(0);
    EXPECT_FALSE(decode_request(trailing));
    EXPECT_FALSE(decode_request(Bytes{2, 4}));                 // version 2
    EXPECT_FALSE(decode_request(Bytes{1, 99}));                // no op 99
    EXPECT_FALSE(decode_request(Bytes{1, 3, 1, 'x', 3, 4}));   // socket kind 3
    EXPECT_FALSE(decode_request(Bytes(kMaxMessage + 1, 1)));
    FakeOps ops;
    Server srv(lab(), ops);
    std::optional<Fd> fd;
    EXPECT_EQ(srv.handle(Bytes{1, 99}, ::getuid(), fd).status, Status::malformed);
}

TEST(Netd, ThePolicyRefusesOtherUidsNamesParentsAndAddresses) {
    FakeOps ops;
    Server srv(lab(), ops);
    EXPECT_EQ(ask(srv, setup("ksim-cucp", "ens19", {172, 30, 30, 30}), ::getuid() + 1).status, Status::refused);
    for (const char* bad : {"cucp", "ksim-", "ksim-UP", "ksim--x", "ksim-a/b", "ksim-x y", "ksim-0123456789012345678901234567"}) {
        EXPECT_EQ(ask(srv, setup(bad, "ens19", {172, 30, 30, 30})).status, Status::refused) << bad;
    }
    EXPECT_EQ(ask(srv, setup("ksim-cucp", "eth0", {172, 30, 30, 30})).status, Status::refused);   // not the parent
    EXPECT_EQ(ask(srv, setup("ksim-cucp", "ens19", {172, 30, 30, 1})).status, Status::refused);   // the AMF's address
    EXPECT_EQ(ask(srv, setup("ksim-cucp", "ens19", {172, 30, 30, 40})).status, Status::refused);
    EXPECT_EQ(ask(srv, setup("ksim-cucp", "ens19", {172, 30, 30, 30}, 16)).status, Status::refused);
    EXPECT_TRUE(ops.names.count("ksim-cucp") == 0);
    EXPECT_EQ(ask(srv, setup("ksim-cucp", "ens19", {172, 30, 30, 39})).status, Status::ok);
    EXPECT_EQ(ops.last_parent, "ens19");
    EXPECT_EQ(ask(srv, setup("ksim-cucp", "ens19", {172, 30, 30, 31})).status, Status::refused);   // exists
    Request t;
    t.op = Op::teardown;
    t.netns = "other-ns";   // not ours: never touched
    EXPECT_EQ(ask(srv, t).status, Status::refused);
    EXPECT_TRUE(ops.names.count("other-ns") == 1);
}

TEST(Netd, OnTheDevPcNoParentLinkIsAllowed) {
    FakeOps ops;
    Policy p = lab();
    p.parent.clear();
    Server srv(p, ops);
    EXPECT_EQ(ask(srv, setup("ksim-cucp", "ens19", {172, 30, 30, 30})).status, Status::refused);
    EXPECT_EQ(ask(srv, setup("ksim-cucp", "", {0, 0, 0, 0}, 0)).status, Status::ok);   // a namespace with lo only
}

TEST(Netd, ClientAndServerPassASocketOverSeqpacket) {
    int sv[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv), 0);
    FakeOps ops;
    Server srv(lab(), ops);
    std::thread server([&] {
        while (serve_one(sv[1], srv)) {
        }
        ::close(sv[1]);
    });
    {
        Client c = Client::adopt(Fd(sv[0]));
        ASSERT_TRUE(c.setup_node("ksim-cucp", "ens19", {172, 30, 30, 30}, 24));
        auto bad = c.setup_node("ksim-cucp", "ens19", {172, 30, 30, 30}, 24);
        EXPECT_FALSE(bad);
        EXPECT_EQ(c.last_error(), "netd: the namespace exists");
        auto fd = c.socket("ksim-cucp", SockKind::udp, AF_INET);
        ASSERT_TRUE(fd);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        EXPECT_EQ(::bind(fd->get(), reinterpret_cast<const sockaddr*>(&a), sizeof(a)), 0);   // a working socket
        EXPECT_FALSE(c.socket("ksim-nope", SockKind::udp, AF_INET));
        auto names = c.list();
        ASSERT_TRUE(names);
        EXPECT_EQ(*names, (std::vector<std::string>{"ksim-cucp"}));   // other-ns is not listed
        ASSERT_TRUE(c.gc());
        EXPECT_EQ(ops.names, (std::set<std::string>{"other-ns"}));
    }
    server.join();
}

// ---- the UEs' namespaces (P1 N11) ---------------------------------------------------------

Request ue_op(Op op, const std::string& n = "ksim-ue-3") {
    Request r;
    r.op = op;
    r.netns = n;
    return r;
}

Request tun_req(const std::string& ifname, std::array<std::uint8_t, 4> addr, std::uint16_t mtu, std::uint8_t table) {
    Request r = ue_op(Op::tun);
    r.ifname = ifname;
    r.addr = addr;
    r.mtu = mtu;
    r.table = table;
    return r;
}

TEST(Netd, UeRequestsAndThePidRoundTrip) {
    Request t = tun_req("pdu2", {10, 45, 0, 7}, 1400, 102);
    t.main_default = true;
    auto back = decode_request(encode(t));
    ASSERT_TRUE(back);
    EXPECT_EQ(back->op, Op::tun);
    EXPECT_EQ(back->ifname, "pdu2");
    EXPECT_EQ(back->addr, (std::array<std::uint8_t, 4>{10, 45, 0, 7}));
    EXPECT_EQ(back->mtu, 1400);
    EXPECT_EQ(back->table, 102);
    EXPECT_TRUE(back->main_default);
    Request e = ue_op(Op::exec);
    e.argv = {"ping", "-c", "3", "172.30.61.1"};
    back = decode_request(encode(e));
    ASSERT_TRUE(back);
    EXPECT_EQ(back->argv, e.argv);
    for (std::size_t cut = 0; cut < encode(e).size(); ++cut) {
        EXPECT_FALSE(decode_request(ByteView(encode(e).data(), cut))) << cut;
    }
    Request none = ue_op(Op::exec);   // no words
    EXPECT_FALSE(decode_request(encode(none)));
    Request many = ue_op(Op::exec);
    many.argv.assign(17, "x");
    EXPECT_FALSE(decode_request(encode(many)));
    Reply r;
    r.pid = 4242;
    auto rb = decode_reply(encode(r));
    ASSERT_TRUE(rb);
    EXPECT_EQ(rb->pid, 4242u);
}

TEST(Netd, ThePolicyKeepsTheUeOperationsToUeNamespacesAndSaneDevices) {
    FakeOps ops;
    Server srv(lab(), ops);
    EXPECT_EQ(ask(srv, ue_op(Op::setup_ue, "ksim-cucp")).status, Status::refused);   // not a UE's
    EXPECT_EQ(ask(srv, ue_op(Op::setup_ue, "ksim-ue-")).status, Status::refused);
    EXPECT_EQ(ask(srv, tun_req("pdu1", {10, 45, 0, 2}, 1400, 101)).status, Status::refused);   // not set up
    ASSERT_EQ(ask(srv, ue_op(Op::setup_ue)).status, Status::ok);
    EXPECT_EQ(ask(srv, ue_op(Op::setup_ue)).status, Status::refused);   // exists
    EXPECT_EQ(ask(srv, tun_req("pdu0", {10, 45, 0, 2}, 1400, 101)).status, Status::refused);
    EXPECT_EQ(ask(srv, tun_req("pdu16", {10, 45, 0, 2}, 1400, 101)).status, Status::refused);
    EXPECT_EQ(ask(srv, tun_req("eth0", {10, 45, 0, 2}, 1400, 101)).status, Status::refused);
    EXPECT_EQ(ask(srv, tun_req("pdu1", {10, 45, 0, 2}, 575, 101)).status, Status::refused);
    EXPECT_EQ(ask(srv, tun_req("pdu1", {10, 45, 0, 2}, 9001, 101)).status, Status::refused);
    EXPECT_EQ(ask(srv, tun_req("pdu1", {10, 45, 0, 2}, 1400, 100)).status, Status::refused);   // main tables
    EXPECT_EQ(ask(srv, tun_req("pdu1", {10, 45, 0, 2}, 1400, 254)).status, Status::refused);
    for (std::array<std::uint8_t, 4> a : {std::array<std::uint8_t, 4>{0, 0, 0, 0}, {127, 0, 0, 1}, {224, 0, 0, 1},
                                          {169, 254, 1, 1}, {255, 255, 255, 255}}) {
        EXPECT_EQ(ask(srv, tun_req("pdu1", a, 1400, 101)).status, Status::refused);
    }
    EXPECT_EQ(ask(srv, tun_req("pdu15", {10, 45, 0, 2}, 1400, 115)).status, Status::ok);
    Request dns = ue_op(Op::resolv);
    dns.addr = {127, 0, 0, 53};
    EXPECT_EQ(ask(srv, dns).status, Status::refused);
    dns.addr = {10, 45, 0, 1};
    EXPECT_EQ(ask(srv, dns).status, Status::ok);
    Request e = ue_op(Op::exec);
    e.argv = {"true"};
    EXPECT_EQ(ask(srv, e).status, Status::refused);   // no descriptors
    std::optional<Fd> fd;
    std::vector<Fd> four;
    four.reserve(4);
    for (int i = 0; i < 4; ++i) {
        four.emplace_back(::dup(0));
    }
    EXPECT_EQ(srv.handle(encode(e), Peer{::getuid(), 0}, std::move(four), fd).status, Status::refused);   // gid 0
    std::vector<Fd> one;
    one.emplace_back(::dup(0));
    EXPECT_EQ(srv.handle(encode(dns), Peer{::getuid(), ::getgid()}, std::move(one), fd).status,
              Status::refused);   // descriptors go with exec only
}

TEST(Netd, ClientAndServerPassATunOneWayAndExecDescriptorsTheOther) {
    if (::getuid() == 0) {
        GTEST_SKIP() << "exec is never for root";
    }
    int sv[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv), 0);
    FakeOps ops;
    Server srv(lab(), ops);
    std::thread server([&] {
        while (serve_one(sv[1], srv)) {
        }
        ::close(sv[1]);
    });
    {
        Client c = Client::adopt(Fd(sv[0]));
        ASSERT_TRUE(c.setup_ue("ksim-ue-3"));
        auto tun = c.tun("ksim-ue-3", TunSpec{"pdu1", {10, 45, 0, 2}, 1400, 101, true});
        ASSERT_TRUE(tun);
        EXPECT_TRUE(ops.last_tun.main_default);
        const Bytes packet{0x45, 0, 0, 20};
        ASSERT_EQ(::write(ops.tun_peer.get(), packet.data(), packet.size()), 4);   // the device gives a packet
        Bytes got(64);
        EXPECT_EQ(::read(tun->get(), got.data(), got.size()), 4);
        ASSERT_TRUE(c.resolv("ksim-ue-3", {10, 45, 0, 1}));
        EXPECT_EQ(ops.last_dns, (std::array<std::uint8_t, 4>{10, 45, 0, 1}));
        int in[2], out[2], err[2], st[2];
        ASSERT_EQ(::pipe2(in, O_CLOEXEC), 0);
        ASSERT_EQ(::pipe2(out, O_CLOEXEC), 0);
        ASSERT_EQ(::pipe2(err, O_CLOEXEC), 0);
        ASSERT_EQ(::pipe2(st, O_CLOEXEC), 0);
        auto pid = c.exec("ksim-ue-3", {"ip", "-o", "addr"}, {in[0], out[1], err[1], st[1]});
        ASSERT_TRUE(pid);
        EXPECT_EQ(*pid, 4242u);
        EXPECT_EQ(ops.last_argv, (std::vector<std::string>{"ip", "-o", "addr"}));
        EXPECT_EQ(ops.last_peer.uid, ::getuid());
        EXPECT_EQ(ops.last_peer.gid, ::getgid());
        for (int f : {in[0], out[1], err[1], st[1]}) {
            ::close(f);
        }
        char buf[64] = {};
        EXPECT_EQ(::read(out[0], buf, sizeof(buf)), 7);
        EXPECT_EQ(std::string(buf, 7), "ran ip\n");
        int status = -1;
        EXPECT_EQ(::read(st[0], &status, sizeof(status)), static_cast<ssize_t>(sizeof(status)));
        EXPECT_EQ(status, 0);
        for (int f : {in[1], out[0], err[0], st[0]}) {
            ::close(f);
        }
        ASSERT_TRUE(c.tun_down("ksim-ue-3", TunSpec{"pdu1", {10, 45, 0, 2}, 1400, 101, false}));
        EXPECT_EQ(ops.downs, (std::vector<std::string>{"pdu1"}));
    }
    server.join();
}

} // namespace
} // namespace ksim::net::netd
