// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// ksim-netd without root (P1 N9; ADR 0009 point 3): the request and reply
// format, what the policy refuses, and the client and server over a
// socketpair with a fake set of operations, a socket passed over SCM_RIGHTS.

#include <gtest/gtest.h>

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
    std::set<std::string> names{"other-ns"};
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
    EXPECT_FALSE(decode_request(Bytes{1, 9}));                 // no op 9
    EXPECT_FALSE(decode_request(Bytes{1, 3, 1, 'x', 3, 4}));   // socket kind 3
    EXPECT_FALSE(decode_request(Bytes(kMaxMessage + 1, 1)));
    FakeOps ops;
    Server srv(lab(), ops);
    std::optional<Fd> fd;
    EXPECT_EQ(srv.handle(Bytes{1, 9}, ::getuid(), fd).status, Status::malformed);
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

} // namespace
} // namespace ksim::net::netd
