// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The privileged netd smoke (P1 N9; tools/ci.d/66-netd-priv.sh, opt-in): against
// a real ksim-netd running as root, make a namespace with no parent link (the
// dev PC allows none), get a UDP socket made inside it, check it is in another
// namespace than ours (its lo answers only to itself), then gc, and check no
// ksim- namespace is left. From P2 Q6 (netd v3; the hook's netd has --dn
// 10.60.0.0/24): a DN namespace with its TUN dn0 (10.60.0.1, the UE pool
// 10.45.0.0/16 routed to it); an ICMP echo request from 10.45.0.2 written into
// the TUN is answered by the namespace's kernel, out of the same TUN. No bridge
// and no veth here: the dev PC has none (P-64).
//
//   netd_smoke <netd socket>

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "net/netd.hpp"

using namespace ksim::net::netd;

namespace {

std::uint16_t csum(const std::uint8_t* p, std::size_t n) {
    std::uint32_t s = 0;
    for (std::size_t i = 0; i + 1 < n; i += 2) {
        s += static_cast<std::uint32_t>(p[i] << 8 | p[i + 1]);
    }
    if (n % 2 != 0) {
        s += static_cast<std::uint32_t>(p[n - 1] << 8);
    }
    while (s >> 16 != 0) {
        s = (s & 0xFFFF) + (s >> 16);
    }
    return static_cast<std::uint16_t>(~s);
}

/// The DN namespace's TUN answers an echo request from the UE pool (P2 Q6).
bool dn_echo(Client& c) {
    if (!c.setup_dn("ksim-dn-smoke")) {
        std::printf("NETD_SMOKE: setup_dn %s\n", c.last_error().c_str());
        return false;
    }
    auto tun = c.dn_tun("ksim-dn-smoke", DnTunSpec{{10, 60, 0, 1}, 1500, {10, 45, 0, 0}, 16});
    if (!tun) {
        std::printf("NETD_SMOKE: dn_tun %s\n", c.last_error().c_str());
        return false;
    }
    std::uint8_t pkt[28] = {0x45, 0, 0, 28, 0x12, 0x34, 0, 0, 64, 1, 0, 0, 10, 45, 0, 2, 10, 60, 0, 1,
                            8, 0, 0, 0, 0x6b, 0x73, 0, 1};   // ICMP echo request, id 0x6b73, seq 1
    const std::uint16_t ip = csum(pkt, 20);
    pkt[10] = static_cast<std::uint8_t>(ip >> 8);
    pkt[11] = static_cast<std::uint8_t>(ip);
    const std::uint16_t ic = csum(pkt + 20, 8);
    pkt[22] = static_cast<std::uint8_t>(ic >> 8);
    pkt[23] = static_cast<std::uint8_t>(ic);
    if (::write(tun->get(), pkt, sizeof(pkt)) != static_cast<ssize_t>(sizeof(pkt))) {
        std::printf("NETD_SMOKE: write to dn0\n");
        return false;
    }
    std::uint8_t back[256] = {};
    for (int i = 0; i < 200; ++i) {
        const ssize_t n = ::read(tun->get(), back, sizeof(back));
        // An echo reply (type 0) from 10.60.0.1 to 10.45.0.2.
        if (n >= 28 && back[9] == 1 && back[20] == 0 && back[12] == 10 && back[13] == 60 && back[16] == 10 &&
            back[17] == 45 && back[19] == 2) {
            return true;
        }
        ::usleep(10'000);
    }
    std::printf("NETD_SMOKE: no echo reply on dn0\n");
    return false;
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fputs("usage: netd_smoke <socket>\n", stderr);
        return 2;
    }
    auto c = Client::connect(argv[1]);
    if (!c) {
        std::printf("NETD_SMOKE=FAIL connect\n");
        return 1;
    }
    if (!c->setup_node("ksim-smoke", "", {0, 0, 0, 0}, 0)) {
        std::printf("NETD_SMOKE=FAIL setup %s\n", c->last_error().c_str());
        return 1;
    }
    auto fd = c->socket("ksim-smoke", SockKind::udp, AF_INET);
    if (!fd) {
        std::printf("NETD_SMOKE=FAIL socket %s\n", c->last_error().c_str());
        return 1;
    }
    // Inside the namespace: bind lo, send to ourselves, read it back.
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t len = sizeof(a);
    if (::bind(fd->get(), reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0 ||
        ::getsockname(fd->get(), reinterpret_cast<sockaddr*>(&a), &len) != 0) {
        std::printf("NETD_SMOKE=FAIL bind in the namespace\n");
        return 1;
    }
    const char ping[] = "ksim";
    char got[8] = {};
    if (::sendto(fd->get(), ping, 4, 0, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 4) {
        std::printf("NETD_SMOKE=FAIL send\n");
        return 1;
    }
    for (int i = 0; i < 100 && ::recv(fd->get(), got, sizeof(got), MSG_DONTWAIT) != 4; ++i) {
        ::usleep(10'000);
    }
    // The same port in our own namespace is free: the socket is not ours.
    const int mine = ::socket(AF_INET, SOCK_DGRAM, 0);
    const bool elsewhere = mine >= 0 && ::bind(mine, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0;
    ::close(mine);
    const bool dn = dn_echo(*c);
    auto names = c->list();
    const bool listed = names && names->size() == 2 &&
                        std::find(names->begin(), names->end(), "ksim-smoke") != names->end() &&
                        std::find(names->begin(), names->end(), "ksim-dn-smoke") != names->end();
    const bool gc = static_cast<bool>(c->gc());
    auto after = c->list();
    const bool clean = after && after->empty();
    const bool ok = std::memcmp(got, ping, 4) == 0 && elsewhere && dn && listed && gc && clean;
    std::printf("NETD_SMOKE=%s loop=%d other_ns=%d dn_echo=%d listed=%d gc=%d left=%zu\n", ok ? "PASS" : "FAIL",
                std::memcmp(got, ping, 4) == 0, elsewhere, dn, listed, gc, after ? after->size() : 99U);
    return ok ? 0 : 1;
}
