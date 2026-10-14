// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The privileged netd smoke (P1 N9; tools/ci.d/66-netd-priv.sh, opt-in): against
// a real ksim-netd running as root, make a namespace with no parent link (the
// dev PC allows none), get a UDP socket made inside it, check it is in another
// namespace than ours (its lo answers only to itself), then gc, and check no
// ksim- namespace is left.
//
//   netd_smoke <netd socket>

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>

#include "net/netd.hpp"

using namespace ksim::net::netd;

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
    auto names = c->list();
    const bool listed = names && names->size() == 1 && names->front() == "ksim-smoke";
    const bool gc = static_cast<bool>(c->gc());
    auto after = c->list();
    const bool clean = after && after->empty();
    const bool ok = std::memcmp(got, ping, 4) == 0 && elsewhere && listed && gc && clean;
    std::printf("NETD_SMOKE=%s loop=%d other_ns=%d listed=%d gc=%d left=%zu\n", ok ? "PASS" : "FAIL",
                std::memcmp(got, ping, 4) == 0, elsewhere, listed, gc, after ? after->size() : 99U);
    return ok ? 0 : 1;
}
