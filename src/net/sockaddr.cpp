// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "net/sockaddr.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>

#include <cstring>

namespace ksim::net {

socklen_t to_sockaddr(const Endpoint& e, sockaddr_storage& out) noexcept {
    std::memset(&out, 0, sizeof out);
    if (e.family == Endpoint::Family::v6) {
        auto* s = reinterpret_cast<sockaddr_in6*>(&out);
        s->sin6_family = AF_INET6;
        s->sin6_port = htons(e.port);
        std::memcpy(&s->sin6_addr, e.addr.data(), 16);
        return sizeof(sockaddr_in6);
    }
    auto* s = reinterpret_cast<sockaddr_in*>(&out);
    s->sin_family = AF_INET;
    s->sin_port = htons(e.port);
    std::memcpy(&s->sin_addr, e.addr.data(), 4);
    return sizeof(sockaddr_in);
}

Endpoint from_sockaddr(const sockaddr* sa, socklen_t len) noexcept {
    Endpoint e;
    if (sa == nullptr) {
        return e;
    }
    if (sa->sa_family == AF_INET && len >= static_cast<socklen_t>(sizeof(sockaddr_in))) {
        sockaddr_in s{};
        std::memcpy(&s, sa, sizeof s);
        e.family = Endpoint::Family::v4;
        std::memcpy(e.addr.data(), &s.sin_addr, 4);
        e.port = ntohs(s.sin_port);
    } else if (sa->sa_family == AF_INET6 && len >= static_cast<socklen_t>(sizeof(sockaddr_in6))) {
        sockaddr_in6 s{};
        std::memcpy(&s, sa, sizeof s);
        e.family = Endpoint::Family::v6;
        std::memcpy(e.addr.data(), &s.sin6_addr, 16);
        e.port = ntohs(s.sin6_port);
    }
    return e;
}

std::vector<std::uint8_t> pack_sockaddrs(const std::vector<Endpoint>& list) {
    std::vector<std::uint8_t> out;
    for (const auto& e : list) {
        sockaddr_storage ss{};
        const socklen_t n = to_sockaddr(e, ss);
        const auto* p = reinterpret_cast<const std::uint8_t*>(&ss);
        out.insert(out.end(), p, p + n);
    }
    return out;
}

} // namespace ksim::net
