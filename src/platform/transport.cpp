// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "platform/transport.hpp"

#include <arpa/inet.h>

#include <charconv>
#include <cstring>

namespace ksim {

Result<Endpoint> Endpoint::parse(std::string_view host, std::uint16_t port) {
    if (host.size() >= INET6_ADDRSTRLEN) {
        return make_error(Errc::invalid_argument, 0, "endpoint: the address is too long");
    }
    char buf[INET6_ADDRSTRLEN] = {};
    std::memcpy(buf, host.data(), host.size());
    Endpoint e;
    e.port = port;
    if (inet_pton(AF_INET, buf, e.addr.data()) == 1) {
        e.family = Family::v4;
        return e;
    }
    if (inet_pton(AF_INET6, buf, e.addr.data()) == 1) {
        e.family = Family::v6;
        return e;
    }
    return make_error(Errc::invalid_argument, 0, "endpoint: not a numeric IPv4 or IPv6 address");
}

Result<Endpoint> Endpoint::parse(std::string_view host_port) {
    std::string_view host;
    std::string_view port;
    if (!host_port.empty() && host_port.front() == '[') {
        const auto close = host_port.find(']');
        if (close == std::string_view::npos || close + 1 >= host_port.size() || host_port[close + 1] != ':') {
            return make_error(Errc::invalid_argument, 0, "endpoint: expected [address]:port");
        }
        host = host_port.substr(1, close - 1);
        port = host_port.substr(close + 2);
    } else {
        const auto colon = host_port.rfind(':');
        if (colon == std::string_view::npos || host_port.find(':') != colon) {
            return make_error(Errc::invalid_argument, 0, "endpoint: expected address:port");
        }
        host = host_port.substr(0, colon);
        port = host_port.substr(colon + 1);
    }
    std::uint16_t p = 0;
    const auto [ptr, ec] = std::from_chars(port.data(), port.data() + port.size(), p);
    if (ec != std::errc{} || ptr != port.data() + port.size() || port.empty()) {
        return make_error(Errc::invalid_argument, 0, "endpoint: the port is not 0..65535");
    }
    return parse(host, p);
}

Endpoint Endpoint::v4(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d, std::uint16_t port) noexcept {
    Endpoint e;
    e.family = Family::v4;
    e.addr[0] = a;
    e.addr[1] = b;
    e.addr[2] = c;
    e.addr[3] = d;
    e.port = port;
    return e;
}

std::string Endpoint::host() const {
    char buf[INET6_ADDRSTRLEN] = {};
    if (family == Family::v4) {
        inet_ntop(AF_INET, addr.data(), buf, sizeof buf);
    } else if (family == Family::v6) {
        inet_ntop(AF_INET6, addr.data(), buf, sizeof buf);
    } else {
        return "-";
    }
    return buf;
}

std::string Endpoint::to_string() const {
    if (family == Family::v6) {
        return "[" + host() + "]:" + std::to_string(port);
    }
    return host() + ":" + std::to_string(port);
}

bool Endpoint::in(const Endpoint& prefix, unsigned bits) const noexcept {
    if (family != prefix.family || family == Family::none) {
        return false;
    }
    const unsigned width = family == Family::v4 ? 32 : 128;
    if (bits > width) {
        return false;
    }
    for (unsigned i = 0; i < bits; ++i) {
        const unsigned byte = i / 8;
        const unsigned mask = 0x80U >> (i % 8);
        if ((addr[byte] & mask) != (prefix.addr[byte] & mask)) {
            return false;
        }
    }
    return true;
}

const char* link_event_name(LinkEvent e) noexcept {
    switch (e) {
    case LinkEvent::up:
        return "up";
    case LinkEvent::restart:
        return "restart";
    case LinkEvent::shutdown:
        return "shutdown";
    case LinkEvent::lost:
        return "lost";
    case LinkEvent::refused:
        return "refused";
    }
    return "?";
}

} // namespace ksim
