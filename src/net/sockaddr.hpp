// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Endpoint <-> sockaddr (P1 N2).

#pragma once

#include <sys/socket.h>

#include <cerrno>
#include <cstdint>
#include <vector>

#include "platform/result.hpp"
#include "platform/transport.hpp"

namespace ksim::net {

socklen_t to_sockaddr(const Endpoint& e, sockaddr_storage& out) noexcept;
Endpoint from_sockaddr(const sockaddr* sa, socklen_t len) noexcept;
/// Addresses packed back to back, as SCTP_SOCKOPT_BINDX_ADD and CONNECTX take them.
std::vector<std::uint8_t> pack_sockaddrs(const std::vector<Endpoint>& list);

inline int family_of(const Endpoint& e) noexcept { return e.family == Endpoint::Family::v6 ? AF_INET6 : AF_INET; }

/// An Errc::io error carrying errno.
inline Error os_error(const char* what) noexcept {
    return make_error(Errc::io, static_cast<std::uint32_t>(errno), what);
}

} // namespace ksim::net
