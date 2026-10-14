// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Named network namespaces as iproute2 keeps them (P1 N9; ADR 0009 point 3):
// a namespace is kept alive by a bind mount of its nsfs file on
// /run/netns/<name>, so `ip netns` sees ours and theirs alike. Creating,
// joining and removing one needs CAP_SYS_ADMIN: only ksim-netd calls these.
// Work inside a namespace runs on a short-lived thread that joins it, so the
// caller's thread never changes namespace.

#pragma once

#include <functional>
#include <string>
#include <vector>

#include "platform/reactor.hpp"
#include "platform/result.hpp"

namespace ksim::net::netns {

inline constexpr const char* kDir = "/run/netns";

/// A new namespace named `name` (refused when it exists).
Result<void> add(const std::string& name);
/// Unmounts and removes it; the namespace goes once nothing else holds it.
Result<void> del(const std::string& name);
/// A descriptor of the namespace (O_RDONLY|O_CLOEXEC).
Result<Fd> open(const std::string& name);
/// The names under /run/netns.
std::vector<std::string> list();
/// Runs `fn` on a thread that joined the namespace `ns_fd`, and returns its result.
Result<void> run_in(int ns_fd, const std::function<Result<void>()>& fn);

} // namespace ksim::net::netns
