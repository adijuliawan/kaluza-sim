// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// GET /v1/events as NDJSON (P1 N8; cli.md): the events after `since` that `keep`
// takes, and with `follow` those that come after, until the client leaves or the
// node stops. Served by a node and by a split run's supervisor alike.

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>

#include "api/http.hpp"
#include "platform/event.hpp"

namespace ksim::api {

/// While following, a blank line goes out after each quiet `beat`, so a client
/// that has left is noticed at once: the write fails and the server thread is
/// free again. Without it a stream to a quiet node held its thread until the next
/// event. The supervisor reconnects to a role every 5 s of silence, so a role
/// quiet for 80 s had all 16 of its threads held this way and answered nothing
/// (KS-PLAT-D14, LW1a). Readers skip blank lines.
void stream_events(const EventRing& ring, std::uint64_t since, const std::function<bool(const Event&)>& keep,
                   bool follow, const std::atomic<bool>& stop, const Server::Write& write,
                   std::chrono::milliseconds beat = std::chrono::seconds(1));

} // namespace ksim::api
