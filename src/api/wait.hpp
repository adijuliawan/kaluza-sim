// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// `wait` (P1 N8; ADR 0009 point 6; cli.md §3): a long poll over the run's
// numbered events. It matches events already recorded by default (since 0, like
// grepping a log), or only those after the request with --new. A command with
// --wait records the sequence number before it starts, so the event it causes
// cannot be missed. A satisfied wait prints the event as KEY=value evidence:
// what kaluza-core's log-grep rows read today (verification.md §6, ask 2).

#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "api/reply.hpp"
#include "platform/event.hpp"

namespace ksim::api {

struct WaitQuery {
    std::vector<std::string> until;   // event names that end the wait with exit 0
    std::vector<std::string> fail;    // event names that end it with exit 1 (CAUSE from the event)
    std::string subject;              // "" for any subject
    std::vector<std::pair<std::string, std::string>> where;   // field equalities
    std::uint64_t since = 0;
    std::chrono::milliseconds timeout{30'000};

    bool matches(const Event& e) const;
};

/// EVENT, SEQ, T_MS, SUBJECT (and UE for a UE's events), then each field with
/// its key upper-cased ("t3512_s" -> T3512_S).
void add_evidence(Reply& r, const Event& e);

/// Waits on `ring` (blocking the calling thread, never a shard).
Reply wait(const EventRing& ring, const WaitQuery& q);

/// "nas.reg.accept,nas.reg.reject" -> its names.
std::vector<std::string> split_names(const std::string& list);

} // namespace ksim::api
