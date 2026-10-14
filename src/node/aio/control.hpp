// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The all-in-one node's control routes (P1 N8; cli.md, src/api/openapi.yaml):
// the v0 verbs. Group selectors are resolved by ksim-ctl through /v1/ues; a
// UE route takes one UE ("imsi-…" or its farm index).

#pragma once

#include <atomic>

#include "api/http.hpp"
#include "node/aio/aio.hpp"

namespace ksim::node {

/// Binds the routes; POST /v1/stop sets `stop`.
void bind_control(api::Server& server, AllInOne& aio, std::atomic<bool>& stop);

} // namespace ksim::node
