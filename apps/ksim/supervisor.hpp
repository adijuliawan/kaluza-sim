// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The split run's supervisor (P2 Q3; ADR 0011 point 1). `ksim run` with a
// topology of mode: split starts the roles as processes of their own, in the
// order their links need: the CU-CP (it listens for F1-C and E1), the CU-UP,
// the DU, then the UE farm. Each is this same binary with --role, in its own
// run directory under the supervisor's (<run>/<role>/), with its own control
// socket. The supervisor
//   - merges every role's events into its own ring and events.ndjson, so
//     `ksim-ctl wait` sees the whole run;
//   - serves the control API at <run>/ctl.sock and passes each call to the
//     role that owns it (UE verbs to the farm, gNB verbs to the CU-CP), so
//     ksim-ctl and the gates are unchanged;
//   - links <run>/<capture>.pcapng to the role that writes it, for the gates;
//   - restarts the gNB's roles for `gnb restart` and stops them all for `stop`;
//   - reports a role that exits on its own as an event (run.role.exit).

#pragma once

#include <csignal>
#include <string>

namespace ksim::node {
struct Topology;
}

namespace ksim::app {

struct RoleArgs {
    bool lab = false;
    bool plain_nas = false;
    std::string sealed;
    std::string kek;
};

/// Runs a split run until SIGINT, SIGTERM or `ksim stop`; the exit status of `ksim run`.
int supervise(const node::Topology& t, const std::string& topology_file, const std::string& run_dir, const RoleArgs& a,
              const volatile std::sig_atomic_t& signal);

} // namespace ksim::app
