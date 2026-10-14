// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The dev-PC guard (P1 N8; ADR 0009 point 11, ADR 0010): the real AMF listens
// on this dev PC (172.30.30.1:38412), and the dev PC must carry no lab traffic.
// So ksim refuses any peer or bind address in 172.30.0.0/16 unless it runs with
// --lab on the host kaluza-uesim, and refuses to start while an OCUDU or B220
// cell process (gnb, odu) runs. 192.168.134.0/24 (vmnet8, host-only, the
// Open5GS rig) and loopback are allowed anywhere.

#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "platform/transport.hpp"

namespace ksim::node {

struct GuardInput {
    std::vector<Endpoint> addresses;   // the AMF, the NG-C bind, …
    bool lab = false;                  // --lab
    std::string host;                  // this host's name
    std::vector<std::string> processes;   // command names running on this host
};

/// "" when the run may start, else why not.
std::string check_guard(const GuardInput& in);

/// This host's name and the command names of its processes (/proc/*/comm).
std::string host_name();
std::vector<std::string> process_names();

} // namespace ksim::node
