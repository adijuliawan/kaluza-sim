// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The all-in-one topology (P1 N8; architecture §9): the P1 subset of the
// topology YAML. One gNB with one DU and one cell, one AMF, and UE groups of
// sim-range cards. Relative paths are relative to the topology file; "~/" is
// the user's home. Unknown keys are refused, so a typo is not a silent default.
//
//   plmn: "00101"
//   seed: 42
//   amf: [{addr: 127.0.0.1, port: 38412}]
//   gnbs:
//     - id: {value: 0x1A0, bits: 22}
//       name: ksim-gnb1
//       cucp: {ng_bind: 127.0.0.2}
//       cuup: {n3_bind: 127.0.0.2}          # N3 (GTP-U 2152); default: the ng_bind address
//       dus: [{id: 1, cells: [{pci: 101, tac: 1, arfcn: 632628}]}]
//   ues:
//     - {group: phones, count: 3, range: "001010000300001", card: {template: ../cards/usim-5g.yaml},
//        nssai: [1, "1-000001"], imeisv_tac: "86000000",    # SST, or SST-SD in hex
//        persona: ../personas/s22plus.yaml}                  # N15, optional
//   secrets: {sealed: ~/.kaluza-sim/cards, kek: ~/.kaluza-sim/secrets/kek}
//   peer: {name: stub}                      # free-form pins for the manifest
//   security: {allow_null: false}            # D1: the bisect switch only
//   netd: {socket: /run/ksim/netd.sock, netns: ksim-cucp, cuup_netns: ksim-cuup, parent: ens19, prefix: 24,
//          nodes: true, ues: true}
//                                            # with ksim-netd: NG-C from the CU-CP's own namespace,
//                                            # N3 from the CU-UP's (nodes); each UE in a namespace
//                                            # ksim-ue-<index> with a TUN per session (ues, P1 N11)

#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "platform/result.hpp"
#include "platform/transport.hpp"

namespace ksim::node {

struct Slice {
    std::uint8_t sst = 1;
    std::optional<std::uint32_t> sd;
    friend bool operator==(const Slice&, const Slice&) = default;
};

struct UeGroup {
    std::string group;
    unsigned count = 1;
    std::string first_imsi;
    std::string card_template;
    std::vector<Slice> nssai{Slice{}};   // the requested NSSAI
    std::string imeisv_tac = "86000000";   // 8 digits; the SNR comes from the IMSI
    std::string persona;                    // N15: a persona file (personas/), empty: the generic UE
};

/// The CU-CP's namespace from ksim-netd (ADR 0009 points 3 and 4): ng_bind is
/// the address its ipvlan carries, and NG-C sockets are made inside it.
struct NetdConfig {
    bool enabled = false;
    std::string socket = "/run/ksim/netd.sock";
    std::string netns = "ksim-cucp";
    std::string cuup_netns = "ksim-cuup";   // N3's namespace, with n3_bind on its ipvlan
    bool nodes = true;                      // the CU-CP's and CU-UP's namespaces
    bool ues = true;                        // the UEs' namespaces and TUNs
    std::string parent;
    std::uint8_t prefix = 24;
};

struct Topology {
    std::string file;                      // where it was read from
    std::string mcc;
    std::string mnc;
    std::uint64_t seed = 0;
    Endpoint amf;
    std::uint32_t gnb_id = 0x1A0;
    std::uint8_t gnb_id_bits = 22;
    std::string gnb_name = "ksim-gnb1";
    Endpoint ng_bind;                      // port 0
    Endpoint n3_bind;                      // the CU-UP's N3 address, port 2152
    std::uint64_t du_id = 1;
    std::uint16_t pci = 101;
    std::uint32_t tac = 1;
    std::uint32_t arfcn = 632628;
    std::vector<UeGroup> ues;
    std::string sealed_dir;
    std::string kek_file;
    std::map<std::string, std::string> peer;
    bool allow_null = false;
    std::uint16_t ng_streams = 2;
    /// NAS in clear in the Uu capture (KS-CTL-004: only when asked for; ksim
    /// run --plain-nas). Without it the Uu capture holds RRC, and the NAS
    /// inside it as it went over the air.
    bool plain_nas = false;
    NetdConfig netd;
};

/// Reads and checks a topology; the error's text says where and why.
Result<Topology> load_topology(const std::string& file, std::string& why);

/// "~/x" with $HOME, a relative path against `base_dir`, an absolute one as is.
std::string resolve_path(const std::string& p, const std::string& base_dir);

} // namespace ksim::node
