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
//       cucp: {ng_bind: 127.0.0.2}           # P2 Q5: ue_inactivity_s: N (1..7200, default 7200)
//       cuup: {n3_bind: 127.0.0.2}          # N3 (GTP-U 2152); default: the ng_bind address
//       dus: [{id: 1, cells: [{pci: 101, tac: 1, arfcn: 632628}]}]
//   ues:
//     - {group: phones, count: 3, range: "001010000300001", card: {template: ../cards/usim-5g.yaml},
//        nssai: [1, "1-000001"], imeisv_tac: "86000000",    # SST, or SST-SD in hex
//        persona: ../personas/s22plus.yaml}                  # N15, optional
//   secrets: {sealed: ~/.kaluza-sim/cards, kek: ~/.kaluza-sim/secrets/kek}
//   peer: {name: stub}                      # free-form pins for the manifest
//   security: {allow_null: false}            # D1: the bisect switch only
//   watchdog_ms: 250                         # P2 Q7: platform.loop_lag above this; 0 = off
//   farm: {shards: 4}                        # P2 Q7, split only: the UE farm on 4 shards
//   mode: split                              # P2 Q3: aio (default) or split, the roles as processes
//   (in gnbs[0]) split: {f1c: 127.0.10.1, e1: 127.0.20.1, du: 127.0.10.2, cuup: 127.0.10.3,
//                        cuup_e1: 127.0.20.2, streams: 16}
//                                            # split only: the CU-CP's F1-C and E1 listening addresses,
//                                            # the DU's F1-C and F1-U address, the CU-UP's F1-U address
//                                            # and E1 address, the F1-C/E1 outbound streams asked for
//   (in gnbs[0]) peers: {cucp: ocudu, cuup: ocudu}
//                                            # P2 Q4, split only: roles the interop peer runs (ADR 0012);
//                                            # with a peer CU-CP, cucp: may be left out
//   (in a cell) ssb_arfcn: 632640            # P2 Q4: the SSB the MeasurementTimingConfiguration names
//   netd: {socket: /run/ksim/netd.sock, netns: ksim-cucp, cuup_netns: ksim-cuup, parent: ens19, prefix: 24,
//          nodes: true, ues: true, du_netns: ksim-du, mid: true, mid_prefix: 24}
//                                            # P2 Q6, split with node namespaces (kaluza-uesim): each
//                                            # role's namespace gets a ksim-mid leg with its split
//                                            # address (the CU-CP's F1-C and E1, the CU-UP's F1-U and
//                                            # E1, the DU's), and the DU a namespace of its own
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
    std::string card_template;              // the soft card, or one of:
    std::string card_pcsc;                  // P2 Q1: a PC/SC reader (exact name, "#n", or a unique part)
    std::string card_bridge;                // P2 Q1: the card bridge's host:port (ksim-sim serve --pcsc)
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
    std::string du_netns = "ksim-du";       // P2 Q6, split with mid: the DU's namespace (no ipvlan)
    bool mid = false;                       // P2 Q6: each split role's leg on ksim-mid (kaluza-uesim)
    std::uint8_t mid_prefix = 24;
    bool nodes = true;                      // the CU-CP's and CU-UP's namespaces
    bool ues = true;                        // the UEs' namespaces and TUNs
    std::string parent;
    std::uint8_t prefix = 24;
};

/// P2 Q3 (ADR 0011): the shape of a run, and the role a process takes in it.
enum class Mode : std::uint8_t { aio, split };
enum class Role : std::uint8_t { all, cucp, cuup, du, ue };
const char* role_name(Role r) noexcept;
/// "cucp", "cuup", "du", "ue" (or "all"); nullopt for anything else.
std::optional<Role> parse_role(const std::string& s);

/// The split's links (ADR 0011 point 3): on the dev PC everything on 127.0.0.x.
struct SplitConfig {
    Endpoint f1c_listen = Endpoint::v4(127, 0, 10, 1, 38472);   // the CU-CP's F1-C (PPID 62)
    Endpoint e1_listen = Endpoint::v4(127, 0, 20, 1, 38462);    // the CU-CP's E1 (PPID 64)
    Endpoint du = Endpoint::v4(127, 0, 10, 2, 2152);            // the DU's F1-C (port 0) and F1-U address
    Endpoint cuup_f1u = Endpoint::v4(127, 0, 10, 3, 2152);      // the CU-UP's F1-U
    Endpoint cuup_e1 = Endpoint::v4(127, 0, 20, 2, 0);          // the CU-UP's E1 address
    std::uint16_t streams = 16;                                 // F1-C and E1 outbound streams asked for
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
    std::uint32_t ssb_arfcn = 632640;   // P2 Q4: the cell's MeasurementTimingConfiguration
    std::vector<UeGroup> ues;
    std::string sealed_dir;
    std::string kek_file;
    std::map<std::string, std::string> peer;
    bool allow_null = false;
    // P2 Q7: a timer this many ms late raises platform.loop_lag (the watchdog); 0: off.
    std::uint32_t watchdog_ms = 250;
    // P2 Q7 (ADR 0011 point 5): the UE role's farm shards in a split run, 1..8.
    unsigned farm_shards = 1;
    std::uint16_t ng_streams = 2;
    std::uint16_t ue_inactivity_s = 7200;   // P2 Q5: cucp: {ue_inactivity_s: N}, 1..7200
    /// NAS in clear in the Uu capture (KS-CTL-004: only when asked for; ksim
    /// run --plain-nas). Without it the Uu capture holds RRC, and the NAS
    /// inside it as it went over the air.
    bool plain_nas = false;
    NetdConfig netd;
    Mode mode = Mode::aio;
    SplitConfig split;
    // P2 Q4 (ADR 0012): a role the interop peer runs instead of us, split only:
    // "ocudu" or empty (ours). gnbs[0].peers: {cucp: ocudu, cuup: ocudu}.
    std::string peer_cucp;
    std::string peer_cuup;
    // Set at run time, not in the file (P2 Q3): the role this process runs and the
    // DU's KAIR socket (the supervisor's run directory).
    Role role = Role::all;
    std::string kair_socket;
};

/// Reads and checks a topology; the error's text says where and why.
Result<Topology> load_topology(const std::string& file, std::string& why);

/// "~/x" with $HOME, a relative path against `base_dir`, an absolute one as is.
std::string resolve_path(const std::string& p, const std::string& base_dir);

} // namespace ksim::node
