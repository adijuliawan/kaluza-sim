# ADR 0011: P2's runtime shape

- **Status:** accepted, 2026-10-15 (user, with the P2 plan; decisions D1–D8 by their answers)
- **Context:** P2 splits the all-in-one gNB into separate processes over real F1-C, F1-U and E1, brings 100 UEs, and measures the performance targets of `requirements.md` §3.5 on kaluza-uesim. The P1 design leaves several things open:
  - how the roles start and how the gates keep one entry point;
  - which transport KAIR takes between processes;
  - F1/E1 between namespaces on the dev PC, where a veth flaps vmnet8 for both VMware guests (kaluza-core P-64);
  - ADR 0009 point 6 left metrics and the loop-lag watchdog for P3, but the 100-UE and performance rows need them;
  - every N3 and F1-U packet is written to pcapng, which would fill the VM's 11 GB disk in a throughput run.
- **Decision:**
  1. **One entry point.** `ksim run -c <topology>` stays the only way to start a run. The topology's `mode: aio | split` picks the shape. In split mode `ksim` is a supervisor:
     - it asks netd for the namespaces (and, on kaluza-uesim, `ksim-mid`);
     - it starts each role as this program with `--role` (`ksim-cucp`, `ksim-cuup`, `ksim-du` and `ksim-ue` are the same program with the role fixed). Each role asks netd for its own sockets in its namespace, as P1's node does (ADR 0009 point 4), so no role calls `setns`; on the dev PC the roles make their own sockets on 127.0.0.x;
     - each role has its own control socket `<run>/<node>.sock`, log and pcaps under `<run>/<node>/`;
     - the supervisor merges every role's events into its own `wait` ring and proxies `/v1/<node>/…`, so `ksim-ctl` and the gates are unchanged;
     - one merged manifest; a role's exit becomes a failure event.

     The all-in-one node and each role process run the same node code: a node hosts a set of roles, and each link between two roles is memlink when both are in the process and a real socket when one is not (tenet 1), so the two shapes cannot drift. The role apps are thin mains over it.
  2. **KAIR between processes:** UNIX SOCK_SEQPACKET on path sockets in the run directory, which cross namespaces. The DU listens and keeps a CELL_ANNOUNCE/SUBSCRIBE registry; each farm shard connects and subscribes; broadcast and paging go once per subscribed shard; the farm demuxes by `radio_id`. SFN runs on a shared CLOCK_REALTIME epoch. UDP stays for multi-host use later.
     - *Amended 2026-10-17 (P3 R0):* not built in P2. The DU never sends CELL_ANNOUNCE (with one DU per run every shard subscribes to it), and its SFN runs from the monotonic clock (`du.cpp`). P3 R2 builds both, with several DUs (rows ksim-p3.cell.announce and ksim-p3.cell.sfn-epoch; ADR 0013 point 2). *Built in P3 R2* (KS-RRC-B10).
  3. **Where the roles live:**
     - **kaluza-uesim:** a namespace per RAN role. The CU-CP holds .30 (N2) and the CU-UP .31 (N3) as ipvlan children of `ens19`, as in P1. F1-C, F1-U and E1 run on `ksim-mid`, an uplink-free bridge (10.250.0.0/24, never `ens19`) with a veth leg into each role's namespace. The DU has a mid leg only. The farm runs in the root namespace; each UE keeps its own namespace and TUNs.
     - **The dev PC:** every role runs on 127.0.0.x in the root namespace, unprivileged. No bridge and no veth (P-64).
  4. **netd v3** adds, behind the same allowlist and uid check:
     - on kaluza-uesim only: `ksim-mid` and its veth legs; `exec` inside a node namespace as the caller, for peer processes (ADR 0012);
     - on both hosts: a DN namespace with a TUN for the scripted core's UPF (the throughput harness);
     - gc of bridges, veths and DN namespaces.
     - *As built (P2 Q6):* ops `bridge`, `veth`, `setup_dn`, `dn_tun`, enabled by `--mid <net>` (refused off kaluza-uesim, as `--parent`) and `--dn <net>` (both hosts); `exec` goes to any namespace netd made, still as the caller and never root. The split roles on kaluza-uesim each set up their own namespace and mid leg (topology `netd: {mid: true}`); a split topology with node namespaces but no `mid` is refused, so on the dev PC the roles stay in the root namespace and only the UEs get namespaces.
  5. **Shards:** the UE farm runs several shards, with UEs pinned by index and one KAIR socket per shard. The CU-CP and the DU stay on one shard. The ID layout `[shard:4][gen:4][index:24]` is kept, and the SCTP I/O thread waits until a measurement asks for it.
     - *As built (P2 Q7):* topology `farm: {shards: N}` (1..8, split runs only, no pcsc: or bridge: cards). UE i lives on lane i mod N with its lane's KAIR connection and, with netd, its lane's own netd connection; the control API posts a UE's verbs to its lane (`call_ue`). 100 UEs on 4 lanes register with a session each in under a second on the dev PC, with no TSan report.
  6. **Moved into P2 from ADR 0009 point 6:**
     - metrics v0 on `/metrics` (Prometheus text): procedure counters with causes, per-QFI bytes, per-hop latency histograms, RSS and threads. Part of KS-CTL-005; the TS 28.552 labels come later;
     - the loop-lag watchdog: a `platform.loop_lag` event above a threshold, and gates ABORT with exit 7 (`cli.md` §2).

     Fault injection stays in P3.
  7. **User-plane capture** is `full | headers | off` per topology. Gates use full; performance runs use headers, so a 30-minute run stays small.
     - *As built (P2 Q8):* `capture: {user_plane: full|headers|off}`.
       - headers keeps each GTP-U frame's first 128 octets with its length on the wire, and flushes every 1024 frames.
       - full flushes as it writes, since the gates read the file during the run.
       - The manifest records the policy (KS-PLAT-B51).
     - The CU-CP settings this ADR lists are topology settings as of Q8: `cucp: {nea: [..], nia: [..]}` (KS-SEC-B4) and `cucp: {t_reordering_ms: N}` (KS-RRC-B5). The UP policy for "preferred" and the flow-to-DRB mapping follow in Q9 and Q10.
     - *As built (P2 Q9):* `cucp: {up_policy: {preferred_integrity, preferred_confidentiality, absent_integrity, absent_confidentiality, integrity_possible}}` (KS-NGAP-B8).
       - The defaults: "preferred" is performed, and with no indication integrity is off and ciphering on. These are OCUDU's choices too.
       - `ksim-ctl gnb <name> up-policy` changes the policy during a run.
     - *As built (P2 Q10):* `cucp: {drb_map: per-5qi|per-session}` (KS-RRC-B6), default per-5qi.
       - per-5qi gives each 5QI of a session its own DRB, the default DRB holding the first flow's, as OCUDU's CU-CP does.
       - per-session puts every flow on one DRB, P1's way.
       - A modification keeps the mapping, and a DRB left with no flow is removed.
     - *As built (P2 Q11):* `cucp: {gbr_budget_kbps: N}` (KS-RRC-B7), default 100000, is the cell's GBR budget (ledger A-07).
       - A GBR flow always gets its own DRB, and one over the budget is refused.
       - `ksim-ctl gnb <name> gbr-budget` changes it during a run, and notification control tells the AMF.
  8. **Topology settings,** each recorded as a -B row when it lands: the CU-CP's NEA/NIA preference lists, its UP security policy for "preferred" and for an absent Security Indication, its QoS-flow-to-DRB mapping, and t-Reordering.
  9. **Throughput** is measured only on the dev PC or inside kaluza-uesim against the scripted core on 127.0.0.x, never across the lab (kaluza-core-df, 2026-10-15). The numbers are the sim's own processing over an ideal link with zero delay; the scripted UPF's CPU is reported apart.
- **Consequences:**
  - Every P1 gate runs in both shapes, aio and split, in CI.
  - netd grows. Its new operations sit behind the allowlist; the bridge and veths are refused on the dev PC; `exec` runs as the caller's uid; `fuzz_netd_req` covers the new requests.
  - Rows that need a CU-CP verb cannot run when the CU-CP is OCUDU's (ADR 0012); `gates/rows/p2.tsv` marks them per mode.
