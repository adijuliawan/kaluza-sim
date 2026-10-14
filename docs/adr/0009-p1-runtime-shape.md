# ADR 0009: P1's runtime shape

- **Status:** accepted, 2026-10-15 (user: points 2 and 3 by their answers; the rest with the P1 plan)
- **Context:** P1 builds the first running simulator: the card, the UE's NAS, an all-in-one gNB and the scenarios against two real cores. The design documents leave several things open or contradict each other:
  - **AS security:** the roadmap allows NULL AS security only in P1, but TS 33.501 §5.3.3 and Annex D.1 forbid NIA0 on SRBs outside unauthenticated emergency sessions. KS-SEC-T2 also wants the AS half of the key chain (K_gNB from the UL NAS COUNT) proven against two cores in P1.
  - **Privilege:** netns, TUN and ipvlan need CAP_NET_ADMIN, while `ksim` parses every byte the network sends. AppArmor blocks unprivileged user namespaces on the dev PC.
  - **Sockets:** `lab.md` puts each RAN node in its own ipvlan netns, while the all-in-one process holds N2 (.30) and N3 (.31) at once.
  - **Events and testing:** the roadmap lists events under P3, but the gate contract (`wait` printing evidence) and `verification.md` §1 (a sim mutant per scenario row) need them in P1.
  - **Paging:** paging is in P1's exit, but paging DRX is P3.
  - **Lab safety:** the real AMF listens on the dev PC itself (172.30.30.1:38412), and the dev PC must carry no lab traffic.
- **Decision:**
  1. **The air link:** KAIR v1 frames, encoded, over in-memory byte channels (`platform/memlink`) between the UE and the DU. The P1 subset is:
     - CELL_ANNOUNCE, SUBSCRIBE, BCH, SI, PCCH;
     - PRACH, RAR, MSG3, MSG4;
     - DL_SDU, UL_SDU, KEEPALIVE.
     P2's split then changes only the transport.
  2. **AS security:** real 128-NIA2 and 128-NEA2 on SRBs and DRBs from P1 on (the user, 2026-10-15). NULL algorithms exist only as a topology switch for bisecting a key mismatch, and never in an exit run. UP integrity "required" is honoured with NIA2; "preferred" is answered as off.
  3. **Privilege:** a small root helper, `ksim-netd` (the user, 2026-10-15). It is a systemd unit behind `/run/ksim/netd.sock` with an SO_PEERCRED uid check. It creates and removes netns, ipvlan links, addresses, routes and sysctls, and hands back TUN fds and bound sockets over SCM_RIGHTS.
     - **Allowlist:** `ksim-*` names; addresses 172.30.30.30–.39; parent `ens19` on kaluza-uesim only. On the dev PC no parent link is allowed at all.
     - `ksim` itself stays unprivileged. Unit tests use a fake netd.
  4. **N2 and N3 in one process:** netd opens the SCTP socket inside `ksim-<run>-cucp` (bound to .30) and the UDP 2152 socket inside `ksim-<run>-cuup` (bound to .31), and passes both descriptors. A socket keeps its netns, so `ksim` never calls `setns`, and P2's split processes use the same calls.
  5. **Time:** an `Executor` interface (post, timers, now), implemented by the real-time `Shard` and by a single-threaded virtual-time `SimLoop`. Procedure tests run in virtual time against a scripted core over memory. The `ksim` binary always uses real sockets for NG-C and NG-U, as `architecture.md` §2.1 says.
  6. **Events, `wait` and mutants move to P1:**
     - every event name is registered in `src/api/events.tsv`;
     - `wait` is a long poll over the event sequence;
     - `KSIM_MUTANT("name")` switches are compiled in only with `KSIM_MUTATIONS=ON`, listed in `tests/mutants.tsv`;
     - every P1 row has a mutant that fails exactly that row.
     Metrics and fault injection stay in P3.
  7. **The control API:** HTTP/1.1 and JSON on a UNIX socket in the run directory, with TCP 127.0.0.1:9400 optional.
     - Libraries: cpp-httplib (MIT, one header, vendored), nlohmann-json, CLI11, yaml-cpp.
     - A verb with `--wait` registers its waiter before it starts. A satisfied wait prints the event's evidence as KEY=value lines.
  8. **The scripted core stub** (`tests/corestub`, and `apps/ksim-corestub` on loopback): the AMF's NAS and NGAP sides, the home functions, an SMF, an SMSF and a UPF with a DN reflector.
     - It uses our own codecs and crypto. Every value it expects comes from spec text and KAT-backed derivations, never from kaluza-core.
     - It judges procedures, not encodings. Encodings are judged by tshark and pycrate on every run's pcaps, and by the two real cores.
  9. **Scenarios** are POSIX sh gates driven by `ksim-ctl`, in kaluza-core's row format, scored from the sim's own evidence: events, `ksim-ctl` output and the run's pcaps.
     - The row set is frozen in `gates/rows/p1.tsv`. Its row text is kaluza-core's, verbatim, for the parity contract.
     - `tools/p1_exit.py` scores each core: the stub, Open5GS (ADR 0010) and kaluza-core. Scenario YAML timelines wait for P3.
  10. **Paging** in P1 is stamped with its PF/PO but not enforced; DRX enforcement stays P3 (abstraction ledger A-11). P1 has no cell selection: a UE camps on the configured cell (A-12).
  11. **The dev-PC guard:** `ksim` refuses any peer in 172.30.0.0/16 unless it runs with `--lab` on host `kaluza-uesim`, and refuses to start while an OCUDU or B220 cell process runs. The stub binds 127.0.0.x only.
- **Consequences:**
  - The roadmap's "NULL AS security is allowed only in this milestone" no longer applies; P2 adds NEA1/NIA1 and the UP security policy.
  - netd is a root process that parses requests. It keeps a minimal operation set, an allowlist and a fuzz target (`fuzz_netd_req`).
  - Privileged tests run only as opt-in CI hooks (`KSIM_CI_PRIV=1`, `sudo -n`); otherwise they SKIP.
  - Rows that only a core-side change can trigger (network-requested release or modification, configuration update, network deregistration) are scored on the stub and Open5GS only in P1. The user granted kaluza-sim no trigger on kaluza-core (2026-10-15). Their kaluza-core parity comes under the gate contract, where the core's gate makes the network-side call.
