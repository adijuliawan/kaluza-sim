# ADR 0012: OCUDU as P2's interop peer

- **Status:** accepted, 2026-10-15 (user: the venue and the namespaces, decision D4; the pin and the lab conditions agreed with kaluza-core-df)
- **Context:**
  - P2's exit is the OCUDU F1/E1 interop rows: our DU with OCUDU's `ocucp` and `ocuup` (ADR 0002, `roadmap.md`). E1 is wanted in both directions (`verification.md` §3).
  - OCUDU is BSD (the srsRAN Project renamed) and its ASN.1 is Rel-18 (F1AP v18.8.0, E1AP v18.5.0, NGAP v18.8.0).
  - The lab's tree `ran/ocudu-fork` is at `d9d2263f4d`. It belongs to the lab and kaluza-core's B220 cell; its build directory holds only `gnb`.
  - The dev PC carries the real AMF at 172.30.30.1:38412, so a peer config there could reach the lab.
  - A code survey on 2026-10-15 found two defects in our code that OCUDU refuses: our DU's MeasurementTimingConfiguration is empty (OCUDU's CU-CP rejects the F1 Setup), and our E1 Bearer Context Setup sets ActivityNotificationLevel "ue" without the UE Inactivity Timer that TS 37.483 makes conditional on it (OCUDU's CU-UP rejects it).
- **Decision:**
  1. **The pin:** `d9d2263f4d`, recorded in every run manifest with the binaries' sha256.
  2. **Our own build:** `tools/ocudu-peer.sh build` exports that commit with `git archive` (read-only on the fork) into `~/kaluza-sim-peers/ocudu-d9d2263f4d/` and builds only `ocucp` and `ocuup` there. The build is x86-64-v3 with no ISA auto-detect, so it runs on the VM's Zen 3. Nothing is ever built in `ran/ocudu-fork`.
  3. **The combinations:**

     | Combo | UEs + DU | CU-CP | CU-UP | What it proves |
     |---|---|---|---|---|
     | C2 | ours | ours | ours | the split itself |
     | C3 | ours | OCUDU | OCUDU | F1-C and F1-U interop (the exit) |
     | C4 | ours | ours | OCUDU | E1 with OCUDU as CU-UP |
     | C5 | ours | OCUDU | ours | E1 with OCUDU as CU-CP |

  4. **Where it runs (D4):**
     - **The dev PC:** every combination, on 127.0.0.x only, against our scripted core, and C3 against the Open5GS rig over vmnet8. Never while a B220 cell runs.
     - **kaluza-uesim:** C3 against kaluza-core in an agreed window: `ocucp` at 172.30.30.36 (N2 to .1:38412) and `ocuup` at .37 (N3 to .2), in our ipvlan namespaces, started by `ksim-netd`'s `exec` as amadeus. kaluza-core-df checked that the AMF needs no change and that .36/.37 are V-UPF neighbours.
  5. **Peer configs** are written from templates under `topologies/peers/ocudu/`: TAC 1 for 001/01, our gNB-ID range (0x1A1/22 and up), and the security, inactivity and `sctp_nodelay` settings. **Our dev-PC guard applies to them:** an AMF address in 172.30.0.0/16 is refused unless the script runs on kaluza-uesim with `--lab`. Peers are stopped with `pkill -x`, and `stop` checks that none is left.
     - *Amended 2026-10-16 (P2 Q4):* `stop` matches the processes by our build's path, not by name, so no other OCUDU on the host is touched, and it stops the CU-UP before the CU-CP (a CU-UP whose CU-CP went first retries E1 Setup, fails it fatally and writes no captures). No peer starts while a `gnb` or `odu` process runs.
     - *Amended 2026-10-16:* on the dev PC, `gates/run.sh` starts the peers that a split topology's gNB names (`peers: {cucp: ocudu, cuup: ocudu}`): the CU-CP, then the CU-UP once the CU-CP listens for E1, then `ksim`, which runs only our roles. The peer writes into `<run>-peer`, which becomes `<run>/peer` at the end (ksim wants its run directory new), owner-only, with the PIN file.
     - *Amended 2026-10-16:* the peer's own NGAP and E1AP captures hold K_gNB and the UP keys in clear, which ours never do. `tools/peer_redact.py` zeroes them after the run (pycrate; a PDU it cannot read is zeroed whole), or the two captures are removed when the oracle venv is missing, so the canary's zero holds over the peer's files too.
  6. **The release cap:** towards a peer with `peer_release: 18`, the F1AP, E1AP and NGAP builders leave out Rel-19-only IEs, honouring criticality (`architecture.md` §4.1).
     - *Amended 2026-10-16 (P2 Q4):* every IE and procedure ID our builders use exists in Rel-18 (checked against OCUDU's ID tables: none is newer than Rel-16), so there is nothing to leave out yet. `tools/guards/check_peer_release.py` keeps it so: a constant above Rel-18's highest ID (F1AP 919, E1AP 219, NGAP 443) fails CI until its builder leaves it out towards a Rel-18 peer and the guard lists how. The `peer_release` setting comes with the first such IE.
  7. **Triage:** each difference is judged against the spec text. It becomes a sim -D row (fixed in our code), an entry in `gates/allow/ocudu.tsv` (row, reason, clause, OCUDU source reference), or an -S row when the spec is ambiguous. OCUDU defects are recorded as leads for the user and never fixed here. OCUDU is a peer and a BSD reference, never an oracle (`verification.md` §5). The record is `docs/interop/ocudu.md` (from P2 Q4): what each run showed, the sim defects fixed, the peer's spec-permitted behaviour we accommodate, and the leads.
     - *Amended 2026-10-16 (P2 Q5):* `gates/allow/ocudu.tsv` has a modes column (an entry holds in the interop modes it lists), and a gate may forbid the lookup when a row fails for a cause other than the lead's. The gates score a p2 row only in the modes `gates/rows/p2.tsv` gives it. In C4, `gates/run.sh` starts OCUDU's CU-UP after `ksim` and stops it before.
- **Consequences:**
  - OCUDU runs are recorded evidence (rows, run manifests), not CI steps: CI cannot assume the peer build exists. An opt-in hook runs C3–C5 when it does (`tools/ci.d/58-ocudu.sh` from P2 Q4: SKIP without the build).
  - OCUDU has no control API of ours. Rows that need a CU-CP verb use OCUDU's own trigger (its inactivity timer for the release) or are marked not applicable for that mode.
  - Any copy of OCUDU code keeps its BSD header and a NOTICE entry (ADR 0004).
