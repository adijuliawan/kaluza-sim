# Verification strategy and kaluza-core integration

**The principle:** kaluza-sim is useful only if it is independent and itself verified. Its expected values come from:
- the spec text;
- independent oracles (decoders that check our bytes);
- independent peers (implementations that run the other end).

They never come from kaluza-core ([ADR 0005](adr/0005-independence-from-kaluza-core.md)). A difference with a peer is a lead; the spec text decides.

## 1. Tiers

| Tier | What | Where it runs |
|---|---|---|
| T1 | Unit tests and golden vectors: codecs, entities, KATs, the card OS | Dev box; every commit |
| T1b | Property and fuzz tests: round trips, "no input may crash a process", FSM tables against TS 24.501 §5.1.3 and §6.1.3 | Dev box; nightly |
| T2 | Interop with independent peers (§3) | Dev box and lab |
| T3 | Lab scenarios against kaluza-core on k3s | kaluza-uesim (VM 105, 172.30.30.30–.39; [`lab.md`](lab.md)), in agreed windows |
| T4 | Gate parity with the UERANSIM-based gates (§4) | kaluza-uesim, in a kaluza-core session's set |
| T5 | Behaviour compared with real-device captures (kaluza-ue `*_l3.pcap`, the core's `ngap.pcap`) | Dev box |

**Every scenario row has a sim mutant** (a `KSIM_MUTATIONS=ON` switch) that must fail exactly that row, the same discipline as kaluza-core's gate controls.

## 2. Oracles (they decode our bytes; never kaluza-core)

| Subject | Oracle |
|---|---|
| NGAP, RRC, F1AP, E1AP, XnAP, NAS, GTP-U, NR-U | **tshark 4.6.4** (feed pcaps on stdin; AppArmor blocks paths under `~/Development`) and **pycrate** (in a venv), both directions. Every PDU type in the v1 procedure list must round-trip and decode field by field |
| RRC (extra) | asn1c-JER versus tshark leaf comparison, as `/home/amadeus/Development/ran/kaluza-ue/tools/rrc-oracle.py` does |
| Card | **pySim-shell** over vpcd reads every EF of the soft card; real sysmoISIM cards answer the same APDU sequences; `pySim-trace.py gsmtap-udp` decodes our traces. As built (P1 N14): `tools/ci.d/55-pysim.sh` runs `tests/oracles/pysim_shell.py` in full mode. It prints PYSIM_EF_READ=n/n (each EF read and decoded, or refused with 6982 as its ARR says), PYSIM_TRACE_READS=n/n with no unknown file, tshark on the trace, the test K absent, and an fsdump imported into an image that validates |
| Crypto | KATs: TS 35.208 (MILENAGE), 35.233 (TUAK), 35.236 (MILENAGE-256), 33.501 C.4 (SUCI), 33.401 Annex C (AES NEA2/NIA2), the SAGE documents (SNOW 3G), 35.223 (ZUC) |
| Key chain | A separate, minimal Python oracle written from TS 33.501 Annex A and 33.220 B.2 (FC values checked against j70). Final proof: SMC and handovers succeed against both kaluza-core and Open5GS |

**Vectors of external origin are allowed**, with their origin recorded per vector:
- 3GPP/SAGE KATs;
- captures from phones, modems and OCUDU, including those in `/home/amadeus/Development/kaluza-core/testkit/kaluza-testkit-vectors`.

**Vectors produced by kaluza-core's own encoders are not allowed.**

## 3. Interop matrix

| Sim side | Peer | What it shows | From |
|---|---|---|---|
| UE + RAN | kaluza-core (lab, k3s) | The target | P1 |
| UE + RAN | **Open5GS fork core** (a full 001/01 core on the rig VM `amadeus-open5gs`, driven from the dev PC over vmnet8; [ADR 0010](adr/0010-open5gs-control-core.md)) | A second core. It tells sim bugs from core bugs and stops the sim being tuned to kaluza-core. Differences are triaged against the spec; Open5GS's known deviations go on an allow-list | P1 exit |
| UE + RAN | free5gc (`/home/amadeus/Development/free5gc`) | A third opinion where the first two disagree | optional |
| DU with sim UEs | OCUDU `ocucp` + `ocuup` (fork `d9d2263f4d` or later) | F1-C/F1-U interop. OCUDU's production CU-CP then talks NGAP to kaluza-core for up to 100 soft UEs | P2 |
| CU-CP ↔ CU-UP | OCUDU CU-UP or CU-CP | E1 interop | P2 |
| CU-CP | OCUDU CU-CP serving a sim DU | Xn handover against an independent implementation | P3 |
| UE | kaluza-ue `*_l3.pcap`, the core's `ngap.pcap` | Message sequences and IE presence compared with real devices | P1 onward |
| E2 agents (Ph2) | OSC RIC (`/home/amadeus/Development/ran/oran-sc-ric`), FlexRIC (`/home/amadeus/Development/ran/flexric-build`) | KPM/RC, with E2SM versions pinned | Ph2 |

Peers are pinned per row: the OCUDU commit, the Open5GS fork commit, the kaluza-core tag. The pins go in the run manifest.

### 3.1 P1's exit accounting

P1's rows are `gates/rows/p1.tsv` ([ADR 0009](adr/0009-p1-runtime-shape.md)): kaluza-core's row text for the gates `kaluza-amf-ueransim`, `kaluza-smf-ueransim` and `kaluza-smsf`, verbatim, plus kaluza-sim's own `ksim-p1.*` rows. A row is in P1 when the sim's own evidence decides it (events, `ksim-ctl` output, the run's pcaps); rows only the core's state can decide wait for gate parity (P4). Each row names the cores it runs on. `tools/p1_exit.py` reads the newest `rows.tsv` of each core and requires:

| Core | Requirement |
|---|---|
| The scripted stub | every row PASS; a TUN row the inject-mode stub run SKIPs counts when it PASSes in netns mode on a real core |
| Open5GS | every row PASS, or ALLOWED by an entry of `gates/allow/open5gs.tsv` (the SMS rows: the fork has no SMS over NAS); nothing unaccounted |
| kaluza-core | every row PASS, or accounted for by a KF finding acknowledged by the core session |

It also requires every mutant killed, every readable EF read by pySim-shell, no malformed frame in the run pcaps, no canary hit, and at least one KF handed over or the user's explicit acceptance of none. Rows only a core-side change can trigger (network-requested release or modification, configuration update, network deregistration) run on the stub and Open5GS: kaluza-sim has no trigger on kaluza-core in P1 (the user, 2026-10-15).

**As built (P1 N16):**
- **Mutants:** `tools/mutants.sh` runs each mutant of `tests/mutants.tsv` against the gate that scores its row, with `ksim` from the mutants preset under `KSIM_MUTANT` and the stub from the dev preset. A mutant is killed when its own row FAILs. Rows that depend on the mutated step fail with it and are listed, not counted against it (KS-PLAT-B30): the plan's "exactly one row failing" is read that way.
- **The exit check:** `tools/p1_exit.sh` takes each row's newest result per real core across its runs (`runs/open5gs-*`, `runs/lab/kaluza-*`). It reads the component run's `checks.txt`, `build/mutants-run/last` and `build/pysim/last`, and prints `P1_EXIT=PASS|PENDING|FAIL`.
- **CI:** hooks 68 (mutants) and 90 (`--stub-only`) run in `ci full`.

### 3.2 P2's exit accounting

P2's rows are `gates/rows/p2.tsv` ([ADR 0011](adr/0011-p2-runtime-shape.md), [ADR 0012](adr/0012-ocudu-interop-peer.md)): the P1 row set again, scored per **mode**, plus kaluza-sim's own `ksim-p2.*` rows (interop, AS security, the UP security policy, QoS, cards, scale, performance). The modes are `aio`, `split` (C2: our own DU, CU-CP and CU-UP over real F1/E1) and the OCUDU combinations `C3` (OCUDU's CU-CP and CU-UP), `C4` (OCUDU's CU-UP) and `C5` (OCUDU's CU-CP). `tools/p2_exit.py` keeps p1_exit's newest-result-per-row rule, keyed by (core, mode), and requires:

| What | Requirement |
|---|---|
| The P1 rows in split mode | stub: every row PASS (CI); Open5GS: PASS or ALLOWED; kaluza-core: PASS or a KF |
| OCUDU | every C3 row PASS or ALLOWED by `gates/allow/ocudu.tsv` on the stub and on kaluza-core (window LW2); every C4 and C5 row PASS or ALLOWED on the stub |
| Performance | each `requirements.md` §3.5 target met on kaluza-uesim (window LW3), or the user's recorded decision |
| The rest | every P2 stub row PASS; the 100-UE rows; the PC/SC rows (vpcd in CI, the real card); every mutant killed; no malformed frame; no canary hit; no exit run with NULL AS algorithms |

Rows the cores cannot serve are scored where they can be (the user, 2026-10-15, and kaluza-core-df's facts): reflective QoS and the UP security policy on the stub (and Open5GS where its SMF sends the IE), GBR on the stub and Open5GS. On kaluza-core those sessions record the gNB default they get.

## 4. Parity crosswalk (P4)

- **Baseline:** the 1,633 rows of the 23 gates that start a UERANSIM gNB, in `/home/amadeus/Development/kaluza-core/docs/compliance/smf/phase-2/rows-k3s-963130e1-native-eupf-75d3202.tsv` (`phase-2-final`).
- **Target:** the same gates run with `UE_IMPL=kaluza-sim`, which a kaluza-core session adds (§6).
- **Same-day control:** the baseline is also phase 3's control. If the lab has moved on (core or UPF commits) by P4, UERANSIM is scored again on the same day as the sim, and the crosswalk compares those two runs, not the old TSV (kaluza-core, 2026-10-14).
- **Every baseline row must end in exactly one of these, with 0 rows unaccounted:**

| Outcome | Meaning |
|---|---|
| `PASS` | Same row, same verdict |
| `renamed=<new>` | The row was renamed |
| `retired` | A UERANSIM artefact that no longer applies, e.g. the P-33 tunnel-quieting rows |
| `stays-on-ueransim` | SNPN and Ethernet rows, until those families arrive ("later") |
| `core-finding=KF-nnn` | The sim found a kaluza-core defect |
| `sim-gap=KS-…-Gn` | A declared sim gap |

The sim ships its own crosswalk tool (`tools/crosswalk.py`) with the same TSV schema, so it never depends on kaluza-core code.

## 5. Registers and findings

- **Specs:** pinned in [`specs.md`](specs.md); the highest Rel-19 (`j`) version on the day, re-read at each phase's T0. A Rel-20 item is taken only after Rel-20's ASN.1/OpenAPI freeze, item by item, as kaluza-core does.
- **Registers:** one per area under `docs/compliance/<area>/README.md`, created in P0, in kaluza-core's style:
  - a header (what it is, the commit assessed, spec versions, the row-prefix legend);
  - a **coverage table derived from the spec**, never typed by hand;
  - rows of Row | What | Clause | Verified by | Status (built / declared / out / planned vN).
  - Rows record behaviour verified against running code, not intent.
- **Deviations:** `docs/compliance/deviations.md` indexes the `-V` rows. The ideal RLC/MAC is a declared abstraction (`-G` rows plus `docs/abstraction-ledger.md`), not a deviation.
- **Findings:** each kaluza-core defect the sim finds goes to `docs/findings/KF-nnn.md`, with a pcap, an event slice and the clause. A kaluza-core session picks it up and records it in its own register; the sim's register keeps an `-F` pointer row.
- **Who decides:** a register row cites 3GPP, ETSI, GSMA, IETF, O-RAN or SCF text. UERANSIM, OCUDU, Open5GS, OAI, PacketRusher, Wireshark and pySim are leads, never specs. kaluza-core is never an oracle for the sim, and the sim is never one for kaluza-core.

## 6. The gate contract offered to kaluza-core

This repo edits nothing in kaluza-core. A kaluza-core session adopts the contract when it chooses, for example with a `UE_IMPL=ueransim|kaluza-sim` switch in `misc/gate/kaluza-deploy.sh`.

**What the gates use today** (survey, 2026-10-14):
- **nr-cli UE commands:** `--dump`, `status`, `timers`, `ps-list`, `ps-establish`, `ps-release(-all)`, `ps-modify`, `ps-dn-auth`, `deregister` (normal, switch-off, disable-5g, remove-sim), `sms-send`, `sms-requested`, `sms-replay`, `sms-resubmit`.
- **nr-cli gNB commands:** `ue-list`, `ue-release`.
- **Log greps:** about 40 phrases, e.g. "Initial Registration is successful", "PDU Session establishment is successful".
- **Probes:** for example `grep dn-auth src/…` and `$UE_DIR/COMMIT`.
- **Lifecycle:** `setsid -f nohup build/nr-gnb -c …` over SSH, stopped with `pkill -x`.

**What kaluza-sim offers:**

| Need | Offered |
|---|---|
| Commands | `ksim-ctl` keeps nr-cli's verbs and its `<node> --exec '<cmd>'` form ([`cli.md`](cli.md)), and adds `ho`, `xn-ho`, `n2-ho`, `ho-cancel`, `ng-reset`, `power`, `sim …`, `rlf`, `move`, `wait` |
| Output | KEY=value lines (`CM_STATE=CM-IDLE`, `PS.1.ADDRESS=10.45.0.2`, `T3512.VALUE=3600`); `--json`; `--format=nrcli` |
| Log greps | NDJSON events with stable, spec-referenced names, plus `ksim-ctl ue <sel> wait <event> --timeout N`, which removes sleep-and-grep loops. An optional compat emitter writes the legacy phrases during the transition |
| Exit codes | 0 ok · 1 rejected/failed (`CAUSE=`) · 2 usage · 3 timeout · 4 unknown node · 5 capability absent · 6 wrong state · 7 abort · 10 internal |
| Probes | `ksim-ctl <node> capabilities` (`CAP.SMS_NAS=1`, …), `VERSION=`, `COMMIT=`, `SPEC_PINS=` |
| Lifecycle | `ksim run -c scenario.yaml --run-dir D` as a systemd service (survives SSH loss); logs, pcaps and the manifest in the run directory; `ksim stop`; `FAULTS=0` checked before a set starts |
| Rows | Scenario assertions print kaluza-core's row format (`  PASS  name got=…`), but pass/fail rows stay in the gates |

**kaluza-core's response (2026-10-14):** no objection. It asked for three things, which the contract adopts:
1. **Row text stays identical.** The `UE_IMPL` switch never appears in a gate's row text, so row IDs match under both RANs and the parity diff is a plain TSV compare.
2. **`wait` keeps the evidence.** `ksim-ctl ue <sel> wait <event>` must leave the same evidence the log-grep rows read today: registration and PDU session state, the assigned IP and the TEID. It prints them as KEY=value lines on success, and the NDJSON event carries them. Otherwise those rows lose their proof.
3. **A same-day control.** The 1,633-row baseline (`963130e1` native + eUPF `75d3202`) is phase 3's control. If the lab moves on before P4, UERANSIM is scored on the same day as the sim, not against the old TSV (§4).
