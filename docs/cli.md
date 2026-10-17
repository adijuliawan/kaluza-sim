# `ksim-ctl`: the UE and RAN command line

`ksim-ctl` drives every kaluza-sim node through its HTTP/JSON control API ([`architecture.md`](architecture.md) §9). It is for interactive use and for kaluza-core's POSIX sh gates.
- It keeps **nr-cli's verbs and its `<node> --exec '<cmd>'` form**, so moving a gate off UERANSIM changes the binary and the node name, not the logic.
- New commands cover the device, the SIM, radio and mobility, the data plane, events and the RAN nodes.

**As built through P1 N16:**
- **Verbs:**
  - `nodes`, `info`, `version`, `capabilities`, `faults list`, `ues`, `stop`. From P2 Q14 prep `stop` (and SIGTERM) first lets the network finish the releases under way: until the DU holds no UE context, its count has not fallen for 3 s, or 10 s are up. Then NG ends with SCTP's graceful SHUTDOWN, within 3 s (KS-PLAT-D20);
  - `ue <sel> status|power on|power off --switch-off|--abrupt|register|deregister normal|switch-off|wait|events` (N8, `--abrupt` N12);
  - `ue <sel> ps-list|ps-establish ipv4|ps-release|ping` (N10), `ifaces|exec` and `ping --df` (N11), `service-request`, `sim remove|insert` and `airplane on|off` (N12);
  - `ue <sel> sms-send <digits> <text> [--ucs2] [--srr] [--vp N]|sms-list|sms-memory full|available` and `register --update` (N13);
  - From P3 R3, faults (ADR 0013 point 9): `faults list|set <rule> [--row ID]|clear [<id>|all]`, `ue <sel> rlf` and `du <name>-du cell on|off`. A rule is `<link>.<dir> [msg=M] [ue=N] drop|dup|delay=MS [xN|x*] [pct=P]`:
    - `link` is `ngap`, `f1ap` or `e1ap` (`msg=` an AP message's ASN.1 name, `InitialContextSetupRequest`), `uu` (`msg=` a KAIR frame type, `UL_SDU`, `PRACH`; `ue=` the radio ID) or `n3`, `f1u` (`msg=` a GTP-U message, `G-PDU`);
    - `dir` is `ul` (towards the core), `dl` or `any`; `xN` acts on the first N matches (default 1), `x*` on every one; `pct` on that share of them (seeded);
    - on `uu`, `x*` with `drop` is the air link's loss: RLC AM retransmits each lost SDU one t-PollRetransmit (45 ms) later, and past maxRetxThreshold (8) its transmitter has a radio link failure (KS-L2R-001);
    - every rule set, spent and cleared goes to `<run>/faults.tsv` (a split run's in each role's directory) with its `--row`, and `faults list` prints `FAULTS=0` when none is set; gates refuse to start otherwise, and `tools/p3_exit.py` refuses an exit run with a rule set outside a fault row;
    - `ue <sel> rlf` is a sudden radio link failure; `du <name>-du cell off` takes the cell off the air and the DU asks for its UEs' release, `cell on` puts it back (KS-L2R-005); `du … ue-list` adds `CELL_POWERED`.
  - From P3 R4, a gNB with several DUs (topology v3's `dus`, one cell each): DU 1 is `<gnb>-du` as before, DU n `<gnb>-du<n>`, and every `du <name> …` verb names one. `nodes` lists a node per DU; `info` adds `F1_DUS` (the DUs past F1 Setup at the CU-CP) and `CELLS_ACTIVE`; `du … ue-list` adds `ANNOUNCES` (CELL_ANNOUNCE frames sent), `SFN` with `SFN_AT_MS` (the CLOCK_REALTIME ms it was read at) and `CELL_HANDLE`; `ue <sel> status` adds `CELL` (the camped cell's handle) and `CELL_TAI`. `du <name> restart` also runs all in one: that DU alone stops and starts again, its cell off the air 2 s, as a split run's DU process restarted by its supervisor now is.
  - `ue <sel> sim info|sim read <EF>|sim trace on|off` (N14): `read` takes a name, FID or FID path and refuses key files, NAS state and what the ARR keeps from a reader; `trace` writes the run's `sim.pcapng`;
  - `wait`, `events`;
  - `gnb <name> ue-list|amf-list` (N8), `ue-release <ue> [--cause C]|restart` (N12);
  - `stub release|ping-ue` (N10), `stub deregister [--rereg]|t3512 --seconds N|restart` (N12) and `stub sms-sub --ue SUPI [--off]` (N13), with `--socket` on `ksim-corestub`'s control socket.
  - `stub nas-alg --ea 1|2 --ia 1|2` (P2 Q8): the NAS algorithms the stub's next SECURITY MODE COMMAND selects (row ksim-p2.nas-nea1-nia1).
  - `stub up-policy --integrity X --confidentiality Y [--rate-ul R] [--rate-dl R]` (P2 Q9): the UP Security Indication the stub's SMF sends with the next sessions.
    - X and Y are each `required`, `preferred`, `not-needed` or `absent` (no IE).
    - R is `bitrate64kbs` or `maximum-UE-rate`.
  - `stub qos flows-add|add --qfi N [--5qi N] [--precedence N] --filter F [--direction uplink|downlink|bidirectional]`, `stub qos flows-clear` and `stub qos del --qfi N` (P2 Q10): QoS flows beside the default one.
    - `flows-add` and `flows-clear` set the flows of the sessions set up after it.
    - `add` and `del`, with `--ue SUPI --psi N`, change a live session by a network-requested modification (the 5GSM command inside a PDU SESSION RESOURCE MODIFY REQUEST).
    - F is comma-separated: `all`, `remote=A/N`, `local=A/N`, `proto=N`, `lport=N`, `lports=N-M`, `rport=N`, `rports=N-M`, `spi=N`, `tos=V/M`.
    - The stub's report shows `NOTIFIES` and the UPF's packets per QFI, `UPF_UL_QFI.n` and `UPF_DL_QFI.n`.
  - P2 Q11 adds to `stub qos`:
    - `--gfbr K --mfbr K [--notify]` for a GBR flow (kbit/s, the same both ways, notification control);
    - `stub qos mod --ue SUPI --psi N --qfi N --5qi N` to change a flow where it is;
    - `stub qos rq-timer --seconds N` for the RQ timer the next accepts give a UE that offered RqoS (0: none).
  - `ksim-corestub --dn-netd <socket> [--dn-ns ksim-dn-…]` (P2 Q12): the UPF forwards to a DN namespace's TUN `dn0`, 10.60.0.1, made by that ksim-netd and removed at exit. `gates/run.sh` passes it from `STUB_DN_NETD`.
    - The report adds `UPF_DN_TX`, `UPF_DN_RX`, `UPF_DN_NO_UE` and `UPF_DL_BYTES`.
    - `tools/perf/perf.sh [nea2] [nea1] [split] [many]` runs the performance harness with it (KS-PLAT-B53).
  - `stub udp-ue --ue SUPI --psi N [--src A] [--sport N] [--qfi N] [--rqi]` (P2 Q11): a UDP datagram from the DN to the UE's port 7, which inject mode echoes. It goes on the QFI given, else as the UPF classifies it, with the RQI when asked.
    - The report adds `UPF_UDP_TO_UE`, `UPF_UDP_FROM_UE`, `UPF_RQI_MARKED`, `SM_RQOS`, `NOTIFY_FULFILLED`, `NOTIFY_NOT_FULFILLED` and `SETUPS_WITH_REFUSED_FLOWS`.
- **The run:** `--run D`, else `$KSIM_RUN`, else `$KSIM_RUNS/latest` (`runs/latest`); `--socket S` reaches any control socket, e.g. `ksim-corestub`'s, with `stub`.
- **`ksim-sim`** (the offline card tool) has `range init|derive|provision|deprovision` (N8, N9) and, from N14:
  - `serve [--test-keys | --sealed D --kek F] [--imsi I] [--template Y] [--vpcd host:port] [--personality sysmoISIM-SJA5] [--trace-udp host:port] [--trace-pcap F] [--seconds N]`;
  - `validate <image> [--access]`;
  - `export [--test-keys | --sealed D --kek F] [--imsi I]`;
  - `import --fsdump F [--template Y] --out Y`.
- **nr-cli's form (N16):** `ksim-ctl [options] <imsi-…|gNB> --exec '<command>'` runs the command for that UE or gNB (`IPv4` taken as `ipv4`), and `--format=nrcli` prints `key: value` lines, keys in lower case with dashes. The registration gate reads the RM state this way.
- **Unbuilt verbs** answer exit 5 and name the milestone that brings them.
- **Routes:** in [`src/api/openapi.yaml`](../src/api/openapi.yaml).

## 1. Forms

```
ksim-ctl ue <sel> <command> [args]        one UE, a group, or all
ksim-ctl ue <sel>                         interactive shell (history, tab completion), like nr-cli without --exec
ksim-ctl <node> --exec '<command>'        nr-cli-compatible form; <node> = imsi-… | a gNB/DU/CU name
ksim-ctl gnb|cucp|du|cuup <name> <command> [args]
ksim-ctl nodes                            list running nodes, their roles, addresses and versions
```

**UE selectors (`<sel>`):**
- `imsi-001010000300017`, the SUPI;
- `17`, the index in the farm;
- `group:phones`, a topology group;
- `all`;
- from P2 Q7, `1-100`, a range of farm indices.

Group commands take `--stagger <ms>` and `--parallel <n>`, and print one block per UE separated by a blank line.

**As built (P2 Q7):**
- `--parallel N` (1..64) and `--stagger DUR` are global options: `ksim-ctl --parallel 10 --stagger 50ms ue 1-100 power on --wait 30s`. N UEs are worked on at a time, each started DUR after the one before; the blocks print in farm order once all are in, and the exit code is the worst of them.
- `ksim-ctl metrics` prints `/v1/metrics` in the Prometheus text format (metrics v0, part of KS-CTL-005):
  - `ksim_events_total{event,cause}`;
  - `ksim_qfi_bytes_total` and `ksim_qfi_packets_total{qfi,direction}` at the CU-UP's N3;
  - the histogram `ksim_hop_latency_ms{hop=kair_ul|kair_dl}`;
  - `ksim_process_resident_bytes`, `ksim_process_threads`, `ksim_loop_lag_max_ms`.

  A split run labels each line with its `role`.
- `ksim-ctl debug stall <ms>` blocks the run's loop that long, the DU's in a split run: the watchdog's test.
  - A timer later than the topology's `watchdog_ms` (250 by default) raises `platform.loop_lag`.
  - The gates then ABORT with exit 7 instead of scoring rows.
- `ksim-ctl netd …` talks to ksim-netd for scripts (`--netd PATH`, or `$KSIM_NETD`, default `/run/ksim/netd.sock`):
  - `list`, `setup-node <ns> [--parent P --addr A/N]`, `veth <ns> <A/N>` and `teardown <ns>`, within netd's allowlist;
  - `exec <ns> --log FILE -- <argv…>` starts a command in a namespace netd made, as the caller. The words after `--` go as they are. It prints `PID=` and does not wait. The PID is netd's helper, which leads the command's process group, waits on it and passes SIGTERM, SIGINT and SIGHUP on to it. `kill -TERM -PID` stops the group (KS-PLAT-D18; dash's kill takes no `--`).

  `tools/ocudu-peer.sh run --lab` uses it to start OCUDU's roles in our namespaces on kaluza-uesim (LW2).
- `ksim-ctl info` shows the CU-CP's AS preference as `AS_NEA` and `AS_NIA` (P2 Q8).
- `ksim-ctl gnb <name> up-policy [--preferred-integrity 0|1] [--preferred-confidentiality 0|1] [--absent-integrity 0|1] [--absent-confidentiality 0|1] [--integrity-possible 0|1]` (P2 Q9) reads or sets the CU-CP's local UP security policy for the sessions after.
  - The topology's `cucp: {up_policy: {...}}` sets its defaults.
  - Each session's decision is a `ran.up.security` event.
- `ksim-ctl gnb <name> qos <ue>` (P2 Q10) shows each of the UE's sessions as the CU-CP holds it: `PS.<psi>.DRBS`, and per DRB `PS.<psi>.DRB.<id>.QFIS`, `.5QI` and `.DEFAULT`, with `DRB_MAP` (the topology's `cucp: {drb_map: per-5qi|per-session}`).
- `ksim-ctl gnb <name> qos-release <ue> --psi N --qfi N` (P2 Q10): the gNB releases one QoS flow itself, reconfigures the CU-UP, the DU and the UE, and tells the AMF in PDU SESSION RESOURCE NOTIFY (`ran.session.modify` with `by=gnb`).
- P2 Q10 adds to these views:
  - `ue <sel> ps-list`: the QoS rules (`PS.<psi>.RULES`, `PS.<psi>.RULE.<id>`), the flows' 5QI (`PS.<psi>.FLOW.<qfi>.5QI`), the uplink packets per QFI the classifier sent (`PS.<psi>.UL_QFI.<qfi>`) and those no rule matched (`PS.<psi>.UL_UNMATCHED`);
  - `cuup <name> bearers`: each DRB as `DRB.<cu-up ue>.<psi>.<drb>.QFIS|DEFAULT|UL_PACKETS|DL_PACKETS`, and `QFI.<n>.UL_PACKETS|DL_PACKETS`;
  - `du <name> ue-list`: each UE's DRBs as `UE.<c-rnti>.DRB.<drb>.LCID|QFIS`.
- `ksim-ctl gnb <name> gbr-budget [kbps]` (P2 Q11) reads or sets the cell's GBR budget. The default comes from the topology's `cucp: {gbr_budget_kbps: N}`, 100000.
  - A GBR flow over the budget is refused.
  - A change notifies the AMF of the flows with notification control that are not fulfilled, or fulfilled again.
- P2 Q11 adds to these views:
  - `ue <sel> ps-list`: `PS.<psi>.DERIVED` (the derived QoS rules, with `.DERIVED.<n>.QFI`), `PS.<psi>.RQ_TIMER_MS`, `PS.<psi>.DL_QFI.<qfi>` and `PS.<psi>.DL_UNKNOWN_QFI`;
  - `gnb <name> qos <ue>`: `GBR_BUDGET` and `GBR_USED` in bit/s, and per DRB `.GFBR` (DL/UL) and `.NOT_FULFILLED`;
  - `cuup <name> bearers`: `END_MARKERS`, and `.GFBR` per DRB; `du <name> ue-list`: `.GFBR` per DRB.
- `ksim-bench [--ms N] [--size BYTES] [--check <bounds.tsv>]` (P2 Q8), a separate binary: the user plane's per-packet costs in one process, as `BENCH.<case>.NS=` and `BENCH.<case>.MBITS=`.
  - It covers PDCP DRB pairs per algorithm, the AS contexts against one-shot calls, SDAP, and GTP-U N3 and NR-U.
  - With `--check` it prints `BENCH=PASS|FAIL` against the bounds. CI's hook 75 runs it from the release build.

**Global options:**
- `--json`, or `--format=kv|json|nrcli`;
- `--timeout <dur>`;
- `--wait <dur>`: block until the procedure ends;
- `--run <dir>`: choose a run; the default is the newest.

## 2. Output and exit codes

**KEY=value lines** are the default: one key per line, stable names, documented in `src/api/openapi.yaml`. `--json` prints the same object as JSON. `--format=nrcli` prints nr-cli-shaped YAML for gates during the transition.

| Exit | Meaning |
|---|---|
| 0 | ok |
| 1 | the procedure was rejected or failed; `CAUSE=` says why (e.g. `CAUSE=5GMM#7`) |
| 2 | usage error |
| 3 | timeout |
| 4 | unknown node or UE |
| 5 | capability absent (see `capabilities`) |
| 6 | wrong state for the command (e.g. `ps-establish` while deregistered) |
| 7 | abort: the environment is unsound (loop lag over threshold, faults left on, scene version mismatch) |
| 10 | internal error |

```
$ ksim-ctl ue 17 register --wait 30s
UE=imsi-001010000300017
PROC=registration
RESULT=ACCEPT
GUTI=00101-cafe-01-0040-c0de0017
TAI=00101-000001
ELAPSED_MS=187
EVENT_SEQ=48211
```

## 3. UE commands

| Group | Command | What it does | When |
|---|---|---|---|
| Device | `power on` | Boot: card reset, PLMN and cell selection, registration (initial, or GUTI-based from the card's stored state) | v1 |
| | `power off [--switch-off\|--graceful\|--abrupt]` | Switch-off deregistration, graceful (state written to the card), or abrupt (battery pull: no NAS, no card write) | v1 |
| | `airplane on\|off` | Radio off/on as a phone does: deregistration with switch-off when registered, then no radio | v1 |
| | `reboot` | `power off --graceful` then `power on` | v1 |
| SIM | `sim info` | READER (inproc, pcsc:<reader>, bridge:<host:port>; P2 Q1), ICCID, IMSI, UST/EST service flags, SUCI scheme, routing indicator. **Never keys**. For a card outside the process only READER and IMSI, and `sim read` is refused | v1 |
| | `sim read <EF>` | Decoded content of a non-secret EF (e.g. `5GS3GPPLOCI`, `FPLMN`, `SMSP`). Refuses 4F03/4F05/AF20/AF30 | v1 |
| | `sim remove` · `sim insert <card>` · `sim swap <card>` | Card removal (NAS remove-SIM handling) and insertion | v1 |
| | `sim trace on\|off` | GSMTAP-SIM APDU trace, redacted ([`sim-uicc.md`](sim-uicc.md) §6) | v1 |
| Status | `status` | RM/CM/RRC state, 5GMM substate, 5GS update status, GUTI, TAI, serving cell, PLMN | v1 |
| | `info` | SUPI, IMEISV, persona, UE capabilities summary | v1 |
| | `timers` | Every running NAS/RRC timer with its remaining time | v1 |
| | `nssai` | Configured, allowed, rejected and pending NSSAI | v1 |
| | `cells` | Serving and neighbour cells with RSRP, RSRQ and SINR from the radio model | v1 |
| | `meas` | measConfig in force, and the last measurement reports | v1 |
| 5GMM | `register [--type initial\|mobility\|periodic] [--nssai 1-000001,…] [--follow-on]` | Start a registration | v1 |
| | `deregister normal\|switch-off\|remove-sim\|disable-5g` | UE-initiated deregistration (TS 24.501 §5.5.2.2) | v1 |
| | `service-request [--data\|--signalling]` | From CM-IDLE | v1 |
| | `plmn-search` · `plmn-select auto\|<mccmnc>` | PLMN selection (TS 23.122) | v1 |
| 5GSM | `ps-list` | Sessions: PSI, DNN, S-NSSAI, type, addresses, AMBR, QoS flows | v1 |
| | `ps-establish ipv4\|ipv6\|ipv4v6 [--dnn D] [--sst S --sd SD] [--ssc 1]` | UE-requested establishment (IPv6 and IPv4v6 in v1.x) | v1 |
| | `ps-modify <psi> [--qos …]` | UE-requested modification | v1 |
| | `ps-release <psi>\|--all` | UE-requested release | v1 |
| | `qos <psi>` | QoS rules, flow descriptions, and derived (reflective) rules | v1 |
| | `ps-dn-auth <psi> …` | Answers for PDU session authentication (EAP/PAP/CHAP) | v1.x |
| SMS | `sms-send <msisdn> <text> [--ucs2] [--srr]` | MO SMS over NAS | v1 |
| | `sms-list` · `sms-memory full\|available` | Received messages; memory-full handling with RP-SMMA | v1 |
| Radio and mobility | `move <x,y[,z]>` | Set the position in the scene | v1 |
| | `path <x1,y1 x2,y2 …> --speed <m/s>` | Waypoint trajectory | v1 |
| | `cell-lock <pci>\|off` | Force camping or measurement on one cell (a test aid, not a 3GPP feature) | v1 |
| | `rlf` | Inject radio link failure on the serving cell | v1 |
| | `link loss <pct>` · `link delay <ms>` · `link clear` | Per-UE impairments on the KAIR link | v1 |
| Data plane | `exec [--] <cmd…>` | Run a command inside the UE's netns as the user, e.g. `exec ping -c3 172.30.61.1`, `exec iperf3 -c …`, `exec curl …`. The words go as they are; the command's output is printed, then `EXIT_CODE=` and `TIMED_OUT=`; a non-zero exit is exit 1, a run past `--timeout` exit 3 (the command killed). Needs the UE's namespace (ksim-netd): in inject mode exit 5 | v1 |
| | `ping <dst> [--psi N] [-c N] [--interval MS] [--size N]` | Convenience wrapper; prints `SENT=`, `RECEIVED=`, `LOSS_PCT=`, `RTT_AVG_MS=`; no reply at all exits 1. Until the TUN data plane (P1 N11) the device builds the echo requests itself (inject mode) | v1 |
| | `ifaces` | TUN devices, addresses, MTU, DNS, packet counts, `NOISE=`, and the kernel's own view of the namespace (`KERNEL.<if>.IPV4=`, `KERNEL_IPV6=`); `MODE=netns\|inject` | v1 |
| Events | `events [--follow] [--filter nas.*] [--since <seq>]` | NDJSON event stream for this UE. Over HTTP (`GET /v1/events?follow=1`) a followed stream sends a blank line after each quiet second, so a client that has left frees its server thread; readers skip blank lines, and `ksim-ctl events` prints none (P2 Q7, KS-PLAT-D14) | v1 |
| | `wait <event> [--timeout 30s] [--where key=val] [--since <seq>\|--new]` | Block until an event arrives, e.g. `wait nas.reg.accept`, `wait rrc.ho.complete`. It is a long poll over the run's event sequence: by default it also matches events already recorded (`--since 0`, like grepping a log); `--new` matches only events after the call. A procedure verb given `--wait` registers its waiter before it starts, so it cannot miss its own event. On success it prints the event's evidence as KEY=value lines: registration or PDU session state, the assigned IP, the TEID. That is the evidence the log-grep gate rows need ([`verification.md`](verification.md) §6) | v1 |
| Later | `inactive-status` (v1.x) · `loc` (LPP, Ph2) · `ims register\|call\|hangup` (Ph2) | — | — |

## 4. RAN commands

| Node | Command | What it does | When |
|---|---|---|---|
| gNB / CU-CP | `ue-list` | RAN UE contexts: RAN/AMF UE NGAP IDs, C-RNTI, cell, RRC state | v1 |
| | `ue-release <ue> [--cause user-inactivity\|radio-connection-with-ue-lost\|…]` | NGAP UE Context Release Request (forces CM-IDLE) | v1 |
| | `ho <ue> --target <pci\|gnb>` | Handover decision now; Xn if a peer exists, else N2 | v1 |
| | `xn-ho <ue> --target …` · `n2-ho <ue> --target …` | Force the handover type | v1 |
| | `ho-cancel <ue>` | Handover cancellation (NGAP or XnAP) | v1 |
| | `ng-reset [--partial <ue…>]` | NG Reset, full or partial | v1 |
| | `amf-list` | AMF associations, GUAMIs, availability | v1 |
| | `xn-link up\|down <peer>` | Bring an Xn-C association up or down (scores N2 versus Xn) | v1 |
| DU | `cell on\|off <pci>` · `cell power <pci> <dBm>` | Cell outage and power steps | v1 |
| | `ue-list` · `paging-stats` | DU UE contexts; paging occasions served | v1 |
| CU-UP | `bearers` · `tunnels` · `gtpu-echo <peer>` | E1 bearer contexts; GTP-U TEIDs; an Echo to a peer | v1 |
| Split run (P2 Q3) | `cucp <name> restart` · `du <name>-du restart` · `cuup <name>-cuup restart` | That role's process alone stops and starts again; its last run directory is kept as `<role>.<n>/` (`gnb <name> restart` restarts all three) | v1 |
| Any node | `info` · `version` · `capabilities` | Role, addresses, `VERSION=`, `COMMIT=`, `SPEC_PINS=`, `CAP.*=` | v1 |
| | `faults list\|set <rule>\|clear` | Fault injection ([`architecture.md`](architecture.md) §9); `FAULTS=0` when clean | v1 |
| | `pcap start\|stop [--iface …]` | Captures per interface | v1 |

**As built (P2 Q3):** `du <name>-du ue-list` answers `CELL_ACTIVE`, `UES`, `UL_SDUS`, `DL_SDUS` and `WRONG_PPID`, and from P2 Q4 `DDDS_TX` (NR-U DL DATA DELIVERY STATUS frames sent) and `SI_TX` (MIBs and SIB1s on air). `cuup <name>-cuup bearers` answers `E1_READY`, `CONTEXTS`, `DL_PACKETS`, `UL_PACKETS` and `DROPPED`, and from P2 Q4 `DDDS_RX`, from P2 Q5 `INACTIVITY_REPORTS` (BEARER CONTEXT INACTIVITY NOTIFICATIONs sent). The stub's report (`ksim-ctl --socket <stub> stub`) gives `LAST_RELEASE_CAUSE` from P2 Q5, and from P2 Q14 prep `NG_END` (`shutdown`: the gNB ended NG with SCTP's graceful SHUTDOWN; `lost`: an ABORT or a lost peer), `RELEASE_REQUESTS_REPEATED` (UE CONTEXT RELEASE REQUESTs for a UE that had asked already or was being released) and `RELEASE_DELAY_MS` (`ksim-corestub --release-delay-ms`: its UE CONTEXT RELEASE COMMAND that late, as a loaded core's; `gates/run.sh` passes `STUB_RELEASE_DELAY_MS`). `gnb <name> ue-list` adds `F1_UE_STREAMS` (the SCTP streams the DU's UE-associated F1AP came on) and `F1_UE_ON_STREAM0`. In a split run `nodes` lists the four roles with their `PID` and `UP`. A role the interop peer runs (P2 Q4, the topology's `peers:`) is listed with `PEER=ocudu` instead, `info` adds `PEER_CUCP=` or `PEER_CUUP=`, and that role's verbs (`gnb <name> ue-list`, `amf-list`, `ue-release`, `cuup … bearers`, its `restart`) answer exit 5: the peer has no ksim control API. `paging-stats`, `tunnels` and `gtpu-echo` are not built yet (exit 5); `du <name>-du cell on|off` is from P3 R3.

## 5. Moving a gate from nr-cli

| nr-cli (UERANSIM) | ksim-ctl |
|---|---|
| `nr-cli <imsi> --exec 'status'` | `ksim-ctl <imsi> --exec 'status'` or `ksim-ctl ue <imsi> status` |
| `--exec 'ps-establish IPv4 --sst 1 --sd 1 --dnn ims'` | Same verb; `ipv4` is case-insensitive |
| `--exec 'deregister switch-off'` | Same |
| `--exec 'sms-send …'` | Same |
| `nr-cli UERANSIM-gnb-… --exec 'ue-list'` / `'ue-release <id>'` | `ksim-ctl cucp <name> ue-list` / `ue-release <ue>`; gNB aliases configurable |
| `pkill -9 nr-ue` (radio loss) | `ksim-ctl ue <sel> power off --abrupt`, or `rlf` |
| Grep a log line ("Initial Registration is successful") | `ksim-ctl ue <sel> wait nas.reg.accept --timeout 30s`. An optional compat emitter writes the old phrases during the transition |

The gate contract as a whole is in [`verification.md`](verification.md) §6.

## 6. The AT port (optional, v1.x, build phase P3c)

Each UE can expose a modem-style AT interface on a pty (`/run/ksim/ue-<n>/at`), or on TCP for remote use. Your existing modem scripts, `minicom`/`socat`, and lpac's AT backend then drive a simulated UE the way they drive the RM520N or RG255C.

- **Syntax and responses:** ITU-T V.250 syntax; result codes; `+CMEE` error reporting; URCs.
- **TS 27.007 (j60):** `ATI`, `+CGMI/+CGMM/+CGMR/+CGSN`, `+CFUN`, `+CPIN`, `+CIMI`, `+COPS`, `+C5GREG`, `+CGDCONT`, `+CGACT`, `+CGPADDR`, `+C5GNSSAI`, `+CSQ`, `+CEER`, `+CGEREP`.
- **SIM access passthrough:** `+CSIM`, `+CRSM`, `+CCHO`, `+CCHC`, `+CGLA` forward APDUs to the soft or real card ([`sim-uicc.md`](sim-uicc.md) §5).
- **TS 27.005 (j00), SMS:** `+CMGF`, `+CSCA`, `+CMGS`, `+CNMI`, `+CMGR`, `+CMGL`, `+CMGD`, `+CPMS`.
- **Quectel extension subset** for the RM520N and RG255C personas: `+QENG` (servingcell, neighbourcell), `+QNWPREFCFG` (mode_pref, nr5g_band, ue_usage_setting, nr5g_disable_mode, voice_domain), `+QNETRC`, `+QRSRP`, `+QRSRQ`, `+QSINR`, `+QSIMSTAT`.
  - Implemented from the documented behaviour of the AT manuals in `/home/amadeus/Development/ran/firmware/Quectel/`.
  - The manuals are marked confidential, so **no text from them is copied** into this repo; it only cites them by path ([`research/quectel.md`](research/quectel.md)).

The AT port is a front end over the same UE actor as `ksim-ctl`. It adds no protocol behaviour of its own.
