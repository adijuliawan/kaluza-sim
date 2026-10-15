# `ksim-ctl`: the UE and RAN command line

`ksim-ctl` drives every kaluza-sim node through its HTTP/JSON control API ([`architecture.md`](architecture.md) §9). It is for interactive use and for kaluza-core's POSIX sh gates.
- It keeps **nr-cli's verbs and its `<node> --exec '<cmd>'` form**, so moving a gate off UERANSIM changes the binary and the node name, not the logic.
- New commands cover the device, the SIM, radio and mobility, the data plane, events and the RAN nodes.

**As built through P1 N16:**
- **Verbs:**
  - `nodes`, `info`, `version`, `capabilities`, `faults list`, `ues`, `stop`;
  - `ue <sel> status|power on|power off --switch-off|--abrupt|register|deregister normal|switch-off|wait|events` (N8, `--abrupt` N12);
  - `ue <sel> ps-list|ps-establish ipv4|ps-release|ping` (N10), `ifaces|exec` and `ping --df` (N11), `service-request`, `sim remove|insert` and `airplane on|off` (N12);
  - `ue <sel> sms-send <digits> <text> [--ucs2] [--srr] [--vp N]|sms-list|sms-memory full|available` and `register --update` (N13);
  - `ue <sel> sim info|sim read <EF>|sim trace on|off` (N14): `read` takes a name, FID or FID path and refuses key files, NAS state and what the ARR keeps from a reader; `trace` writes the run's `sim.pcapng`;
  - `wait`, `events`;
  - `gnb <name> ue-list|amf-list` (N8), `ue-release <ue> [--cause C]|restart` (N12);
  - `stub release|ping-ue` (N10), `stub deregister [--rereg]|t3512 --seconds N|restart` (N12) and `stub sms-sub --ue SUPI [--off]` (N13), with `--socket` on `ksim-corestub`'s control socket.
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
- `all`.

Group commands take `--stagger <ms>` and `--parallel <n>`, and print one block per UE separated by a blank line.

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
| SIM | `sim info` | ICCID, IMSI, UST/EST service flags, SUCI scheme, routing indicator. **Never keys** | v1 |
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
| Events | `events [--follow] [--filter nas.*] [--since <seq>]` | NDJSON event stream for this UE | v1 |
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
| Any node | `info` · `version` · `capabilities` | Role, addresses, `VERSION=`, `COMMIT=`, `SPEC_PINS=`, `CAP.*=` | v1 |
| | `faults list\|set <rule>\|clear` | Fault injection ([`architecture.md`](architecture.md) §9); `FAULTS=0` when clean | v1 |
| | `pcap start\|stop [--iface …]` | Captures per interface | v1 |

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
