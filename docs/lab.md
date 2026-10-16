# Lab: where kaluza-sim runs, and how

**Decisions (user, 2026-10-14):**
- Runs against kaluza-core use **kaluza-uesim (Proxmox VM 105) as it is.** Build phase P2 measures the performance targets there and decides whether to resize.
- **Real SIM cards are reached through a card bridge on the dev PC.**

The lab follows kaluza-core's re-layout. Design: https://claude.ai/artifact/WzcF39UQft2B8yBZoHyLx2. As built: https://claude.ai/artifact/FGfvpNWLRqrjdwyAiCvYLQ. Repo source: `/home/amadeus/Development/kaluza-core/docs/phase-2/lab-relayout.md`, owned by kaluza-core. This repo never edits it.

## 1. Hosts and roles

| Host | Role | What runs there |
|---|---|---|
| **Dev PC** (24 threads, 61 GiB, Ubuntu 26.04, Linux 7.0.0-34) | Build. Tier-1 tests: unit, KAT, fuzz, virtual-time procedure tests, and all-in-one against a scripted core stub, with **no lab traffic**. Loopback interop with OCUDU's CU-CP and CU-UP. **The card bridge** | Compilers, asn1c, the oracles (tshark, pycrate, pySim), `ksim-sim serve --pcsc` with the OmniKey 3x21 |
| **kaluza-uesim** (VM 105) | Every run against kaluza-core: lab scenarios (T3) and gate parity (T4). OCUDU interop that involves the core | kaluza-sim binaries, a netns per RAN node, a netns per UE |
| **amadeus-open5gs** (the rig VM: VMware on the dev PC, vmnet8 192.168.134.128) | The Open5GS fork as P1's control core ([ADR 0010](adr/0010-open5gs-control-core.md)), driven from the dev PC over vmnet8 only | A full 001/01 fork core from kaluza-sim's own config copy, started for a control run and stopped after it (every NF, plus `ogstun`); never while a kaluza-core gate set runs, since the gates start fork peers from the same install |
| Neither | The B220 / OCUDU cell on the dev PC | kaluza-sim never transmits. Heavy sim load stays off the dev PC while its cell runs (kaluza-core's "no big reads during the cell" rule) |

## 2. kaluza-uesim (read 2026-10-14, read-only)

| Item | Value |
|---|---|
| VM | Proxmox VMID 105, 4 vCPU, 8 GB (7 GiB visible), 32 GB disk with **11 GB free** |
| OS | Ubuntu 26.04 LTS, Linux 7.0.0-34-generic, the same as the dev PC |
| CPU as seen by the guest | AMD Threadripper PRO 5975WX (Zen 3) flags: AES, PCLMULQDQ, VAES, AVX, AVX2, BMI2, FMA, SHA-NI; **no AVX-512** |
| Kernel features | `sctp` loaded; `/dev/net/tun` present; chrony synced to NTP |
| NICs | `ens18`: management, 192.168.0.139/24 on router A (vmbr0). `ens19`: VLAN 30 on vmbr1 (VLAN-aware), the dev PC's `lab-trunk` (1 Gb/s, physical MTU 9000) |
| `ens19` addresses | 172.30.30.20–.23, from kaluza-core's netplan overlay `/etc/netplan/60-kaluza-lab.yaml` (source `/home/amadeus/Development/kaluza-core/deploy/lab/uesim/60-kaluza-lab.yaml`) |
| Routes | `192.168.10.230/32` (the N3IWF's NWu) via 172.30.30.1 |
| Co-tenants | UERANSIM (nine trees under `~/`), n3iwue |
| Access | `ssh kaluza-uesim` from the dev PC: user amadeus, lab key, passwordless sudo. Today it goes to 192.168.0.139 over the dev PC's Wi-Fi |

## 3. Addresses on VLAN 30

| Address | Holder |
|---|---|
| 172.30.30.1 | Dev PC `lab-trunk.30`: AMF N2 `:38412`; N3IWF N3 |
| .2 | V-UPF N3 (VF). It never ARPs for its peers: each one needs a static neighbour entry (§4) |
| .3–.6 | Core-side N3 peers; the dev PC's `lab-trunk.30` holds .3–.5. Roles in `lab-relayout.md` |
| .10 | OCUDU gNB (B220) |
| .11 | DNAT alias for the N3IWF gate's NAT rows. It keeps that role |
| .12 | kaluza-gnb2 (phase 3). It moves here from the phase-3 plan's example .11: kaluza-core's proposal, with the user's go on 2026-10-14. It gets its V-UPF neighbour entry once VM 109 exists |
| .20 | kaluza-uesim: UERANSIM gNB, n3iwue IKE |
| .21–.23 | kaluza-uesim aliases: n3iwue multi-UE runs, UERANSIM's handover-target gNB |
| **.30–.39** | **kaluza-sim RAN nodes.** kaluza-core found the block free in every repo and live (2026-10-14). With the user's go of the same day, a kaluza-core session records it in `lab-relayout.md` |

**Inside the block:**

| Address | Use |
|---|---|
| .30 / .31 | gNB 1: CU-CP (N2, Xn-C) / CU-UP (N3, Xn-U) |
| .32 / .33 | gNB 2: CU-CP / CU-UP |
| .34 / .35 | gNB 3: CU-CP / CU-UP. Three gNBs allow A→B→C→A handover chains that prove the NH/NCC chain |
| .36–.39 | Spare: OCUDU CU-CP/CU-UP peers for Xn and E1 interop runs against the core, extra gNBs |

**What stays off VLAN 30:**
- **UEs.** A UE's traffic leaves inside GTP-U from its gNB's CU-UP address. UE netns get only their PDU session addresses.
- **F1-C, F1-U and E1** between the nodes of one gNB. They run on a host-internal bridge `ksim-mid` (10.250.0.0/24, no uplink), so they never load the trunk.
- **The DU.** It needs no VLAN 30 address.

**gNB identities:**
- gNB IDs, NCIs and PCIs come from a kaluza-sim range (for example gNB IDs from 0x1A0, PCIs from 101), so they never collide with OCUDU (PCI 1) or UERANSIM. `ksim` refuses to start on a collision it can see.
- **TACs are shared, not ours.** A cell must advertise a TAC the AMF serves, or its gNB gets NG SETUP FAILURE. The AMF's list (kaluza-core `deploy/nf/amf/application.yaml`, read by kaluza-core 2026-10-14):

| TAC | Use |
|---|---|
| **000001** | 001/01 3GPP cells: every kaluza-sim cell by default |
| **000003** | SNPN cells (001/01, NID 000007ed9d5), which broadcast NPN-Support |
| 000002, 000004, 000005, 000006 | The dedicated non-3GPP TACs (N3IWF, TNGF, TWIF, W-AGF; TS 23.501 §5.3.2.3). **A gNB never advertises them**; `ksim` refuses a topology that does |
| **000007** | The second 001/01 TAC. It arrives with wave 40 (a list entry and an AMF roll), for P3's mobility-registration rows |

- **999/70 has no AMF.** Its subscribers register as roamers through 001/01 cells (the AMF's roaming partners are 999-70 and 999-71). No kaluza-sim cell broadcasts 999/70 against kaluza-core.

## 4. Network plumbing (the VM's netplan is not touched)

- **Per-node namespaces.** At run start, `ksim-netd` creates a netns per RAN node (`ksim-<run>-<node>`). Each gets an **ipvlan (L2 mode) child of `ens19`** carrying the node's .30–.39 address.
  - ipvlan shares `ens19`'s MAC, so the Proxmox bridge and any MAC filtering see nothing new. The V-UPF's neighbour entries depend on that MAC, so the nodes **must stay ipvlan L2 children of `ens19`**. A macvlan or another NIC would bring a new MAC, and the V-UPF's downlink would go to the wrong place.
  - In L2 mode, ipvlan children cannot reach the parent's own addresses (.20–.23), and kaluza-sim never needs to.
- **The V-UPF's static neighbours (a P1 entry condition).**
  - The V-UPF does not ARP for its N3 peers. It holds a permanent neighbour per peer: `PLANE_NEIGHBOURS` in kaluza-core's `deploy/k8s/userplane/visited/upf.env`, applied by `plane.sh`. On 2026-10-14 it listed .1, .3, .4, .5, .6, .10 and .20.
  - A CU-UP address without an entry gets no downlink GTP-U: the uplink works and the downlink silently never leaves the UPF.
  - **Done 2026-10-14, 15:59 KST.** kaluza-core added .30–.39 as permanent neighbours on the V-UPF's n3, all at `ens19`'s MAC `bc:24:11:2d:72:d9`, the one already pinned for .20. The roll changed nothing else, and the SMF re-associated.
  - .12 (kaluza-gnb2) gets its entry once VM 109 exists and has a MAC.
  - If `ens19`'s MAC ever changes (the VM's NIC re-created), every entry goes stale. Tell the core session.
- **The internal bridge.** `ksim-mid` connects the nodes of one gNB by veth legs.
- **Run stop** removes the namespaces and the bridge. `ksim-netd gc` cleans up leftovers at start and reports what it removed.
- **Control.** Each node's control API listens on a UNIX socket under `/run/ksim/<run>/<node>.sock`, reachable from the root netns and over SSH. TCP ports 9400–9405 are used only in all-in-one mode or when a node runs in the root netns.
- **Evidence.** `tcpdump -i ens19` in the root netns sees every node's N2/N3/Xn traffic. Run pcaps are written per interface by the nodes themselves.
- **Throughput.** The trunk is 1 Gb/s, so simulated-UE data tops out near 940 Mbit/s per direction. N3 crosses the trunk once to the V-UPF; traffic to `visited-dn` on `kaluza-dn` crosses it again. The 400 Mbit/s aggregate target ([`requirements.md`](requirements.md) §3.5) fits.

## 5. Build and deploy

- **Build on the dev PC only**, with preset `release-lab`: `-march=x86-64-v3 -maes -mpclmul -mvaes -mtune=znver3`.
  - Never `-march=native`: the dev PC's i7 has instructions Zen 3 lacks (the same lesson as OCUDU in the kaluza-gnb2 VM).
  - Both hosts run Ubuntu 26.04 on Linux 7.0.0-34, so shared libraries match. P0 confirms this with a smoke run.
- **No build trees in the VM.** It has 11 GB free and 4 vCPUs.
- **Deploy:** `tools/deploy-uesim.sh --window-agreed` streams a tar to `kaluza-uesim:~/ksim/releases/<git-describe>/` and re-points the `~/ksim/current` symlink (as built in P1 N9):
  - the `apps/` binaries;
  - `topologies/`, `personas/`, and the card *templates*;
  - never secrets.

  Old versions are pruned, keeping the last three.
- **Secrets** (sealed card secrets, the range master secret) are streamed separately into a 0600 path, never printed, and verified by checksum. That is kaluza-core's practice for lab secrets.
- **The provisioning credentials** (the Keycloak client `kaluza-sim-key-entry`'s secret and its mTLS client certificate, [ADR 0008](adr/0008-subscriber-provisioning-api.md)) stay on the dev PC in `~/.config/kaluza-sim/provisioning/` (0700/0600). They are never deployed to the VM. The 999/70 seed file (`~/.config/kaluza-sim/seed/`) stays there too. Provisioning runs from the dev PC only ([`sim-uicc.md`](sim-uicc.md) §8).
- **Run directories** (`~/kaluza-sim-runs/<ts>/`: logs, pcaps, manifest) are pruned by age, because of the small disk.
- **ksim-netd v3 (P2 Q6, ADR 0011 point 4).** New operations:
  - `bridge` and `veth` (`ksim-mid`, 10.250.0.0/24), only with `--mid`, which netd refuses off kaluza-uesim;
  - `setup_dn` and `dn_tun` (a DN namespace `ksim-dn-…` with a TUN `dn0` for the scripted UPF), with `--dn 10.60.0.0/24` on both hosts;
  - `exec` into any namespace netd made.

  The units: `tools/systemd/ksim-netd.service` (the VM: `--mid 10.250.0.0/24 --dn 10.60.0.0/24`) and `ksim-netd-devpc.service` (the dev PC: `--dn` only; never a bridge or a veth there, P-64).
  - **The dev PC's upgrade is the user's (D6),** from a `release` build of this tree:

    ```
    sudo install -o root -g root -m 0755 build/release/apps/ksim-netd/ksim-netd /usr/local/sbin/ksim-netd
    sudo install -o root -g root -m 0644 tools/systemd/ksim-netd-devpc.service /etc/systemd/system/ksim-netd.service
    sudo sed -i "s/^Environment=KSIM_UID=.*/Environment=KSIM_UID=$(id -u)/" /etc/systemd/system/ksim-netd.service
    sudo systemctl daemon-reload && sudo systemctl restart ksim-netd
    ```

    Done by the user on 2026-10-16 at 19:33 KST: netd v3 from the release build of 45bbae7's tree, with the `ksim-netd-devpc.service` unit (`--uid 1000 --dn 10.60.0.0/24`). The P2 Q12 performance harness (`tools/perf/perf.sh`, KS-PLAT-B53) uses it for the UE and DN namespaces. For Q12's profile the user also set `kernel.perf_event_paranoid=1` with sysctl, until the next reboot (it was 4). On 2026-10-17 at 02:07 KST the user installed netd again from the release build of b8ffa0c's tree, with KS-PLAT-D18's fix: a SIGTERM to the PID `ksim-ctl netd exec` prints now ends the command too (checked with a `sleep` in a scratch namespace).

    The privileged hooks (`KSIM_CI_PRIV=1 tools/ci.d/66-netd-priv.sh full`, `67-netns.sh full`) start their own netd from `build/dev` and need no install. From Q6 they check the DN namespace's TUN with an echo, and the data plane in split mode.
  - **The VM's is mine in a window (LW1's setup, D6):** the deploy prints the same steps.
- **Deploy v3 (P2 Q6):** `tools/deploy-uesim.sh` also ships the role apps and `ksim-corestub`, and with `--peers` OCUDU's `ocucp`/`ocuup` and their PIN.
  - A peer library missing on the VM is named (`PEER_LDD=MISSING …`): the D7 list.
  - A run that outlives SSH is the user unit `tools/systemd/ksim-run@.service` (`systemctl --user start ksim-run@split-lab`). It needs lingering (`loginctl enable-linger`, root, once).
  - `topologies/split-lab.yaml` is LW1's split run: the CU-CP at .30 plus 10.250.0.1, the CU-UP at .31 plus 10.250.0.3, the DU at 10.250.0.2.
- **The OCUDU peer (P2 Q4, ADR 0012):** `tools/ocudu-peer.sh build` on the dev PC. It exports `d9d2263f4d` from `ran/ocudu-fork` with `git archive` (the fork is never written to) into `~/kaluza-sim-peers/ocudu-d9d2263f4d/` and builds only `ocucp` and `ocuup`, Release, `-march=x86-64-v3`.
  - Built 2026-10-16: `ocucp` sha256 `0765349bbee1181696d9148f0f5ceb746fd6167429b6f40297eecee570de4551`, `ocuup` `43856373603eaf0256109aab10396c11373df5cabcf3ee8aa1875379fbf64d40`, recorded in the build's `PIN` file and copied into every run. Neither binary holds an AVX-512 instruction, so both run on the VM's Zen 3.
  - Beyond glibc and libstdc++, they need `libmbedcrypto.so.16`, `libsctp.so.1` and `libyaml-cpp.so.0.8`. These are the libraries D7 allows on the VM, once deploy v3's ldd check names them there (Q6).
  - On the dev PC the peers run only on 127.0.0.x and never while a `gnb` or `odu` process runs (the script and hook 58 refuse). `gates/run.sh` starts and stops them from a topology's `peers:`.
  - The peer's files go to `<run>/peer/`, owner-only. Its NGAP and E1AP captures hold K_gNB and the UP keys in clear, so `tools/peer_redact.py` zeroes those keys when the run ends.
  - The interop record is [`interop/ocudu.md`](interop/ocudu.md).

## 6. Running alongside UERANSIM and the core's gates

- **Lifecycle.** `ksim run -c topologies/<file>.yaml --run-dir …` runs in the foreground as built in P1; P2 (Q6) adds the systemd unit that lets a run survive SSH loss. `ksim stop` ends it. Stop with `pkill -x` only, never `pkill -f`.
- **One RAN at a time.** UERANSIM and kaluza-sim stay installed side by side, but **only one runs against the core in a given gate window.**
  - kaluza-sim uses its own IMSI range (`001010000300000…`), addresses and gNB IDs, so a crossed run can't corrupt the other's subscribers.
  - A gate that counts NG associations or RAN UEs would still see both.
- **Windows.** Runs happen in windows agreed with the kaluza-core session: never during another session's set, never during a UPF-VPP W5 scoring freeze.
  - Since kaluza-core-e9 ended there is no standing coordinator: kaluza-sim agrees each window with whichever kaluza-core session is active, and asks the user when none is (P1 working agreement, 2026-10-15).
  - P1's windows: **W0** (N9) imports imsi-001010000300000..099 through the provisioning API, then NG Setup, registration of 1–3 UEs, AS SMC and deregistration; **W1** (N11) sessions, a ping to the DN, an MTU probe, two sessions; **W2/W3** (N18) the full P1 row set. The sub-blocks of that import: 000–049 default, 050–059 SMS (`smsSubscribed` true), 060–069 `subsRegTimer` 120 s (each re-registers every 2 min while registered, so they stay out of rows that count AMF log lines), 070–079 EAP-AKA′, 080–099 spare.
  - **P2's windows** (the P2 plan, 2026-10-15; each agreed with the active kaluza-core session with a start and an end):
    - **LW1** (Q7): split mode on the VM (`ksim-mid`, .30/.31), the P1 row set, then 100 UEs (imsi-…0000..099), 10 attaches in parallel, one `internet` session each, low-rate pings; netd v3 and the packages of D7 installed in its setup.
    - **LW2** (Q7): OCUDU `ocucp` at .36 and `ocuup` at .37 in our namespaces (ADR 0012), with our DU and up to 100 UEs.
    - **How LW1 and LW2 run (as built in Q7):**
      1. Setup: `tools/deploy-uesim.sh --window-agreed --peers` (with `--secrets` when the cards changed). Install netd v3 on the VM with the printed steps (D6). `apt install` exactly what `PEER_LDD=MISSING` names, plus iperf3 (D7), each recorded below.
      2. On the VM, from `~/ksim/current`, run `KSIM_LAB=1 KSIM_BIN=~/ksim/current/bin KSIM_PHASE=p2 gates/run.sh kaluza <gates>`, with the topology in `KSIM_TOPOLOGY_FILE`:
         - LW1: `split-lab.yaml` with the P1 gates and `ksim-p2-split.sh`, then `split-lab-100.yaml` with `ksim-p2-scale.sh`;
         - LW2: `ocudu-c3-lab.yaml` with `ksim-p2-ocudu.sh`, the P1 gates that apply in C3, and `ksim-p2-scale.sh`.
      3. In LW2, `gates/run.sh` starts OCUDU through `tools/ocudu-peer.sh run --lab`. Each role runs in a namespace of ours made through `ksim-ctl netd`:
         - `ksim-ocucp`: 172.30.30.36 on `ens19`, and 10.250.0.1 on `ksim-mid`;
         - `ksim-ocuup`: 172.30.30.37, and 10.250.0.3;
         - netd's `exec` starts each role as amadeus, from `topologies/peers/ocudu/*-lab.yml.in`.

         The run waits on OCUDU's console for E1, since its sockets are out of `ss`'s sight. `stop --lab` tears the namespaces down.
      4. The VM has no pycrate venv, so `peer_redact.py` can't run there. The peer's NGAP and E1AP captures are then removed, never kept or copied off in clear (`PEER_REDACTED=removed`).
      5. Afterwards check: `ip netns list` shows no `ksim-` namespace; `pgrep -f peers/ocudu` shows nothing; `ip link show ksim-mid` shows no leg left. Then tell the core session the end time.
      6. After a run, `grep KSIM_LOOP_STUCK <run>/*.out`. Each line names a role's loop that stopped, with its syscall and descriptor and a backtrace (KS-PLAT-B49).
    - **What is installed on kaluza-uesim for P2 (D6, D7):**

      | Date (KST) | What | By |
      |---|---|---|
      | 2026-10-16 08:53 | ksim-netd v3 from release 545129cb1e88 (`--mid 10.250.0.0/24 --dn 10.60.0.0/24`), unit `ksim-netd.service` | me, in LW1's setup |
      | 2026-10-16 08:53 | `libmbedcrypto16` 3.6.5-0.1ubuntu2 and `libyaml-cpp0.8` 0.8.0+dfsg-9 (apt), exactly what ldd named for ocucp/ocuup; `libsctp1` and `iperf3` 3.20-2 were already there | me, in LW1's setup |
    - **LW1a (2026-10-16 08:53–09:35 KST):** the first split run against kaluza-core, from release 545129cb1e88.
      - The P1 data plane, registration and session gates passed, and idle 13 of 14.
      - Calls to the run then went unanswered one by one. From 09:02 it answered nothing, until the gate timeout at 09:35 (KS-PLAT-T53, D12).
      - One UE (…0008) was left registered with a session. It was re-registered and deregistered at 09:40 with kaluza-core-df's agreement.
      - The window was closed early. LW1b and LW2 move to the next window, after B49's diagnostics.
    - **LW1a again (2026-10-16 11:01–11:17 KST, release 081050959efb):** the same stall. Its cause was found on the VM, and it is ours (KS-PLAT-D14).
      - Each role's event stream held a server thread for every supervisor follower that had left.
      - After about 80 quiet seconds a role answered nothing. Each held 82 to 206 connections on its ctl.sock.
      - …0008 was again left registered and was again cleaned up (11:19:50, accepted). kaluza-core-92 found nothing of ours left on the core.
    - **LW1 and LW2 passed (2026-10-16 12:35–13:34 KST, kaluza-core-92's window, AMF f51ccdb1):**
      - LW1a ran the P1 row set in split mode in 3 minutes (KS-PLAT-T55). The split gate's SCTP and F1-U counts still assume the dev PC.
      - LW1b registered 100 UEs with a session each in 18.8 s.
      - LW2 ran OCUDU at .36/.37 in our namespaces: the C3 rows, the P1 rows that apply, and 100 UEs through OCUDU in 26.4 s (KS-PLAT-T56).
      - LW2's first start failed on OCUDU's buffered console (KS-PLAT-D15) and was retried after the fix.
    - **Two teardown defects kaluza-core-92 reported, fixed before LW5 (P2 Q14 prep):**
      - Our CU-CP asked for a UE's release again when F1 went at teardown, though our DU's radio-loss request had asked already (KS-NGAP-D5). It now asks once per UE.
      - Our gNB ended NG with an ABORT (the AMF's COMM_LOST, which set off its race F-77) while the AMF's releases were still queued (KS-PLAT-D20). A stop now waits for the releases under way, then ends NG with a graceful SHUTDOWN. kaluza-core's F-77 fix (kaluza-amf:671c7c89, 2026-10-17 00:11 KST) is proved by LW5's teardowns.
    - **LW3** (Q15): the throughput set inside the VM against the scripted core on 127.0.0.x. Nothing crosses `ens19` or the trunk, but it needs the VM free of core sets.
    - **LW4** (Q14): the real card imsi-001010000300100 through the dev-PC bridge (§7).
    - **LW5** (Q14): the full P2 row set in split mode.
    - After each: every session released, every UE switched off, no `ksim-` or OCUDU process or namespace left.
- **The dev-PC guard.** The real AMF listens on the dev PC itself (172.30.30.1:38412), so `ksim` refuses any peer in 172.30.0.0/16 unless it runs with `--lab` on `kaluza-uesim`, and the scripted core binds 127.0.0.x only ([ADR 0009](adr/0009-p1-runtime-shape.md), point 11). vmnet8 (192.168.134.0/24, host-only) is allowed for the Open5GS control.
- **W0 and later lab runs (P1 N9).** Steps 1–3 run once per release or provisioning change:
  1. `tools/deploy-uesim.sh --window-agreed --secrets` installs a release under `~/ksim/releases` and sends the sealed cards and the KEK.
  2. The user installs `ksim-netd` as root with the commands the script prints. The binary goes to `/usr/local/sbin`, and `tools/systemd/ksim-netd.service` serves the user's uid with ipvlans on `ens19` and 172.30.30.30–.39/24 only.
  3. `tools/kaluza-provision.sh --window-agreed provision --block 001010000300000/100` runs from the dev PC, after the core session has checked a `ksim-sim … --dry-run` bundle. It reads the Keycloak ClusterIP and a Ready UDR pod's IP with `kubectl get` on each run (`--resolve-only` shows them) and passes them to `ksim-sim` (row KS-UICC-B5). Each create is `If-None-Match: *`: 201 counts as created, 412 as existing, and the first other status (0, a TLS or connection failure, included) stops the run with `STOPPED_AT`; the report is `CREATED`, `EXISTING`, `FAILED` and `NOT_TRIED` (row KS-UICC-B8).
  4. On the VM, `KSIM_LAB=1 KSIM_BIN=~/ksim/current/bin gates/run.sh kaluza` runs the gates from `topologies/aio-lab.yaml`. netd makes `ksim-cucp` with 172.30.30.30 and NG-C goes from there to 172.30.30.1:38412; from N10 `ksim-cuup` with 172.30.30.31 for N3; from N11 each UE's `ksim-ue-<n>` with a TUN per session (W1: `DN_ADDR=172.30.61.1`, and `IMS_ADDR=172.30.63.10` for the ims session, which kaluza-core routes out VLAN 63 to the P-CSCF). The gates release every PDU session before a UE de-registers, so no PFCP session is left on the V-UPF (row KS-PLAT-B28).
  5. Afterwards, check that `ip netns list` shows no `ksim-` namespace. `ksim stop` tears it down; `ksim-netd`'s gc covers a run that died.
- **The Open5GS rig (D5, ADR 0010).** A control run follows the same steps each time, all from the dev PC, inside a window agreed with the active kaluza-core session:
  1. `ksim-sim range provision --target open5gs --block … --ssh amadeus-open5gs`. The subscribers get a session per DNN, `internet,ims` by default (N17).
     - `--pcc-gbr 1000` (P2 Q13, D2) adds a GBR PCC rule to the first DNN's session: 5QI 1, GFBR 1000 kbit/s and MFBR 2000 each way, for ICMP with 10.55.0.1. The fork's PCF puts it in the SM policy and its SMF adds the flow to the session. Only the GBR row's UE (`QOS2_UE`, 7) gets it, re-provisioned with `--replace` for a run of `ksim-p2-qos2.sh` alone with `QOS2_PCC_GBR=1`, so the other rows see plain subscribers.
  2. `tools/open5gs-rig.sh start [--session] [--t3512 N]`. It refuses when any open5gs NF already runs.
     - `--session` adds smfd, and upfd as root (`sudo -n`; the user allowed it on 2026-10-15 for upfd only). upfd makes `ogstun`, which then gets 10.55.0.1/16 and 10.56.0.1/16: our copy's pools, off kaluza-core's 10.45–10.50 (kaluza-core-df).
     - `--t3512 120` sets the periodic rows' timer in our copy.
     - With the dev PC's ksim-netd (N17; `tools/systemd/ksim-netd-devpc.service`, no parent link) the UEs run in netns mode. Each UE gets a namespace with TUNs and nothing on the host side, so no veth and no P-64 flap of vmnet8.
  3. `gates/run.sh open5gs`.
     - Split mode: `KSIM_PHASE=p2 KSIM_TOPOLOGY_FILE=$PWD/topologies/split-open5gs.yaml`.
     - C3, OCUDU's CU-CP and CU-UP against the rig (P2 Q13): `KSIM_TOPOLOGY_FILE=$PWD/topologies/ocudu-c3-open5gs.yaml` with `OCUDU_N2N3_BIND=192.168.134.1` (OCUDU's N2 and N3 from vmnet8; F1 and E1 stay on loopback) and `OCUDU_SLICE_SD=1` (the rig's AMF serves 1-000001 only, and refuses an NG Setup without it).
  4. `tools/open5gs-rig.sh stop`. It stops upfd as root too, deletes `ogstun` and `ogstun-edge`, and checks that no NF and no `ogstun` are left.
  5. `ksim-sim range deprovision …`, then remove the NF logs in `~/kaluza-sim-rig/log`, since debug logs can hold the subscribers' key material. Since P2 Q3 `tools/open5gs-rig.sh stop` removes them itself once no NF is left (`LOGS_LEFT=0`).
  6. Tell the core session what was left.

  The NF set is nrfd, scpd, ausfd, udmd, udrd, pcfd, bsfd, nssfd and amfd; smfd and upfd come only with the session runs.
  The rig copy `~/kaluza-sim-rig/etc` differs from `install/etc/open5gs` in four ways, recorded in `tools/open5gs-rig.sh`:
  - its log paths;
  - loopback SBI addresses for nrf, ausf, udm and nssf, because the 5gc FQDNs don't resolve on the rig;
  - the AMF's NGAP on vmnet8 only;
  - NSAC off.

  Subscribers are provisioned with `security.auth_method` 1 (5G AKA), since the fork's UDR defaults to EAP-TTLS without it.
- **CPU.** The 4 vCPUs are shared with UERANSIM and n3iwue when those run, and with whatever else the Proxmox host is doing.
  - kaluza-sim needs no real-time pinning, since its L2 is ideal.
  - Its loop-lag watchdog makes a run ABORT, not FAIL, under contention.
  - **P2 measures the performance targets here** (Q15, window LW3, against the scripted core inside the VM). If they miss, resizing VM 105 is your decision then.

## 7. Real cards: the card bridge

- **Setup.** The OmniKey 3x21 stays on the dev PC, with the existing pcscd, polkit rule and `udevadm trigger -c add` setup (`/home/amadeus/.claude/projects/-home-amadeus-Development-ran/memory/pysim-setup-ran.md`).
- **The bridge.** `ksim-sim serve --pcsc --reader <n> --listen <dev PC address>:35970 --allow 192.168.0.139` exposes one card using the vpcd framing (a 2-byte length, then the APDU; 1-byte control codes for power, reset and ATR).
- **The UE side.** In the VM, the UE uses its `Vpcd` transport in the terminal role and connects to the bridge ([`sim-uicc.md`](sim-uicc.md) §5).
- **Path.**
  - The default is the management LAN: today the dev PC is 192.168.0.8 on `wlo1` (Wi-Fi) and the VM is 192.168.0.139.
  - If Wi-Fi jitter shows in AKA timings, listen on VLAN 30's 172.30.30.1 instead (wired). Run pcaps then carry the bridge's TCP, so filter port 35970.
- **Safety.**
  - Only APDUs cross the bridge; **K never leaves the card.**
  - The bridge binds one address and accepts only the VM's.
  - It refuses administrative commands (VERIFY ADM1, writes to AF20/AF30) unless started with `--admin`. Burning a card stays your action.
- **Cost.** About 1–5 ms per APDU. An authentication takes a handful of APDUs, well inside NAS timers.
- **As built (P2 Q1):** `ksim-sim serve --pcsc <reader> --listen <address>:35970 --allow <VM address>`, one client at a time. A UE on the VM names it with `card: {bridge: <dev PC address>:35970}` and must be the only UE of its group. The real card is a spare sysmoISIM that you burn as imsi-001010000300100 with `ksim-sim burn` (decision D3, sim-uicc.md §5). Its subscriber is provisioned on kaluza-core through the API after telling the core session; that is window LW4.

## 8. Open lab items

kaluza-core answered the open items on 2026-10-14, and the user decided the three that were theirs the same day.

| Item | Who | Status (2026-10-14) |
|---|---|---|
| Record 172.30.30.30–.39 (kaluza-sim) in `lab-relayout.md`'s VLAN 30 table | a kaluza-core session | Checked free in every repo and live. User's go given; core records it |
| Move kaluza-gnb2's example address from .11 to .12 in the phase-3 plan | a kaluza-core session | User's go given; core edits it |
| V-UPF `PLANE_NEIGHBOURS` entries for .30–.39 (a V-UPF roll, §4) | a kaluza-core session | **Done** 2026-10-14, 15:59 KST |
| kaluza-sim's own Keycloak client, exempt from key-entry step-up, plus an mTLS client certificate ([ADR 0008](adr/0008-subscriber-provisioning-api.md)) | a kaluza-core session | **Done** 2026-10-14, 16:11 KST: `kaluza-sim-key-entry`, credentials in `~/.config/kaluza-sim/provisioning/` |
| Import the sim subscriber ranges | 001/01: kaluza-sim, through the UDR's provisioning API. 999/70: kaluza-sim writes the seed file; a kaluza-core session merges it and rolls the home UDR in a window ([`sim-uicc.md`](sim-uicc.md) §8) | 001/01 at P1; 999/70 before the first roaming scenario |
| Lab windows | ask the core session | At P1; P2's LW1–LW5 (§6) |
| A second TAC served by the AMF (000007), for mobility-registration rows | a kaluza-core session | Comes with wave 40, before P3 needs it |
| SUCI Profile A/B key ids for the sim cards | your decision | When P1 reaches its SUCI rows; the null scheme until then |
| The SMF's `ims` pool (10.49.0.0/24) holds about 250 concurrent IMS sessions | a kaluza-core session, if ever needed | Enough for v1's ~100 UEs. A 1000-UE `ims` run needs a bigger pool |
| Measure kaluza-uesim against the performance targets (P2); resize only if they miss | P2 Q15, then your decision | Open. Calibration on the dev PC at P2 Q0: 100 UEs register with a session each in 1.4 s at 45 MB (KS-PLAT-T48) |

**kaluza-core-df's answers for P2 (2026-10-15 ~21:50 KST):**

| Topic | Answer |
|---|---|
| Schedule | No core set planned in the next days; W5/39A undated, no freeze announced; a full-lab roll and set (~5 h) would be announced |
| OCUDU pin | `d9d2263f4d` (`ran/ocudu-fork`), built from an exported tree in our own directory, x86-64-v3; never built in `ran/ocudu-fork` |
| OCUDU at .36/.37 against kaluza-core | No AMF change: NG Setup has no allow-list and TAC 000001 is served; gNB ID 0x1A1/22 collides with nothing; .36 and .37 are V-UPF neighbours. One RAN at a time |
| 100 UEs | Fine in a window: the `internet` pool is 10.45/16, no SMF or eUPF cap near 100, PostgreSQL at 113/400 connections. 10 attaches in parallel; release every session and switch every UE off at the end; tell df the start and end |
| Throughput | Fine inside the VM against our scripted core on 127.0.0.x; agreed as a window, since gates run UERANSIM/n3iwue there |
| UP security | The SMF sends no Security Indication and ignores `upSecurity`, so every session takes the gNB's default (a core gap, TS 23.501 §5.10.3; an SMF change is the user's call) |
| GBR and RQI | No GBR path for a sim subscriber without IMS; the SMF refuses reflective QoS while eUPF sends RQI 0 (register QS-G). Those rows run on the stub (GBR also on Open5GS) |
| NAS algorithms | The AMF prefers NEA 2,1,0 and NIA 2,1,0, with no NEA3/NIA3 |
| Real cards | No spare card in kaluza-core's UDR; a card the user burns as imsi-001010000300100 (our range) is provisioned through the API after telling df |
| netd on the VM | A bridge and veths inside kaluza-uesim are fine (P-64 hits only the dev PC's VMware guests); 10.250.0.0/24 is unused; keep `ksim-mid` uplink-free and off `ens19` |

**The user's P2 decisions on the lab (2026-10-15):** OCUDU runs on the dev PC (loopback, never while a B220 cell runs) and on the VM inside our namespaces (D4). kaluza-sim installs `ksim-netd` on kaluza-uesim inside agreed windows; the user installs it on the dev PC (D6). kaluza-sim may `apt install` iperf3 on the VM, plus exactly the libraries the deploy's ldd check names for `ocucp`/`ocuup`, each recorded here (D7).
