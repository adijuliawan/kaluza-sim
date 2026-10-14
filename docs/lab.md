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
- **Deploy:** `tools/deploy-uesim.sh` rsyncs to `kaluza-uesim:~/kaluza-sim/<git-describe>/` and switches a `current` symlink:
  - the `apps/` binaries;
  - `topologies/`, `personas/`, and the card *templates*;
  - never secrets.

  Old versions are pruned, keeping the last three.
- **Secrets** (sealed card secrets, the range master secret) are streamed separately into a 0600 path, never printed, and verified by checksum. That is kaluza-core's practice for lab secrets.
- **The provisioning credentials** (the Keycloak client `kaluza-sim-key-entry`'s secret and its mTLS client certificate, [ADR 0008](adr/0008-subscriber-provisioning-api.md)) stay on the dev PC in `~/.config/kaluza-sim/provisioning/` (0700/0600). They are never deployed to the VM. The 999/70 seed file (`~/.config/kaluza-sim/seed/`) stays there too. Provisioning runs from the dev PC only ([`sim-uicc.md`](sim-uicc.md) §8).
- **Run directories** (`~/kaluza-sim-runs/<ts>/`: logs, pcaps, manifest) are pruned by age, because of the small disk.

## 6. Running alongside UERANSIM and the core's gates

- **Lifecycle.** `ksim run -c topologies/<file>.yaml --run-dir …` starts a systemd unit, so the run survives SSH loss. `ksim stop` ends it. Stop with `pkill -x` only, never `pkill -f`.
- **One RAN at a time.** UERANSIM and kaluza-sim stay installed side by side, but **only one runs against the core in a given gate window.**
  - kaluza-sim uses its own IMSI range (`001010000300000…`), addresses and gNB IDs, so a crossed run can't corrupt the other's subscribers.
  - A gate that counts NG associations or RAN UEs would still see both.
- **Windows.** Runs happen in windows agreed with the kaluza-core session: never during another session's set, never during a UPF-VPP W5 scoring freeze.
  - Since kaluza-core-e9 ended there is no standing coordinator: kaluza-sim agrees each window with whichever kaluza-core session is active, and asks the user when none is (P1 working agreement, 2026-10-15).
  - P1's windows: **W0** (N9) imports imsi-001010000300000..099 through the provisioning API, then NG Setup, registration of 1–3 UEs, AS SMC and deregistration; **W1** (N11) sessions, a ping to the DN, an MTU probe, two sessions; **W2/W3** (N18) the full P1 row set. The sub-blocks of that import: 000–049 default, 050–059 SMS (`smsSubscribed` true), 060–069 `subsRegTimer` 120 s (each re-registers every 2 min while registered, so they stay out of rows that count AMF log lines), 070–079 EAP-AKA′, 080–099 spare.
- **The dev-PC guard.** The real AMF listens on the dev PC itself (172.30.30.1:38412), so `ksim` refuses any peer in 172.30.0.0/16 unless it runs with `--lab` on `kaluza-uesim`, and the scripted core binds 127.0.0.x only ([ADR 0009](adr/0009-p1-runtime-shape.md), point 11). vmnet8 (192.168.134.0/24, host-only) is allowed for the Open5GS control.
- **W0 and later lab runs (P1 N9).** Steps 1–3 run once per release or provisioning change:
  1. `tools/deploy-uesim.sh --window-agreed --secrets` installs a release under `~/ksim/releases` and sends the sealed cards and the KEK.
  2. The user installs `ksim-netd` as root with the commands the script prints. The binary goes to `/usr/local/sbin`, and `tools/systemd/ksim-netd.service` serves the user's uid with ipvlans on `ens19` and 172.30.30.30–.39/24 only.
  3. `ksim-sim range provision --target kaluza --block 001010000300000/100 …` runs from the dev PC, after the core session has checked a `--dry-run`.
  4. On the VM, `KSIM_LAB=1 KSIM_BIN=~/ksim/current/bin gates/run.sh kaluza` runs the gates from `topologies/aio-lab.yaml`. netd makes `ksim-cucp` with 172.30.30.30, and NG-C goes from there to 172.30.30.1:38412.
  5. Afterwards, check that `ip netns list` shows no `ksim-` namespace. `ksim stop` tears it down; `ksim-netd`'s gc covers a run that died.
- **The Open5GS rig (D5, ADR 0010).** A control run follows the same steps each time, all from the dev PC, inside a window agreed with the active kaluza-core session:
  1. `ksim-sim range provision --target open5gs --block … --ssh amadeus-open5gs`.
  2. `tools/open5gs-rig.sh start`. It refuses when any open5gs NF already runs.
  3. `gates/run.sh open5gs`.
  4. `tools/open5gs-rig.sh stop`. It checks that no NF and no `ogstun` are left.
  5. `ksim-sim range deprovision …`, then remove the NF logs in `~/kaluza-sim-rig/log`, since debug logs can hold the subscribers' key material.
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
  - **P2 measures the performance targets here.** If they miss, resizing VM 105 is your decision then.

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

## 8. Open lab items

kaluza-core answered the open items on 2026-10-14, and the user decided the three that were theirs the same day.

| Item | Who | Status (2026-10-14) |
|---|---|---|
| Record 172.30.30.30–.39 (kaluza-sim) in `lab-relayout.md`'s VLAN 30 table | a kaluza-core session | Checked free in every repo and live. User's go given; core records it |
| Move kaluza-gnb2's example address from .11 to .12 in the phase-3 plan | a kaluza-core session | User's go given; core edits it |
| V-UPF `PLANE_NEIGHBOURS` entries for .30–.39 (a V-UPF roll, §4) | a kaluza-core session | **Done** 2026-10-14, 15:59 KST |
| kaluza-sim's own Keycloak client, exempt from key-entry step-up, plus an mTLS client certificate ([ADR 0008](adr/0008-subscriber-provisioning-api.md)) | a kaluza-core session | **Done** 2026-10-14, 16:11 KST: `kaluza-sim-key-entry`, credentials in `~/.config/kaluza-sim/provisioning/` |
| Import the sim subscriber ranges | 001/01: kaluza-sim, through the UDR's provisioning API. 999/70: kaluza-sim writes the seed file; a kaluza-core session merges it and rolls the home UDR in a window ([`sim-uicc.md`](sim-uicc.md) §8) | 001/01 at P1; 999/70 before the first roaming scenario |
| Lab windows | ask the core session | At P1 |
| A second TAC served by the AMF (000007), for mobility-registration rows | a kaluza-core session | Comes with wave 40, before P3 needs it |
| SUCI Profile A/B key ids for the sim cards | your decision | When P1 reaches its SUCI rows; the null scheme until then |
| The SMF's `ims` pool (10.49.0.0/24) holds about 250 concurrent IMS sessions | a kaluza-core session, if ever needed | Enough for v1's ~100 UEs. A 1000-UE `ims` run needs a bigger pool |
| Measure kaluza-uesim against the performance targets (P2); resize only if they miss | P2, then your decision | Open |
