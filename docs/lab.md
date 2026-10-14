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
| .2 | V-UPF N3 (VF) |
| .10 | OCUDU gNB (B220) |
| .11 | DNAT alias for the N3IWF gate's NAT rows. The phase-3 plan's example address for kaluza-gnb2 clashes with it |
| .20 | kaluza-uesim: UERANSIM gNB, n3iwue IKE |
| .21–.23 | kaluza-uesim aliases: n3iwue multi-UE runs, UERANSIM's handover-target gNB |
| **.30–.39** | **kaluza-sim RAN nodes.** Proposed; a kaluza-core session records the block in `lab-relayout.md` |

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
- TACs must be ones the AMF serves. A second TAC for mobility-registration rows needs core configuration (open item, §8).

## 4. Network plumbing (the VM's netplan is not touched)

- **Per-node namespaces.** At run start, `ksim-netd` creates a netns per RAN node (`ksim-<run>-<node>`). Each gets an **ipvlan (L2 mode) child of `ens19`** carrying the node's .30–.39 address.
  - ipvlan shares `ens19`'s MAC, so the Proxmox bridge and any MAC filtering see nothing new.
  - In L2 mode, ipvlan children cannot reach the parent's own addresses (.20–.23), and kaluza-sim never needs to.
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
- **Run directories** (`~/kaluza-sim-runs/<ts>/`: logs, pcaps, manifest) are pruned by age, because of the small disk.

## 6. Running alongside UERANSIM and the core's gates

- **Lifecycle.** `ksim run -c topologies/<file>.yaml --run-dir …` starts a systemd unit, so the run survives SSH loss. `ksim stop` ends it. Stop with `pkill -x` only, never `pkill -f`.
- **One RAN at a time.** UERANSIM and kaluza-sim stay installed side by side, but **only one runs against the core in a given gate window.**
  - kaluza-sim uses its own IMSI range (`001010000300000…`), addresses and gNB IDs, so a crossed run can't corrupt the other's subscribers.
  - A gate that counts NG associations or RAN UEs would still see both.
- **Windows.** Runs happen in windows agreed with the kaluza-core session: never during another session's set, never during a UPF-VPP W5 scoring freeze.
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

| Item | Who |
|---|---|
| Record 172.30.30.30–.39 (kaluza-sim) in `lab-relayout.md`'s VLAN 30 table | a kaluza-core session |
| A second TAC served by the AMF, for mobility-registration rows (P3) | a kaluza-core session |
| Import the sim subscriber range (`ksim-sim range seed`) | a kaluza-core session |
| The .11 clash (kaluza-gnb2's example address) | core and RAN sessions |
| Measure kaluza-uesim against the performance targets (P2); resize only if they miss | P2, then your decision |
