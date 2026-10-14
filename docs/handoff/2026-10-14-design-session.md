# Handoff: design session, 2026-10-14

The resume point for the next kaluza-sim session. The session that wrote it ran from `~/Development/ran`. Sessions now start in `~/Development/kaluza-sim`, so everything needed is here, in the docs it links to, or in the seeded project memory.

## 1. Where things stand

- **Done:** requirements and architecture, decided with the user. This repo was initialised (`git init -b main`, origin `ssh://git@ssh.github.com:443/adijuliawan/kaluza-sim.git`), and the docs were written.
- **Committed and pushed** at the user's request: `15508d9` (the docs), then this link commit. No code exists yet.
- **A private review page** summarises the docs: https://claude.ai/artifact/DdYiFQqkbaC8kaMCn4ft95.
  - The source HTML from this session is not in the repo.
  - To update it, read the artifact (`Artifact` action `read`), then republish with `url=` so the link stays the same.
  - The repo wins where they differ.
- **Next:** build phase **P0** (§6), once the user says go. Their standing rule: an approved plan is not a start signal, and phases are never chained on our own.
- **The approved plan** that produced these docs is `/home/amadeus/.claude/plans/use-this-as-root-composed-blossom.md`. It is a local file outside the repo; these docs supersede it.

## 2. Decisions and why

| Decision | Why |
|---|---|
| **Fidelity first.** Up to about 100 UEs with full stacks; a 10k+ load mode comes later. | The core's defects show up as protocol behaviour, not load. UERANSIM's leniency is the gap. |
| **v1 = baseline.** Registration (initial, mobility, periodic); 5G AKA and EAP-AKA′; SUCI (null, Profile A, Profile B); PDU sessions and QoS including GBR; Xn and N2 handover; CM-IDLE with paging and service request; deregistration (UE- and network-initiated); SMS over NAS. | The user chose to put every extra family into phase 2. |
| **RRC_INACTIVE in v1.x (P3b)**, straight after the v1 handover milestone. | It is wave 40's step 4. Only the OnePlus and the RM520N can show it on air, and its failure paths can't be forced there. |
| **Phase 2 starts with positioning** (LPP/NRPPa from true positions), then IMS UA, E2 + O1, non-3GPP, full L2. | To land with wave 41 (LMF + GMLC). |
| **C++20 with asn1c.** | The Rel-19 asn1c route is proven on this machine (UERANSIM fork, kaluza-ue). OCUDU is C++ and its BSD code is a usable reference. libbpf, pcsc-lite and netopeer2 are native C. |
| **Uu at protocol fidelity in v1.** Real RRC, PDCP and SDAP over an ideal RLC/MAC link, with a radio model. | PDCP with the core's keys checks K_gNB, NH and NCC, which UERANSIM never did. RLC/MAC detail barely changes what the core can see. |
| **Our own O-CU-CP, O-CU-UP and O-DU**, with OCUDU as an interop peer and reference. | Rel-19, independence, room for fault injection. OCUDU is Rel-18, has no UE, and its test-mode UEs never reach the CU. |
| **Private for now; clean room.** Nothing copied from AGPL (UERANSIM), GPL (onomondo-uicc) or CSSL (OAI/Duranta) code. BSD (OCUDU) and Apache-2.0 (PacketRusher) code may be copied with attribution. | Keeps the option to open it later. |
| **Independence from kaluza-core.** No core code or tables. Values produced by the core's own encoders are never used as expected results. | A test catches a misreading only if the two sides were built separately. Three cases already happened: K_AMF fed the `imsi-` spelling, null-scheme SUCI as BCD hex, and NGAP N-20. ADR 0005 has the details. |
| **Dedicated test subscriber range** (user, 2026-10-14). | Avoids colliding with the seed and the phones. Keys come from one master secret (`docs/sim-uicc.md` §8). |
| **The P1 exit also runs against the Open5GS fork core**, the same control the gates use. | A brand-new sim needs a second core to tell which side is wrong, and to avoid being tuned to kaluza-core. |
| **An optional AT port (P3c)** speaking TS 27.007/27.005 plus a Quectel subset. | The user's modem scripts and lpac's AT backend could drive simulated RM520N/RG255C personas. |
| **Lab host: kaluza-uesim (VM 105) as it is.** kaluza-sim takes 172.30.30.30–.39, one ipvlan netns per RAN node. Builds run on the dev PC with an `x86-64-v3` + AES target and are deployed to the VM ([`../lab.md`](../lab.md)). | The gates already point there, and the VM has SCTP, TUN, AES and VAES. Its disk (11 GB free) is too small for build trees. P2 measures its performance before any resize. |
| **Real cards through a card bridge on the dev PC.** | The OmniKey stays where pySim is set up, and K never leaves the card. |

## 3. kaluza-core context

kaluza-core is a Java 25 / Quarkus 5G core, Rel-19.
- **Phase 2:** closed 2026-10-13 with tag `phase-2`. The final set `phase-2-final` scored 2854 passed / 0 failed / 38 skipped. The lab runs core `963130e1` native with eUPF `75d3202`.
- **Phase 3, "5G-Advanced":** starts with the UPF-VPP block (39A–D). Then mobility (40), 5G-EIR (F5), LMF and GMLC (41), URSP (42), Edge, NEF (31), 5G LAN (46), NPN (47), HPLMN breakout (49), MonSTra (50) and dual-stack (51).
- **Phase 4:** a standalone private SNPN.

**Where to read about it:**

| What | Where |
|---|---|
| Architecture (pinned artifact) | https://claude.ai/artifact/G7R9ncax32UQPxgHH1dK9p, and `/home/amadeus/Development/kaluza-core/docs/architecture.md` |
| Phase-3 plan (living artifact) | https://claude.ai/artifact/CLCFoe7XUwFWo3zeWiMjED. The repo file `/home/amadeus/Development/kaluza-core/docs/phase-3/README.md` is the source of truth. |
| The 11 defects a real UE found and UERANSIM missed | `/home/amadeus/Development/kaluza-core/docs/compliance/ran/README.md` §3 |
| Gate harness | `/home/amadeus/Development/kaluza-core/misc/gate/{kaluza-deploy.sh,run-set.sh,crosswalk.py}`, plus `misc/<nf>/verification/kaluza-*.sh` |
| Parity baseline (rows) | `/home/amadeus/Development/kaluza-core/docs/compliance/smf/phase-2/rows-k3s-963130e1-native-eupf-75d3202.tsv` |
| Lab layout | `/home/amadeus/Development/kaluza-core/docs/phase-2/lab-relayout.md` (§2–§3; don't renumber §7, it is cited) |
| Local Rel-19 specs | `/home/amadeus/Development/kaluza-core/docs/3gpp/ts/<series>/*.zip`. We read them; they are not ours to copy into git. |

**Lab facts the sim needs:**
- **VLAN 30 172.30.30.0/24:**
  - AMF N2 is .1:38412; the V-UPF N3 is .2; the OCUDU gNB N3 is .10.
  - **.11 is the N3IWF DNAT alias.** The phase-3 plan's example address for kaluza-gnb2 clashes with it; flagged to the user.
  - kaluza-uesim is .20, where UERANSIM and n3iwue run. Its aliases .21–.23 carry n3iwue multi-UE runs and UERANSIM's handover-target gNB.
  - **kaluza-sim takes .30–.39** (decided 2026-10-14, after the first draft's .21–.29 was found to collide). The full lab plan is [`../lab.md`](../lab.md).
- **DN:** 172.30.61.1, the dev PC on VLAN 61, used for iperf3 and ping.
- **IMS** sits on VLAN 63: P-CSCF at .10, RTPEngine at .11.
- **UE host:** `kaluza-uesim`, Proxmox VM 105, Ubuntu 26.04, reached with `ssh kaluza-uesim`. Kernel, CPU and memory are to be measured at P0.

## 4. Research summary (details in `docs/research/`)

| Topic | One-line result | File |
|---|---|---|
| OCUDU | srsRAN Project renamed. BSD licence, Rel-18 ASN.1, separate `ocucp`/`ocuup`/`odu` over real F1/E1/Xn/N2/E2. No UE, no O1. FAPI split-6 plugin seam ships only dummy plugins. | [ocudu.md](../research/ocudu.md) |
| duranta-ran | OAI renamed under LF "Duranta". CSSL licence (research and testing only). Full NR UE at Rel-16/17; NGAP Rel-15. rfsim, vrtsim and ZMQ; OCUDU gNB + OAI nrUE over ZMQ in its CI. | [duranta-oai.md](../research/duranta-oai.md) |
| UERANSIM fork | AGPL. asn1c 18e56503 builds Rel-19 v19.3.0 RRC/NGAP/F1AP/E1AP. No PDCP/RLC/MAC, partial RRC, custom Xn, YAML SIM. 6–8 threads per UE. | [ueransim-fork.md](../research/ueransim-fork.md) |
| PacketRusher | Go, Apache-2.0. TUN per UE plus TCX eBPF GTP-U, about 3.4/4.7 Gbit/s per UE. No RRC; one QFI per session; host network namespace. | [packetrusher.md](../research/packetrusher.md) |
| SIM tooling | No open soft card with DF.5GS, GET IDENTITY and TUAK. pySim is the oracle. sysmoISIM cards plus an OmniKey PC/SC reader are on hand. | [sim-tools.md](../research/sim-tools.md) |
| Quectel material | RM5x0N and RG255C AT manuals (confidential: cite by path only) and the firmware images. SNPN is compiled in, with no AT command for it. | [quectel.md](../research/quectel.md) |

## 5. Open items

1. **Importing the sim subscriber range into the core.** `ksim-sim` writes a 0600 seed fragment, and a kaluza-core session imports it. This repo never edits kaluza-core. Real cards keep the core's "K/OPc typed by a person" rule.
2. **Adopting the gate contract** (`docs/verification.md` §6) is a kaluza-core session's call.
3. **The .11 address clash** in the phase-3 plan. The user was told; the core and RAN sessions still need to hear it.
4. **O-RAN specs** (E2AP, E2SM-KPM/RC, O1, WG4/WG5) need the user's O-RAN registration. Only phase 2 needs them.
5. **Side finding for the user:** `/home/amadeus/Development/ran/usim/2026-09-21-test-sims.md` (around line 172) holds an ADM1 PIN in clear text. Never print it.
6. **Measured 2026-10-14:** kaluza-uesim has 4 vCPU, 8 GB and Linux 7.0.0-34 ([`../lab.md`](../lab.md) §2). P2 checks the performance targets there.
7. **Recording 172.30.30.30–.39 (kaluza-sim) in kaluza-core's `lab-relayout.md`** is a kaluza-core session's job.
8. **A second TAC served by the AMF**, for mobility-registration rows in P3, is a kaluza-core session's job.

## 6. First steps of P0 (only after the user's go)

1. **Fetch specs.** Put the "to fetch" set from `docs/specs.md` into `spec/3gpp/` (gitignored). The archive refuses curl's default User-Agent, so send a browser one. Record the sha256 values in `spec/INDEX.tsv`.
2. **Build asn1c.** mouse07410/asn1c at commit **18e56503**; it is BSD-2 and may be built and its runtime vendored.
   - Neither the fork's HEAD nor stock asn1c 0.9.29 works for Rel-16+ NGAP/F1AP/RRC. HEAD dies on parameterized containers; stock cannot parse `[[ ]]` CHOICE brackets. Facts from `/home/amadeus/Development/UERANSIM/tools/README-asn1.md`; read it, don't copy it.
   - `/opt/asn1c` (v0.9.29) is the build kaluza-ue uses for RRC with JER. Check its commit before relying on it for APER.
3. **Write our own `spec/tools/docx_asn1.py`,** clean-room.
   - It must handle the docx traps: `<w:tab/>` as a sibling of `<w:t>`, and `<w:br/>` as a newline.
   - Extract RRC with `NR-InterNodeDefinitions`, NGAP, F1AP, E1AP (TS 37.483) and XnAP.
   - Post-process the encoding-constraint guards with our own tool.
4. **Generate one static library per protocol,** with stamp-cached generation and per-protocol `files.cmake` manifests. Gate the build behind CMake presets. Install clang and ccache, which are not on the dev box yet.
5. **NAS:** write `docx_tables.py` for TS 24.501 j80, then `nasgen`. For reference only, the user's own `/home/amadeus/Development/ran/kaluza-ue/tools/gen-nas-tables.py` read 24.501 v19.7.0. It is not kaluza-core code and may be studied.
6. **Crypto with KATs:** Milenage (35.208), TUAK (35.233), MILENAGE-256 (35.236), ECIES (33.501 C.4), NEA/NIA (33.401 Annex C, the SAGE documents, 35.223).
7. **Oracle harnesses.** tshark is 4.6.4; feed it pcaps on stdin, because AppArmor blocks paths under `~/Development`. Install pycrate in a venv, since it isn't installed. pySim is at `/home/amadeus/Development/ran/usim/pysim-src` with venv `/home/amadeus/Development/ran/usim/.venv-pysim`.
8. **CI guards:** the layer checker, the licence/provenance scanner, the secret canary, and the ban on line-number type names.
9. **Register skeletons** under `docs/compliance/<area>/`, in kaluza-core's style. Coverage counts come from the specs, never typed by hand.

P0's exit: every v1 PDU type round-trips and matches tshark and pycrate, and all KATs pass.

## 7. Dev-box facts (2026-10-14)

| Item | Value |
|---|---|
| Kernel | Linux 7.0.0-34 |
| CPU and memory | 24 threads, 61 GiB |
| Compilers | gcc/g++ 15.2.0; **no clang, no ccache** |
| Build tools | CMake 4.2.3; ninja 1.13.2 |
| Libraries | OpenSSL 3.5.5; libbpf-dev 1.6.3; libpcsclite-dev 2.4.1; libsctp-dev/lksctp-tools 1.0.21; libyaml-cpp 0.8.0; libgtest 1.17.0 |
| pcscd | present. The OmniKey reader needs `udevadm trigger -c add` after a udev reload. |
| Tools | tshark 4.6.4; Python 3.14.4; **pycrate not installed** |
| asn1c | `/opt/asn1c` (v0.9.29, commit unknown); 18e56503 **not installed** |

**Lab rules:**
- No big reads (wc, grep or cat on files over 100 MB) while a B220 cell is running.
- `pkill -x`, never `pkill -f`.
- Never edit a gate script while it runs.
