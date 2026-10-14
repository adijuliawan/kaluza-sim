# Roadmap

**Size scale** (kaluza-core's): **S** a filler, **M** a single-NF wave, **L** a multi-NF wave with new codecs.

**Rules:**
- **Every phase starts only on the user's explicit go**, and phases are never chained.
- Each phase closes like a kaluza-core wave: exit criteria met, registers current, findings handed off. Commits and pushes happen only when the user asks.

## Phases

| Phase | Scope | Exit criteria | Size |
|---|---|---|---|
| **P0** Spec intake, codecs, skeleton | See the P0 list below | Every v1 PDU type round-trips and matches tshark and pycrate; all KATs pass; no ASN.1 construct unhandled | M |
| **P1** UE, soft UICC and NAS over an all-in-one gNB | See the P1 list below | Registration, session, idle, paging, deregistration and SMS scenarios pass against kaluza-core, **and the same scenarios run against the Open5GS fork core** on the rig VM (differences triaged against the spec; known Open5GS deviations on an allow-list). NULL AS security is allowed **only** in this milestone. First KF findings handed to kaluza-core | L |
| **P2** O-RAN split and AS security | Separate `ksim-du`, `ksim-cucp` and `ksim-cuup` over real SCTP/UDP F1-C, F1-U and E1. PDCP with NEA/NIA 1–3; UP security policy. SDAP with reflective QoS. GBR flows. 100 UEs. PC/SC backend for real cards | OCUDU F1/E1 interop rows pass (our DU with OCUDU `ocucp`/`ocuup`); the performance targets of [`requirements.md`](requirements.md) §3.5 met on kaluza-uesim | L |
| **P3** Mobility, radio model, idle → **v1 release** | See the P3 list below | **v1:** wave 40 steps 1–2 testable without radio; multi-hop handover keys proven (A→B→C→A); Xn handover against OCUDU's CU-CP; packet loss across handover measured | L |
| **P3b** RRC_INACTIVE (**v1.x**) | Suspend and resume; RNA update; RAN paging; Retrieve UE Context (Xn); RRC Inactive Transition Report; CN assistance information; CN-paging fallback; T319; the resume keys of TS 33.501 §6.8.2 | Wave 40 step-4 rows, including failure paths | M |
| **P3c** AT port (**v1.x**, optional) | TS 27.007/27.005 on a pty or TCP per UE; +CSIM/+CGLA passthrough to the card; a Quectel subset for the RM520N and RG255C personas ([`cli.md`](cli.md) §6) | The user's modem scripts and lpac's AT backend drive a simulated RM520N persona unchanged | S–M |
| **P4** Gate parity (**v1.x**) | IPv6 and IPv4v6 with SLAAC; NSSAA; PDU session authentication (EAP/PAP/CHAP); SMS test hooks; Reroute NAS; Overload; the final gate contract; `tools/crosswalk.py` | The crosswalk across the 23 gates' 1,633 rows has **0 rows unaccounted** ([`verification.md`](verification.md) §4) | M |
| **P5** Phase-2 families | **Positioning first** (LPP + NRPPa from ground truth, for wave 41; [ADR 0007](adr/0007-positioning-first-in-phase-2.md)). Then IMS UA, E2 + O1, non-3GPP access and full L2, in an order decided later | Each family has its own exit criteria | L each |
| **Later** | eBPF express/scale mode (10k+ UEs); FAPI bridge to an OCUDU DU; URSP; Ethernet/5G LAN; SNPN with EAP-TLS/TTLS; dual-stack transport (NG over IPv6); ATSSS; eUICC (SGP.22/SGP.32); USAT | — | — |

**P0 scope:**
- **Spec intake:** the pins and `spec/INDEX.tsv` ([`specs.md`](specs.md)).
- **asn1c:** mouse07410 at 18e56503, built and pinned.
- **Clean-room extractors:** `docx_asn1.py` (RRC including `NR-InterNodeDefinitions`, NGAP, F1AP, E1AP, XnAP) and `docx_tables.py` (TS 24.501 j80).
- **Codecs:** one static library per protocol; NAS, SMS, APDU, GTP-U, NR-U and PDU Session Container codecs.
- **Crypto with KATs:** MILENAGE, TUAK, MILENAGE-256, ECIES, NEA/NIA, the 5G KDF chain.
- **Platform:** reactor, shards, timer wheel, log, pcap, `SecretBytes`.
- **Harnesses:** oracle (tshark, pycrate, pySim) and fuzz.
- **CI guards:** layer checker, provenance scan, secret canary, the line-number type ban.
- **Register skeletons** with derived coverage counts.
- **kaluza-uesim measured:** vCPU, RAM, kernel.

**P1 scope:**
- **Card:** card OS, USIM and DF.5GS over in-process and vpcd transports; pySim-shell reads every EF.
- **UE NAS:** 5GMM and 5GSM (IPv4); SMS over NAS.
- **gNB:** all-in-one (`ksim`), with F1 and E1 encoded over memory; the NGAP core set; GTP-U N3.
- **UE side:** per-UE netns plus TUN; a first `ksim-ctl`; personas v0; IMEISV.

**P1 entry conditions** (on kaluza-core's side, agreed 2026-10-14; [`lab.md`](lab.md) §8):
- The V-UPF holds static neighbour entries for 172.30.30.30–.39. **Done** 2026-10-14 ([`lab.md`](lab.md) §4).
- kaluza-sim's own Keycloak client exists, is exempt from key-entry step-up, and its credentials (secret plus mTLS certificate) are on the dev PC. **Done** 2026-10-14 ([ADR 0008](adr/0008-subscriber-provisioning-api.md)).
- For roaming scenarios (not a P1 exit row): the 999/70 seed file merged by kaluza-core, with the home UDR rolled in a window.
- A lab window is agreed with the core session.

**P3 scope:**
- **Radio:** `ksim-radio` and its replicas; TR 38.901 pathloss; measurements A1–A5; RLF and re-establishment; cell selection and reselection; PLMN selection; paging DRX.
- **Handover:** Xn, N2 and intra-CU, with forwarding, End Marker, RAN status transfer and NH/NCC.
- **Mobility:** mobility registration; several AMFs and NNSF.
- **Tooling:** fault injection, events and metrics.

## Fit with kaluza-core's phase 3

- Wave 40 (mobility) starts after 39A–D, U2 and the second gNB are ready in the lab. **Aim to finish P3 before wave 40's T0**, or at the latest before its step 2. P4's contract work can run alongside P3 if there is capacity.
- Wave 41 (LMF + GMLC) is served by the first phase-2 family (positioning).
- Waves 42, 46 and 47 keep their soft rows on Android, UERANSIM (`ethernet-pdu`, SNPN mode) or n3iwue until the "later" families arrive.

## Risks

| Risk | Mitigation |
|---|---|
| The specs are huge | Scope by procedure list; registers with derived coverage counts; TS 38.523-1 test purposes as an abnormal-case checklist |
| asn1c at Rel-19 is big and has encoding bugs (the UERANSIM fork generated 2,616 NGAP, 5,240 RRC and 3,704 F1AP files; it sized an extensible INTEGER wrong, giving a 3-bit SRBID) | A pinned commit with a tracked patch list; one library per protocol plus ccache; tshark/pycrate cross-decode of every PDU type in CI; asn1c defects recorded as `-S` rows |
| Effort: two stacks plus a card | No feature ahead of a kaluza-core consumer that can measure it; parity (P4) deferred until after v1 |
| PDCP COUNT/HFN mistakes at handover | Spec-row tests, randomized loss/reorder properties, a decipher-sanity metric |
| The ideal L2 hides MAC/RLC-dependent behaviour | `docs/abstraction-ledger.md`; the phase-2 seams are fixed in v1 |
| Shared lab (the kaluza-uesim VM, W5 freezes, B220 sessions, the V-UPF's static neighbours) | Own addresses (.30–.39, checked free by kaluza-core; [`lab.md`](lab.md)); neighbour entries before P1; agreed windows; read-only on kaluza-core except our own subscribers through its API; an ID-collision check at start |
| O-RAN specs need registration to download | The user fetches them; they stay outside the repo; only phase 2 needs them |
| The GSMA SAGE undertaking for SNOW 3G | Held as kaluza-core already holds it |
| Both implementations read a clause the same wrong way | Independent oracles, Open5GS as a control, phone captures, separate sessions for sim and core |
| OCUDU drift | The OCUDU commit pinned per interop row |
