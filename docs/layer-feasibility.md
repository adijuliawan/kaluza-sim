# Layer feasibility: what kaluza-sim simulates, how, and when

**Question (user, 2026-10-14):** looking at OCUDU and duranta-ran, which layers of the 5G NR stack can a UE + RAN simulator for kaluza-core realistically simulate?

**Answer:**
- **Real** from PDCP up, on both the UE and RAN sides, plus every inter-node interface (F1, E1, Xn, NG).
- **Ideal** RLC/MAC in v1, real in phase 2.
- **Abstracted** PHY: a radio model for measurements and coverage in v1; an SINR→BLER abstraction with phase 2's real MAC.
- **No IQ-level radio inside kaluza-sim.** PHY-in-the-loop stays possible outside it, using the OCUDU gNB with OAI's nrUE over ZMQ.

Evidence is in [research/ocudu.md](research/ocudu.md) and [research/duranta-oai.md](research/duranta-oai.md). The decision is in [ADR 0003](adr/0003-uu-protocol-fidelity.md).

## 1. What the core can see, by layer

kaluza-core sees the RAN only through NG (NGAP, GTP-U) and, through it, N1 (NAS). A lower layer matters to core validation only through what it changes at NG/N1:

| Layer | What it changes at the core's edge | Worth simulating for the core? |
|---|---|---|
| NAS | Everything N1: identities, timers, causes, back-off, security | **Yes, fully** |
| RRC | Establishment cause, UE capability, measurement-driven handover (NGAP HO / Path Switch), RRC_INACTIVE (CN assistance, transition report), paging response timing, RLF → UE Context Release Request | **Yes, fully** |
| PDCP | AS security keyed from the core's K_gNB / NH / NCC (a wrong key = SMC failure); lossless handover (SN status → RAN Status Transfer / SN Status Transfer); UP integrity per the core's UP security policy | **Yes, fully** (UERANSIM never checked any of it) |
| SDAP | QFI ↔ DRB mapping of the core's QoS flows; reflective QoS (UPF RQI → UE derived rules) | **Yes, fully** |
| RLC | Throughput and latency under loss (AM vs UM per 5QI), max-retx → RLF | Semantics in v1 (ideal AM/UM/TM); real in phase 2 |
| MAC | RA timing (T300, T304), DRX and paging timing, scheduling latency, BSR-driven UL delay | Timing in v1 (ideal); real in phase 2 |
| PHY | Error rates, coverage, measurement values | Abstracted: geometry → RSRP/RSRQ/SINR in v1; SINR→BLER in phase 2 |
| RF / IQ | Nothing the core sees directly | No (outside kaluza-sim) |

## 2. Verdict per layer and interface

| Layer / interface | Reference on disk | kaluza-sim | When |
|---|---|---|---|
| RF, low PHY (IQ, OFDM, PRACH detection) | OCUDU `lib/phy/lower`, `lib/radio/zmq`, `lib/radio/plugin_radio_factory.cpp`; OAI `radio/rfsimulator`, `radio/vrtsim`, `radio/zmq` | **Not simulated.** §4 covers PHY-in-the-loop | out |
| Upper PHY (LDPC, polar, channel estimation) | OCUDU `lib/phy/upper`; OAI `openair1/PHY` | Abstraction: SINR → BLER per MCS (TS 38.214 MCS tables) | Ph2, with full L2 |
| Open Fronthaul 7.2x, O-RU | OCUDU `lib/ofh`, `apps/examples/ofh/ru_emulator*`; OAI `radio/fhi_72`, `executables/nr-oru.c` | The O-RU is a logical radio unit inside the radio model (site, antenna, power, carrier); no eCPRI on the wire | later (optional M-plane facade) |
| FAPI (SCF 222) | OCUDU `include/ocudu/fapi`, split-6 plugin seam `apps/units/flexible_o_du/split_6/o_du_high/split6_plugin.h` (only dummy plugins ship); OAI `nfapi/open-nFAPI` | Bridge: our UE MAC under a virtual-PHY plugin inside a real OCUDU DU. KAIR v2 frames are shaped like FAPI P7 to make it a translation | later |
| **MAC** | OCUDU `lib/mac`, `lib/scheduler` | **v1 ideal:** RA as a timed exchange with real contention; C-RNTI; paging occasions (TS 38.304 §7.1); DRX timing. **Ph2 real:** RA, HARQ, scheduler, BSR/SR/PHR, DRX, TA | v1 / Ph2 |
| **RLC** | OCUDU `lib/rlc` | **v1 ideal:** AM/UM/TM semantics (loss on AM = ARQ delay; on UM/TM = drop; max-retx = RLF). **Ph2:** TS 38.322 entities | v1 / Ph2 |
| **PDCP** | OCUDU `lib/pdcp`, `lib/security` | **Real:** NEA/NIA 0–3, COUNT/HFN, 12/18-bit SN, reordering, status report, re-establishment, data recovery, SN status transfer, forwarding | v1 |
| **SDAP** | OCUDU `lib/sdap` | **Real:** QFI↔DRB, headers, reflective QoS, end marker | v1 |
| **RRC** (UE and CU) | OCUDU `lib/rrc` (CU side, Rel-18 ASN.1); OAI `openair2/RRC/NR_UE` (Rel-16/17) | **Real, Rel-19 ASN.1** (TS 38.331 j40), both sides. INACTIVE in v1.x | v1 |
| **NAS** (UE) | OAI `openair3/NAS/NR_UE` (Rel-16); UERANSIM (hand-coded, R15 badge) | **Real**, TS 24.501 j80 | v1 |
| **UICC / USIM** | pySim (oracle), sysmoISIM cards | **Real APDUs** to a soft card or a real card | v1 (ISIM Ph2) |
| **F1** (F1AP, NR-U), **E1** (E1AP) | OCUDU `lib/f1ap`, `lib/nru`, `lib/e1ap`; separate `ocucp`/`ocuup`/`odu` apps | **Real, Rel-19** (TS 38.473 j40, 38.425 j10, 37.483 j40) between separate processes | v1 |
| **Xn** (XnAP, Xn-U) | OCUDU `lib/xnap` (Rel-18, Xn and conditional HO) | **Real, Rel-19** (TS 38.423 j40) | v1 |
| **NG** (NGAP, GTP-U, PDU Session Container) | OCUDU `lib/ngap`, `lib/gtpu`, `lib/psup` | **Real** (TS 38.413 j40, 29.281 j20, 38.415 j10) | v1 |
| E2 (E2AP, KPM, RC, CCC) | OCUDU `lib/e2` (E2AP v03.00, KPM v05.00, RC v05.00, CCC v06.00); FlexRIC (`/home/amadeus/Development/ran/flexric-build`) and the OSC RIC (`/home/amadeus/Development/ran/oran-sc-ric`) on disk | E2 agents in O-CU-CP / O-CU-UP / O-DU; RC handover control drives deterministic mobility | Ph2 |
| O1 (NETCONF/YANG, VES, PM files) | None in OCUDU; OAI has only an M-plane client towards an O-RU | netopeer2 + sysrepo with TS 28.541 NRM YANG; PM per TS 28.552 | Ph2 |
| NRPPa / LPP | OCUDU `lib/nrppa` (Rel-18), `lib/lpp` (Rel-18); PHY gives UL-RTOA and SRS-RSRP only | Measurements from ground-truth geometry, including AoA (which OCUDU cannot produce) and DL-TDOA RSTD | Ph2, first |

## 3. Why not the alternatives

- **L3 only (UERANSIM's level).** Rejected. It would repeat UERANSIM's blind spot: the core's AS keys (K_gNB, NH/NCC chaining across handovers) are never exercised, and lossless handover can't be tested.
- **Full L2 in v1.** Deferred to phase 2. It slows the first release, and its core-visible effect is mostly timing. The seams (`IRlcBearer`, `IMacSap`, KAIR v2) are fixed now, so it slots in without rewrites ([architecture.md](architecture.md) §2.3).
- **IQ-level PHY inside the sim.** Rejected:
  - it needs a full NR UE PHY (PSS/SSS, PBCH, PDCCH blind decoding, LDPC/polar, PUSCH/PUCCH/PRACH/SRS);
  - the only open one on disk is OAI's nrUE, whose CSSL licence limits the patent grant to research and testing;
  - CPU cost limits it to a handful of UEs;
  - the core sees none of it.
- **Use OCUDU as the RAN and build only the UE.** Rejected for v1 ([ADR 0002](adr/0002-own-oran-nodes.md)):
  - OCUDU is Rel-18 and has no NPN support;
  - its split-6 FAPI wire has no open format;
  - its test-mode UEs never reach the CU-CP or the AMF;
  - it gives no hooks for RAN-side fault injection.

  Kept for later as the FAPI bridge, and as an interop peer from P2.

## 4. PHY-in-the-loop, outside kaluza-sim

When a PHY smoke test is wanted, the proven route on this machine needs no kaluza-sim code: **the OCUDU gNB (split 8, ZMQ radio) with OAI's nrUE over ZMQ IQ**. OAI's own CI runs exactly that (`/home/amadeus/Development/ran/duranta-ran/ci-scripts/xml_files/container_5g_zmq_ocudu_1x1.xml`).
- It gives time-domain IQ fidelity for one UE or very few.
- It is research and test use under OAI's CSSL.
- kaluza-sim's role there is none. The core sees an ordinary gNB.

## 5. Mapping to the O-RAN architecture

| O-RAN node | kaluza-sim process | Real interfaces in v1 |
|---|---|---|
| O-CU-CP | `ksim-cucp` | NG-C (AMF), Xn-C (peer CU-CP), F1-C (DU), E1 (CU-UP) |
| O-CU-UP | `ksim-cuup` | NG-U (UPF), Xn-U (peer CU-UP), F1-U (DU), E1 (CU-CP) |
| O-DU | `ksim-du` | F1-C, F1-U; KAIR towards the UE farm |
| O-RU | inside `ksim-radio` / the radio model | none (logical) |
| near-RT RIC | external (FlexRIC / OSC RIC) | E2 (Ph2) |
| SMO | external | O1 (Ph2) |
