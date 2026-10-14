# ADR 0003: Uu at protocol fidelity in v1 (real RRC, PDCP and SDAP; ideal RLC/MAC; a radio model)

- **Status:** accepted, 2026-10-14 (user)
- **Context:**
  - kaluza-core sees the RAN only at NG and N1. UERANSIM simulates RRC and raw IP only, with no PDCP and no AS security, so the core's K_gNB, NH and NCC, lossless handover and UP integrity are never exercised.
  - Full RLC/MAC changes mostly timing and throughput at the core's edge.
  - An IQ-level PHY needs a full NR UE PHY (only OAI's, under CSSL), costs a handful of UEs' worth of CPU, and changes nothing the core sees.
  - The analysis is in [`../layer-feasibility.md`](../layer-feasibility.md).
- **Decision:**
  - **Real in v1:** RRC (TS 38.331 j40, both sides), PDCP (TS 38.323: NEA/NIA 0–3, COUNT/HFN, reordering, status report, re-establishment, SN status transfer, forwarding) and SDAP (TS 37.324: QFI↔DRB mapping, reflective QoS), keyed from the core's material per TS 33.501 Annex A.
  - **Ideal RLC/MAC link:** AM/UM/TM semantics, delay, loss and jitter, RA as a timed exchange with real contention, C-RNTI, paging occasions, DRX timing.
  - **A radio model:** TR 38.901 pathloss, seeded shadowing, RSRP/RSRQ/SINR, RLM.
  - **Full RLC/MAC with an abstract PHY (SINR→BLER) in phase 2,** behind seams fixed now: `IRlcBearer`, `IMacSap`, and KAIR v2 frames shaped like FAPI P7.
- **Consequences:**
  - The core's AS key handling and handover data paths are tested without radio.
  - MAC- and RLC-dependent behaviour (HARQ delay, scheduling, BSR) is not simulated in v1. Every abstraction is listed in `docs/abstraction-ledger.md`, so no gate row is mistaken for a radio claim.
- **Alternatives considered:**
  - **L3 only:** repeats UERANSIM's blind spot.
  - **Full L2 in v1:** slower first release, little extra the core can see.
  - **IQ PHY:** cost, licence, scale.
