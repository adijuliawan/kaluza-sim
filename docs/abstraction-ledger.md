# Abstraction ledger

This ledger lists every place where kaluza-sim deliberately simplifies the real system ([ADR 0003](adr/0003-uu-protocol-fidelity.md)). It exists so that no gate row is read as a radio claim the sim cannot make.

Each entry says:
- what is abstracted;
- what a real system does;
- what the core could observe;
- when it becomes real.

Registers point here with `-G` rows.

| # | Abstraction (v1) | Real system | What the core could observe | Becomes real |
|---|---|---|---|---|
| A-01 | **No PHY:** a radio model computes SS-RSRP/RSRQ/SINR from geometry (TR 38.901 pathloss, seeded shadowing); no fast fading | OFDM, channel estimation, fading | Nothing directly. Measurement values drive handover and RLF timing | Ph2: SINR → BLER abstraction (still no IQ) |
| A-02 | **Ideal RLC:** AM/UM/TM semantics; loss on AM becomes ARQ delay; max-retx maps to RLF | Segmentation, ARQ, status PDUs, t-PollRetransmit, t-Reassembly | Throughput and latency under loss; GBR behaviour | Ph2: TS 38.322 entities |
| A-03 | **Ideal MAC:** no HARQ, no scheduler, no BSR/SR/PHR; RA as a timed four-message exchange with real contention; a fixed grant delay | HARQ, scheduling, BSR-driven UL delay, TA | Latency of user data and signalling (e.g. registration time) | Ph2: TS 38.321 MAC with a DU scheduler |
| A-04 | **One serving cell per UE:** no carrier aggregation, no dual connectivity | CA/DC | None for v1 procedures | not planned |
| A-05 | **No beam management;** SSB per cell treated as one beam | Beam sweeping, L1-RSRP per beam | None | not planned |
| A-06 | **No measurement gaps** in v1 (intra-frequency neighbours only) | Gaps for inter-frequency measurement | Inter-frequency handover timing | v1.x/Ph2 (KS-L2R-006) |
| A-07 | **Coarse per-cell capacity model** for GBR notification control and rate caps | Scheduler-driven per-UE throughput | Notification timing; QoS rows that measure throughput | Ph2 (real scheduler) |
| A-08 | **SI simplified:** MIB/SIB1 sent on a schedule; SIB2–4 as needed for reselection; SI windows not modelled slot by slot | SI windows, periodicity, on-demand SI | SI-change timing only | Ph2 |
| A-09 | **Time:** the simulated SFN comes from a CLOCK_REALTIME epoch across processes; no PPS/GPS timing | GNSS/PTP-synchronised cells | None for v1 procedures (TDOA accuracy is Ph2, from geometry) | — |
| A-10 | **No ROHC;** no PDCP duplication | ROHC profiles; duplication for URLLC | Header size; reliability | not planned |

Every addition to this ledger needs an ADR or a register row explaining why it is safe for the rows that depend on it.
