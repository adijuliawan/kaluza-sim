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
| A-09 | **Time:** the simulated SFN comes from a CLOCK_REALTIME epoch across processes; no PPS/GPS timing. *As built through P2:* each DU's SFN ran from its own monotonic clock; from P3 R2 every DU counts it from CLOCK_REALTIME (KS-RRC-B10) | GNSS/PTP-synchronised cells | None for v1 procedures (TDOA accuracy is Ph2, from geometry) | — |
| A-10 | **No ROHC;** no PDCP duplication | ROHC profiles; duplication for URLLC | Header size; reliability | not planned |
| A-11 | **Paging occasions stamped, not enforced (P1):** the DU stamps each PCCH frame with its PF and i_s, and the UE reads every PCCH frame for its cell | DRX-gated reception of paging (TS 38.304 §7.1) | Paging latency; a UE that would miss a PO in DRX still answers | P3 (paging DRX) |
| A-12 | **Fixed camping (P1):** a UE camps on the cell its topology names; MIB/SIB1 are read and the PLMN and TAC checked, with no cell or PLMN selection. *From P3 R2:* with a radio view the UE camps on the strongest suitable cell it hears (KS-RRC-B10); the S-criterion, reselection and PLMN selection are R17's | Cell selection and reselection, PLMN selection (TS 38.304, TS 23.122) | None for P1's procedures; selection rows wait | P3 (radio model) |
| A-13 | **No RRC re-establishment (P1):** an SRB integrity failure, or an RRCReconfiguration the UE cannot follow, takes the UE to RRC_IDLE and the NAS sees a lower layer failure | RRCReestablishment with T311/T301 (TS 38.331 §5.3.7) | The core sees a release and a new registration or service request instead of a re-established connection | P3 (with handover) |
| A-14 | **Radio link supervision by KEEPALIVE (P1, N12):** the ideal link has no radio, so a connected UE sends a KAIR KEEPALIVE every 200 ms; the DU declares a radio link failure after 1 s with nothing from the UE (F1 UE CONTEXT RELEASE REQUEST, then NGAP with radio connection with UE lost) and the UE after 1 s with nothing from its cell. A `gnb restart` takes the cell off the air for 2 s, as a restarting gNB's is. A powered-off UE hears and sends nothing | T310/N310/N311 on physical-layer out-of-sync indications, RLC maximum retransmissions (TS 38.331 §5.3.10); a gNB's restart time | The time from radio loss to the release request (about 1 s here, shorter than a real gNB's). After a switch-off it can come before a busy AMF's own release, which TS 38.413 handles as a crossing (P2 LW5b: 83 UEs, KS-NGAP-D6); the core sees the same messages | P3 (radio model) |
| A-15 | **Delivery confirmed on the ideal RLC (P3, ADR 0013 point 10):** an AM SDU counts as delivered when the ideal link has handed it to the peer's RLC; there are no HARQ or RLC retransmission delays. The loss numbers across handover are counted over these deliveries and the UE's probe sequence | RLC AM status reports and retransmissions, HARQ (TS 38.322, TS 38.321) | Loss and reordering across handover come only from PDCP, forwarding and the path switch, not from the air; the interruption time has no air component | Ph2 (full L2) |

Every addition to this ledger needs an ADR or a register row explaining why it is safe for the rows that depend on it.
