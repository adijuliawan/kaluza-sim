# Research: duranta-ran / OpenAirInterface (read-only survey, 2026-10-14)

**Tree:** `/home/amadeus/Development/ran/duranta-ran`, branch `develop` at `3313a9b943` (2026-09-15, tag 2026.w37-3). It has a 2.8 GB build in `cmake_targets/`.

## Identity

- **What it is:** OpenAirInterface (OAI), renamed under the LF Networking "Duranta" project. The README title is "Duranta - OpenAirInterface"; the remote is github.com/duranta-project/openairinterface5g; it builds the usual `nr-softmodem` and `nr-uesoftmodem`.
- **Licence:** **CSSL v1.0** since tag 2026.w14 (previously the OAI Public License v1.1). The patent grant is royalty-free **only for study, testing and research**; any other use needs FRAND licensing (`LICENSE` §3). The bundled open-nFAPI is Apache-2.0.
- **For kaluza-sim:** read for facts only, never copied ([ADR 0004](../adr/0004-clean-room-licensing.md)).
- **Size:** mostly C, with some C++ in the radio drivers. About 829K lines (asn1c output is generated at build time). 33,776 commits; weekly tags; last formal release v2.4.0 (December 2025). Heavily CI-tested.
- **ASN.1 releases:** RRC 17.3.0, NGAP **15.8.0**, F1AP 16.21.0, E1AP 16.8.0, XnAP R16.2.0, LPP 16.6.0.

## Stack coverage

| Layer | Where |
|---|---|
| PHY (gNB and UE) | `openair1/PHY/{NR_TRANSPORT,NR_UE_TRANSPORT,CODING,NR_ESTIMATION,NR_UE_ESTIMATION}`, `openair1/SCHED_NR`, `openair1/SCHED_NR_UE` |
| MAC (gNB / UE) | `openair2/LAYER2/NR_MAC_gNB`, `openair2/LAYER2/NR_MAC_UE` |
| RLC, PDCP, SDAP | `openair2/LAYER2/nr_rlc`, `openair2/LAYER2/nr_pdcp` (Rel-16), `openair2/SDAP` (Rel-15) |
| RRC (gNB / UE) | `openair2/RRC/NR`, `openair2/RRC/NR_UE` (Rel-16 procedures, NTN from Rel-17) |
| NGAP, F1AP, E1AP, XnAP | `openair3/NGAP`, `openair2/F1AP`, `openair2/E1AP`, `openair2/XNAP` (Xn handover is on the Q3-2026 roadmap) |
| NAS (UE) | `openair3/NAS/NR_UE` (24.501 Rel-16) |
| USIM | `openair3/UICC` (Milenage only, keys in config; no APDUs) |
| Security | `openair3/SECU`: NEA0–2, NIA1–2 (no ZUC); SUCI via `curve_25519.c`, `x963_kdf.c` |
| E2 | `openair2/E2AP/RAN_FUNCTION`: E2AP v1.01/v2.03/v3.01, KPM v2.03/v3.00, RC v1.03, plus custom MAC/RLC/PDCP/GTP models; FlexRIC submodule |
| O1 | None towards an SMO; only an M-plane client towards an O-RU (`radio/fhi_72/mplane`) |
| OFH 7.2 | `radio/fhi_72` (DU side, OSC xran "K release", DPDK); `fronthaul/` plus `executables/nr-oru.c` for an O-RU |
| FAPI / nFAPI | `nfapi/open-nFAPI` (SCF 222.10.02 plus some 222.10.04; nFAPI SCF 225.2.0), PNF/VNF over socket, SCTP, WLS or nvIPC |

## Simulation hooks

| Hook | What it gives |
|---|---|
| **rfsimulator** (`radio/rfsimulator`) | 16-bit IQ over TCP 4043. The gNB is the server; up to 250 UE clients. Channel models (AWGN, multipath, phase noise) from `openair1/SIMULATION/TOOLS`; runs faster or slower than real time |
| **vrtsim** (`radio/vrtsim`) | IQ over shared memory, real time with an adjustable timescale; channel taps over nanomsg; a CIR database |
| **ZMQ** (`radio/zmq`) | "Based on zmq library in OCUDU project". **OAI CI runs the OCUDU gNB (split 8) with the OAI nrUE over ZMQ**: `ci-scripts/xml_files/container_5g_zmq_ocudu_{1x1,2x2}.xml` |
| RF emulator, IQ player | Noise as RX; record and replay of IQ |
| NR L2 nFAPI UE stub | **Removed for NR** (v2.4.0); LTE only |
| Core-facing testers | `tests/nr-ue-nas-simulator` (UE NAS plus gNB NGAP, fixed flow, no GTP); `tests/nr-cuup` (CU-UP load tester); `tests/nr-cu-nrppa` (NRPPa/NGAP positioning against an AMF and LMF) |

## What kaluza-sim takes from it

- **Evidence that IQ-level UE simulation means a full UE PHY** (here, at CSSL terms) at a CPU cost of a few UEs. kaluza-sim therefore stops at an abstracted PHY ([`../layer-feasibility.md`](../layer-feasibility.md)).
- **A PHY-in-the-loop route outside kaluza-sim:** the OCUDU gNB with the OAI nrUE over ZMQ, for research and test smoke runs.
- **Patterns:** OAI's F1AP, E1AP and XnAP "lib" layers (C structs ↔ ASN.1 with unit tests) show the value of thin, tested codec wrappers.
