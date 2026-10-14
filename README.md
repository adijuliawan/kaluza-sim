# kaluza-sim

A spec-driven 5G UE and O-RAN RAN simulator for validating **kaluza-core**, built from 3GPP Release 19 text.

It is a **second implementation**. It shares no code, tables or reference outputs with kaluza-core, so it catches misreadings that a round-trip test cannot.
- The RAN is built from **O-RAN nodes** (O-CU-CP, O-CU-UP, O-DU) joined by real F1, E1, Xn and NG.
- The UE talks to its SIM through **real APDUs**.
- PDCP runs with the keys the core hands out, so the core's K_gNB, NH and NCC are checked end to end.

**Status (2026-10-14):** design done; no code yet. The next step is build phase **P0**.

**Review page (private artifact):** https://claude.ai/artifact/DdYiFQqkbaC8kaMCn4ft95. It summarises these docs as of the commit named in its header. Where they differ, the repo wins. Republish the page when the docs change.

## Start here (new session)

1. [`docs/handoff/2026-10-14-design-session.md`](docs/handoff/2026-10-14-design-session.md): the resume point. It covers the decisions and their reasons, the research, the open items, and the first steps of P0.
2. [`docs/roadmap.md`](docs/roadmap.md): build phases P0–P5 and their exit criteria.
3. [`docs/architecture.md`](docs/architecture.md) and [`docs/requirements.md`](docs/requirements.md).

**Standing rules:**
- **Never print secrets.** That covers K, OPc, ADM codes, seeds and card images.
- **Read-only on kaluza-core.** Coordinate lab and B220 use with its session.
- **Wait for an explicit go** after a plan is approved.
- **Commits and pushes:** only when told, with no AI attribution.
- **Clean room:** AGPL, GPL and CSSL code is read for ideas only, never copied.

## What it is for

The UERANSIM fork drives 23 of kaluza-core's gates, but it cannot test what phase 3 needs:
- it has no PDCP, RLC or MAC and no AS security;
- its RRC is partial;
- Xn is a custom UDP message, not XnAP;
- the SIM is just keys in YAML;
- it is lenient in ways that hid 11 core defects until a real UE found them.

kaluza-sim targets:
- the phase-3 waves, mobility (wave 40) first, without radio;
- parity with every UERANSIM gate row;
- interop with OCUDU over real F1, E1 and Xn.

## Decisions (2026-10-14)

| Topic | Decision | ADR |
|---|---|---|
| Priority | Fidelity first: up to about 100 UEs with full stacks. A load mode of 10k+ UEs comes later. | [roadmap](docs/roadmap.md) |
| Language | C++20. ASN.1 via asn1c, from our own extraction of the Rel-19 docx | [0001](docs/adr/0001-cpp20-and-asn1c.md) |
| RAN | Our own O-CU-CP, O-CU-UP and O-DU. OCUDU is an interop peer and a reference | [0002](docs/adr/0002-own-oran-nodes.md) |
| Uu depth in v1 | Protocol fidelity: real RRC, PDCP and SDAP, with an ideal RLC/MAC link and a radio model. Full L2 is phase 2 | [0003](docs/adr/0003-uu-protocol-fidelity.md) |
| Licence | Private for now, clean-room with respect to AGPL, GPL and CSSL code | [0004](docs/adr/0004-clean-room-licensing.md) |
| Independence | Our own reading of the spec. Nothing from kaluza-core is used to produce an expected value | [0005](docs/adr/0005-independence-from-kaluza-core.md) |
| RRC_INACTIVE | v1.x (build phase P3b), right after the v1 handover milestone | [0006](docs/adr/0006-rrc-inactive-in-v1x.md) |
| Phase 2 | Positioning (LPP/NRPPa) comes first, to land with wave 41 | [0007](docs/adr/0007-positioning-first-in-phase-2.md) |

## Documents

| Document | Content |
|---|---|
| [`docs/requirements.md`](docs/requirements.md) | Goals and non-goals; the KS-* requirement catalogue; non-functional requirements; the UERANSIM leniencies L1–L15 |
| [`docs/layer-feasibility.md`](docs/layer-feasibility.md) | Which layers are simulated, how and when, with evidence from OCUDU and duranta-ran |
| [`docs/architecture.md`](docs/architecture.md) | Tenets, processes and interfaces, the KAIR air protocol, code layering, concurrency, UE, RAN, control, build and test |
| [`docs/sim-uicc.md`](docs/sim-uicc.md) | Soft UICC: card OS, files, algorithms, APDU transports, tracing, images, test subscriber ranges |
| [`docs/data-plane.md`](docs/data-plane.md) | The v1 user-plane path; the later eBPF express path (PacketRusher study) |
| [`docs/cli.md`](docs/cli.md) | `ksim-ctl`: every UE and RAN command; the optional AT port |
| [`docs/verification.md`](docs/verification.md) | Test tiers, oracles, interop matrix, parity crosswalk, the gate contract offered to kaluza-core |
| [`docs/traceability.md`](docs/traceability.md) | Mapping to kaluza-core's gate families, phase-3 waves, and the defects UERANSIM missed |
| [`docs/roadmap.md`](docs/roadmap.md) | P0–P5, exit criteria, risks |
| [`docs/lab.md`](docs/lab.md) | Where it runs: the dev PC for builds and tier 1; kaluza-uesim (VM 105) for runs against the core on 172.30.30.30–.39; the card bridge |
| [`docs/specs.md`](docs/specs.md) | Pinned spec index: local or to fetch, with versions |
| [`docs/adr/`](docs/adr/) | Decision records 0001–0007 |
| [`docs/research/`](docs/research/) | OCUDU, duranta-ran (OAI), UERANSIM fork, PacketRusher, SIM tooling, Quectel material |

## Repository

- Origin: `ssh://git@ssh.github.com:443/adijuliawan/kaluza-sim.git`. The repo is private, and SSH goes over port 443 because port 22 is blocked.
- Planned layout: `spec/`, `third_party/`, `src/{platform,net,crypto,codec,entity,uicc,radio,proc,node,api}`, `apps/`, `personas/`, `cards/`, `topologies/`, `tests/`, `gates/`, `tools/`, `docs/`. [`docs/architecture.md`](docs/architecture.md) §3 describes it.
- Spec documents, secrets, captures and vendor-confidential material never enter git. [`.gitignore`](.gitignore) enforces this.
