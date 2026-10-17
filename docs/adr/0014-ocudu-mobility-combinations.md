# ADR 0014: OCUDU in P3's mobility combinations

- **Status:** accepted, 2026-10-17 (user, with the P3 plan; the same pin and venues as ADR 0012)
- **Context:**
  - P3's exit names "Xn handover against OCUDU's CU-CP" (`roadmap.md`). OCUDU d9d2263f4d (26.04) has Xn-C handover in both roles, N2 handover in both roles and intra-CU handover across up to 6 DUs. It is triggered from its stdin console (`ho <serving pci> <rnti hex> <target pci> <plmn> <tac>`) or by measurements (`trigger_handover_from_measurements: true`), with neighbours under `cu_cp.mobility.cells[].ncells`.
  - It has no Xn-U or NG-U forwarding and no End Marker; it parses the NH/NCC of PATH SWITCH REQUEST ACKNOWLEDGE without applying it; its NNSF is by PLMN only (`extra_amfs`).
  - Its CU-CP calls `report_fatal_error` when a target DU's CellGroupConfig or dedicated SIB1 fails to unpack, and reads `t304` from the CellGroupConfig unchecked.
  - Its Xn-C gateway is one SCTP socket on port 38422 that listens and connects, and it accepts an association only from a configured peer address, port included (spike 1, KS-PLAT-T64).
  - `ksim-ctl netd exec` gives a command `/dev/null` for stdin, so a row cannot type at OCUDU's console in the lab.
- **Decision:**
  1. **The pin and the build** stay ADR 0012's: `d9d2263f4d`, our own export and build in `~/kaluza-sim-peers/ocudu-d9d2263f4d/`, recorded in every run manifest.
  2. **The combinations** (plan design point f):

     | Combo | UEs + DUs | gNB A | gNB B | What it proves | Where |
     |---|---|---|---|---|---|
     | C6 | ours (2 DUs) | OCUDU CU-CP + CU-UP | — | intra-CU handover under an independent CU-CP; our CellGroupConfig and UE | dev PC (stub); LW6 (kaluza-core) |
     | C7 | ours | ours | OCUDU (C3 shape) | **Xn-C handover both ways (the exit)** | dev PC (stub) |
     | C8 | ours | ours | OCUDU (C3 shape) | N2 handover both ways | dev PC (stub) |

  3. **Driving OCUDU.** Its console is the trigger. On the dev PC `tools/ocudu-peer.sh run` gives `ocucp` a FIFO for stdin in the run directory, and a row writes `ho …` lines into it; in the lab `ksim-ctl netd exec --stdin <fifo>` (netd v4) does the same. The measurement-driven re-runs (R16) set `trigger_handover_from_measurements` and give OCUDU the neighbour table from the topology. The peer templates under `topologies/peers/ocudu/` gain `mobility.cells` and `xnap.gateways` (its Xn address .36 in the lab, 127.0.0.20 on the dev PC, our gNB's Xn address as its one connection).
  4. **What we hand OCUDU is checked offline first.** Every RRC container our DU or CU-CP sends it (the target DU's CellGroupConfig, SIB1, HandoverPreparationInformation, the HandoverCommand) is unpacked and re-packed by OCUDU's own decoder (`tools/ocudu_vectors/unpack.sh`, R1) before any live run, so a fatal path on its side is found as a red test of ours.
  5. **Triage** as ADR 0012 point 7: each difference becomes a sim -D row, an entry in `gates/allow/ocudu.tsv` for the modes it holds (C6, C7, C8) with its reason, clause and OCUDU source reference, or an -S row. The leads known today are allowed in the rows that meet them, with references: no Xn-U forwarding and no End Marker (`ksim-p3.c7.data`), the NH/NCC from the Ack not applied (`ksim-p3.c7.keys`), OCUDU's CU-UP data path with our CU-CP (O-4/O-5, `ksim-p3.c6.data`). OCUDU defects are recorded for the user in `docs/interop/ocudu.md` and never fixed here.
- **Consequences:**
  - C6–C8 run on the dev PC as recorded evidence and in an opt-in CI hook when the peer build exists, as C3–C5 do (hook 58).
  - The exit's OCUDU proof is C7 both ways; C6 comes first, right after our own intra-CU handover (R5), so the riskiest interop is met early.
  - Only C6 runs against kaluza-core (LW6): intra-CU handover is invisible to the AMF. C7 and C8 need a core that serves Path Switch and N2 handover, so they stay on the stub until wave 40.
