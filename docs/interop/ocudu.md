<!--
SPDX-FileCopyrightText: 2026 Adi Juliawan
SPDX-License-Identifier: LicenseRef-kaluza-sim-private
-->

# OCUDU as interop peer: triage record

ADR 0012 makes OCUDU's CU-CP and CU-UP the independent peer for our F1 and E1.
This file records what each interop run showed and how each difference was
sorted:

- **sim defect**: a -D row, fixed in our code;
- **allowed**: the peer's behaviour, permitted by the spec, which we accommodate;
- **lead**: an OCUDU defect against the spec, for the user; never fixed here.

Pin: OCUDU `d9d2263f4d` (`tools/ocudu-peer.sh`, `~/kaluza-sim-peers/ocudu-d9d2263f4d/PIN`).

## C3 on the dev PC (P2 Q4, 2026-10-16)

Our UE farm and DU, OCUDU's `ocucp` and `ocuup`, `ksim-corestub`, all on
127.0.0.x (`topologies/ocudu-c3-stub.yaml`, gate `ksim-p2-ocudu.sh`, hook
`tools/ci.d/58-ocudu.sh`). After the fixes below, 9/9 rows pass (KS-PLAT-T50).

### Sim defects, fixed

| Row | What OCUDU showed |
|---|---|
| KS-F1AP-D2 | F1 Setup refused: our served cell's MeasurementTimingConfiguration had no `measTiming` (`lib/rrc/rrc_du_impl.cpp`: "Invalid Measurement Timing Config container") |
| KS-E1AP-D1 | Activity notification level "ue" without the UE Inactivity Timer (from the Q0 survey; it matters in C4, Q5) |
| KS-F1AP-D3 | Found while building DDDS: no DL PDCP SN Length in our DRB items, mandatory in F1AP |
| KS-NGAP-D3 | The stub's AMF sent no UE AMBR before the first session. OCUDU's CU-UP refused the bearer context: "Invalid UE-DL-AMBR" |

### Allowed, accommodated

- **OCUDU's PDCP sends no downlink data until a DDDS gives it a buffer size**
  (`lib/pdcp/pdcp_entity_tx.cpp` `check_early_drop`: `zero_dbs`). TS 38.425
  5.4.2.1 says the node hosting PDCP "may start sending DL data before receiving
  the initial DL DATA DELIVERY STATUS frame", so waiting is allowed. Our DU now
  sends the initial DDDS the moment a DRB is set up (KS-GTPU-B3). Before that,
  the first ping reply after a session setup and the buffered downlink packet
  after paging were dropped.

### Leads for OCUDU (not fixed here)

- **O-1: a PDU SESSION RESOURCE RELEASE COMMAND is dropped for a UE without a
  CU-UP context.**
  - Seen: the UE went idle by OCUDU's inactivity timer and came back with a
    signalling-only Service Request, so the session had no user plane. The AMF's
    release command then got no answer. The CU-CP log said `Dropping
    PDUSessionResourceReleaseCommand. Could not find CU-UP of the UE` and
    `"PDU Session Resource Release Procedure" failed`.
  - Expected: TS 38.413 8.2.2.2. The NG-RAN node "shall pass" the command's
    NAS-PDU to the UE, "shall release the corresponding resources over Uu and
    over NG, if any", and answers with PDU SESSION RESOURCE RELEASE RESPONSE.
    Without the NAS-PDU the UE's 5GSM release waits out T3582.
  - The C3 gate does not release a session from idle before its
    deregistration row.
- **O-2: OCUDU's CU-UP names itself `ocuup_<id>` in GNB-CU-UP E1 SETUP REQUEST.**
  - The gNB-CU-UP Name IE is a PrintableString (TS 37.483 9.2.1.4, E1AP-IEs
    `GNB-CU-UP-Name`), and `_` is not a
    PrintableString character (X.680 41.4). pycrate refuses the PDU; tshark shows
    it.
  - The name is formed in `apps/units/o_cu_up/cu_up/cu_up_unit_config_translators.cpp`
    (`fmt::format("ocuup_{}", ...)`) and cannot be configured.
  - It matters in C4 (OCUDU's CU-UP with our CU-CP, Q5), where our decoder sees
    the same octets.

## Evidence

- `build/ocudu/last/` holds the hook's last run: the summary, our F1AP and F1-U
  captures, and the peer's files with its NGAP and E1AP redacted.
- The gate's run directories carry everything under `peer/`, owner-only.
