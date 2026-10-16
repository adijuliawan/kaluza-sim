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

## C4 and C5 on the dev PC (P2 Q5, 2026-10-16)

- **C4:** OCUDU's `ocuup` with our CU-CP, DU and UEs (`topologies/ocudu-c4-stub.yaml`).
- **C5:** OCUDU's `ocucp` with our CU-UP, DU and UEs (`ocudu-c5-stub.yaml`).

Both run against `ksim-corestub` with the E1 gate (`ksim-p2-e1.sh`) and the P1 session and data-plane gates, in hook 58. The result is 21 PASS, 1 ALLOWED, 0 FAIL (KS-PLAT-T51).

- **C5 works end to end.** OCUDU's CU-CP sets our CU-UP's bearer contexts up and releases them, a ping passes 3/3, and our CU-UP's inactivity report leads OCUDU's CU-CP to release the UE.
  - OCUDU's E1 Setup Response carries no gNB-CU-CP Name. The IE is optional, so that is not a difference.
- **C4's control plane works:**
  - E1 Setup from OCUDU's CU-UP;
  - bearer context setup, modification and release;
  - OCUDU's inactivity report releasing the UE through our CU-CP;
  - the P1 session rows.
- **C4's user plane does not work:** no user data passes, for two reasons in OCUDU's CU-UP (O-4, O-5), which the allow entry `O-4/O-5` covers.

### Sim defects, fixed

| Row | What the C4/C5 runs showed |
|---|---|
| KS-PLAT-D10 | Building the PDCP timers into E1: asn1c's JER decoder dropped a member written out of ASN.1 order without an error (runtime patch 0008 makes it fail) |
| KS-E1AP-B3 | Our CU-CP gave the CU-UP no DL discard timer. E1 makes it optional, but it is the one the UE gets in RRC; now sent |

### Spec ambiguity

- **KS-E1AP-S2:** the UP keys' length in E1.
  - Our CU-CP sends the 128-bit algorithm key (TS 33.501 A.8); OCUDU's sends the 256-bit KDF output.
  - Our CU-UP now takes either.

### Leads for OCUDU (not fixed here)

- **O-3: OCUDU's CU-UP accepts a bearer context it cannot serve.**
  - Seen: with no Discard Timer in the DRB's PDCP Configuration (optional in TS 37.483 9.3.1.38), it answered BEARER CONTEXT SETUP RESPONSE. Its log said `DRB1 DL: Invalid DRB config, discard_timer is not configured`, and the DRB never carried downlink data.
  - Expected: a value it requires should be refused with a cause, or a default applied.
  - We now send the timer.
- **O-4: OCUDU's PDCP ciphers the SDAP header.**
  - TS 38.323 5.8 excludes it: the ciphered unit is "the data part of the PDCP Data PDU ... except the SDAP header and the SDAP Control PDU".
  - Seen: `pdcp_entity_tx.cpp` and `pdcp_entity_rx.cpp` quote that text, but cipher from the end of the PDCP header (`hdr_size` only).
  - It never shows with OCUDU's own CU-CP, which configures both SDAP headers absent (`lib/cu_cp/up_resource_manager/up_resource_manager_helpers.cpp`, lines 515-516). Our CU-CP configures them present.
- **O-5: OCUDU's CU-UP reads a 128-bit UP key as the first half of a 256-bit one.**
  - Seen: `fill_sec_as_config` copies the E1 key into a 32-octet buffer from its start, and `truncate_key` then takes the 128 least significant bits. With our 16-octet key, those are zeros.
  - Expected: a 16-octet key is the algorithm key itself (TS 33.501 A.8; KS-E1AP-S2).

**How O-4 and O-5 were told apart** (local runs, not committed; C4 with the stub):

| Run | Keys sent | SDAP headers | Ping |
|---|---|---|---|
| as built | 128-bit | present | 0/3 |
| 256-bit keys | 256-bit (ours in the 128 LSBs) | present | 0/3 |
| no SDAP headers | 128-bit | absent | 0/3 |
| both worked around | 256-bit | absent | 3/3 |

Each alone blocks all user data.

### Notes

- O-2's CU-UP name `ocuup_0` reaches our CU-CP intact: our asn1c decoder does not check PrintableString's alphabet. TS 37.483 10.3.4 would ignore the IE (criticality ignore), and the name is only for humans, so nothing differs.

## C3 with 100 UEs (P2 Q7, 2026-10-16)

`topologies/ocudu-c3-stub-100.yaml` has imsi-001010000300000..099 on 4 farm shards, against `ksim-corestub`. Each run had the C3 gate, the P1 registration and session gates, and the scale gate (`ksim-p2-scale.sh`, 10 UEs at a time).
- Over 3 runs, every row passed. 100 UEs registered with one session each through OCUDU's CU-CP and CU-UP in 0.9–1.1 s (KS-PLAT-T52). Hook 58 runs the scale gate as `c3-100`.
- Nothing new from OCUDU. Two things of ours turned up:
  - KS-PLAT-D11: the control socket's backlog. A burst of `ksim-ctl --parallel` calls lost one.
  - The C3 gate left its UE on after deregistering, and the next gate's power-on was refused. The gate now switches the UE off (`--abrupt`).
- The lab run (LW2) uses `topologies/ocudu-c3-lab.yaml` and `tools/ocudu-peer.sh run --lab`. OCUDU's roles run in our namespaces `ksim-ocucp` (.36) and `ksim-ocuup` (.37), from `topologies/peers/ocudu/*-lab.yml.in` ([`lab.md`](../lab.md) §6).

## C3 against kaluza-core, LW2 (P2 Q7, 2026-10-16)

OCUDU's `ocucp` (.36, gNB 0x1A1) and `ocuup` (.37) run in our namespaces on kaluza-uesim (`tools/ocudu-peer.sh run --lab`), with our DU and UEs, against kaluza-core's AMF `f51ccdb1` and its V-UPF.
- Every C3 row passed except downlink paging, which needs the stub's DN trigger.
- The P1 registration and session rows that apply passed.
- 100 UEs registered with a session each through OCUDU in 26.4 s (KS-PLAT-T56).
- Nothing new from OCUDU. Its console has to be line-buffered when written to a file (KS-PLAT-D15).

## Evidence

- `build/ocudu/last/` holds the hook's last runs (`c3/`, `c4/`, `c5/`): the summary, our
  captures and rows, and the peer's files with its NGAP and E1AP redacted.
- The gate's run directories carry everything under `peer/`, owner-only.
