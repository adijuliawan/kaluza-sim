# Traceability to kaluza-core

This page maps three things from kaluza-core to the kaluza-sim release that serves each:
- its phase-2 gate families;
- its phase-3 waves;
- the defects a real UE found that UERANSIM missed.

**Sources:**
- `/home/amadeus/Development/kaluza-core/docs/phase-3/README.md` (the source of truth; living artifact https://claude.ai/artifact/CLCFoe7XUwFWo3zeWiMjED);
- `/home/amadeus/Development/kaluza-core/docs/compliance/ran/README.md` §3;
- the `phase-2-final` row file `/home/amadeus/Development/kaluza-core/docs/compliance/smf/phase-2/rows-k3s-963130e1-native-eupf-75d3202.tsv`.

## 1. Phase-2 gate families (rows at `phase-2-final`)

23 gates start a UERANSIM gNB, holding 1,633 of the 2,892 rows. 21 of them drive UERANSIM UEs; `amf-both-accesses` and `twif` use it for the 3GPP leg.

| Family (rows) | What the gates need from the UE and RAN | kaluza-sim |
|---|---|---|
| AMF core: amf-ueransim (72), udsf (104), scp (42) | GUTI re-registration, T3512, CM-IDLE via `ue-release`, service request, AMF drain and AMF STATUS INDICATION, SCTP loss and re-association | v1 |
| Sessions, QoS, policy: smf (49), pcc (83), pcf (13), bsf (24) | IPv4 sessions, AMBR, dedicated and GBR flows, both modification kinds, UL QFI | v1 |
| Authentication and slicing: ausf (11), nssf (17), nsacf (81), amf-nssaa (41) | AKA, resync, NSSAI handling, #62, T3585; NSSAA | v1; NSSAA v1.x (P4) |
| Charging, exposure, OAM: chf (81), ee (65), oam (112), fm-pm (56) | Traffic volumes, reachability events, two gNBs, SCTP-loss alarms | v1 |
| dn-aaa (150) | EAP/PAP/CHAP over 5GSM; back-off honoured | v1.x (P4) |
| ipv6 (48), plus the ims `v6` part | IPv6 and IPv4v6, SLAAC | v1.x (P4) |
| roaming (258) | A 999/70 SUPI in the visited PLMN; LBO and home-routed sessions; `ps-modify` | v1 |
| smsf (121) | SMS over NAS, MO/MT from idle, SMS test hooks | v1 (hooks v1.x) |
| ims (76) | The `ims` DNN as transport for sipp | v1. The IMS UA (Ph2) lets kaluza-core retire IM-X1/IM-X7 ("soft UEs have no sec-agree") |
| snpn (50) | SNPN access mode | later; stays on UERANSIM until then |
| amf-both-accesses (19), twif (60) | The 3GPP leg of a two-access UE | v1; non-3GPP is Ph2 |

## 2. Phase-3 waves

| Wave | What kaluza-sim provides | Release |
|---|---|---|
| 39A–D (UPF-VPP baseline, N9, N4-u and IPv6, UPF selection) | Re-scoring at parity; UEs spread over several TAs and DNAIs for UPF selection (39D) | v1; 39C IPv6 in v1.x |
| U2 phone sweep | Not applicable (phones only). Its results feed the personas | — |
| **40.1 Xn handover** | Path Switch with real security capabilities; SN status transfer; Xn-U forwarding; End Marker ordering | **v1 (P3)** |
| **40.2 N2 handover** | Required/Request/Command/Notify/Cancel; UL/DL RAN Status Transfer; indirect forwarding | **v1 (P3)** |
| 40.3 AMF relocation, mobility registration; F-50 | Several AMFs, NNSF, GUTI-based registration from the card's stored context; Reroute NAS Request in v1.x | v1 / v1.x |
| **40.4 RRC_INACTIVE** | CN assistance information, Transition Report, resume at another gNB (Retrieve UE Context), RNA update, CN-paging fallback, T319 | **v1.x (P3b)** |
| F5 5G-EIR | IMEISV/PEI per UE (persona); a block-list row | v1 (P1) |
| 41 LMF + GMLC | Cell ID through ULI in v1. LPP (UE) and NRPPa (gNB) from ground-truth positions, including AoA and DL-TDOA RSTD, which on-air can't give | Ph2, first ([ADR 0007](adr/0007-positioning-first-in-phase-2.md)) |
| 42 URSP | UE policy NAS (MANAGE UE POLICY), URSP evaluation | later; Android phones until then |
| Edge-1/2, 31 NEF/CAMARA, 49 HPLMN breakout, 50 MonSTra | App traffic in UE netns, DNS from ePCO, relocation on handover, QoS modification, roaming traffic; signalling volume for MonSTra | v1 (IPv6 multi-homing in v1.x) |
| 46 5G LAN | Ethernet PDU sessions, VN groups | later; the UERANSIM `ethernet-pdu` branch until then |
| 47 NPN | SNPN access mode, EAP-TLS/TTLS primary authentication over 3GPP access | later; UERANSIM (SNPN mode) until then |
| 48 256-bit algorithms | Library only in the core; the sim's crypto registry follows when TS 33.501 integrates them | later |
| F6–F10 fillers (authorization in indirect communication, NF discovery by target PLMN, MSISDN verification, fewer policy associations, CHF segmentation) | SBI-side features. Basic registration and session flows from UEs in the sim ranges (home and roaming) are enough to drive them | v1 |
| 51 dual-stack | 51A IPv6 sessions (v1.x); 51B NGAP 128/160-bit addresses, SCTP and GTP-U over IPv6 (later); 51C non-3GPP IPv6 (Ph2 and later) | v1.x / later |
| Optional 38C, 43, 44A–C, 45 | 38C needs the IMS UA plus location (Ph2); 43 AKMA later; 44 non-3GPP (Ph2); 45 Ambient IoT out | — |

**Timing:** wave 40 starts after 39A–D, U2 and the second gNB are ready in the lab. kaluza-sim aims to finish P3 (v1) before wave 40's T0, or at the latest before its step 2.

## 3. The defects a real UE found and UERANSIM missed (`compliance/ran/README.md` §3)

| Defect | How kaluza-sim reproduces what the real UE or RAN did |
|---|---|
| AMF **F-42**: GUTI re-registration after switch-off looped (the IDENTITY RESPONSE under the kept context was discarded) | The UE keeps its NAS context on the card (EF.5GS3GPPLOCI/NSC) across switch-off and re-registers by GUTI (KS-UICC-008, KS-MM-002) |
| AMF **F-43**: a RAN release mid-identification left T3570 retransmitting | Radio loss injected mid-identification; release request sent; Error Indication on unknown AP IDs; assert no DL NAS after release |
| AMF **F-44**: #71 "ngKSI already in use" rejected instead of re-challenged | The UE answers #71 (KS-MM-006) |
| SMF **F-22**: the ACCEPT had no S-NSSAI | Accept validation: the UE reacts per spec and emits `CORE_ANOMALY` (KS-SM-004) |
| SMF **F-23**: a UE-requested release torn down before the RAN and UE answered | Ordering assertions on release (KS-SM-007, KS-NGAP-007) |
| SMF **F-24** / **F-25**: a restarted SMF replayed nothing / buffered downlink | Sequence-numbered UL/DL probes; a "no loss across an SMF restart" row |
| SMF **F-26**: a release from CM-IDLE sent an N2 release for resources the RAN never had (and crashed OCUDU) | The sim's gNB refuses it cleanly and reports it (never crashes) (KS-NGAP-007) |
| SMF **F-27**: IPv4v6 → IPv4 without #50 | Accept validation (KS-SM-004) |
| SMF **F-28**: no answer to the UE's MTU request; packets over 1456 octets lost | The UE requests the IPv4 link MTU in ePCO as phones do; no jumbo frames; a size-probe row (KS-GTPU-005) |
| NGAP **N-20**: OCUDU's partial NG RESET unreadable (a SIZE bound coded wrong by the core's encoder and decoder alike) | Partial NG Reset with large lists in both directions, plus a PER-coverage corpus cross-decoded by tshark and pycrate (KS-NGAP-012) |

**Same class, also covered:**
- AC-09 (RINMR, KS-MM-005);
- N-21 (UE radio capability, KS-RRCC-002);
- F-46 (switch-off from CM-IDLE, KS-MM-010);
- F-19 (registration update from CM-IDLE, KS-MM-004).

## 4. UERANSIM leniencies

The fifteen leniencies L1–L15 and the rule that replaces each are in [`requirements.md`](requirements.md) §3.1. Each becomes a named negative control: a mutation switch that reproduces the leniency on purpose, so a gate can show it would have caught it.
