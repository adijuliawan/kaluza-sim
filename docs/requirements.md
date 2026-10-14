# kaluza-sim: requirements

**Status:** design baseline, 2026-10-14. The spec versions are pinned in [`specs.md`](specs.md). The clause numbers of the local Rel-19 documents (TS 24.501 j80, 38.413 j40, 38.331 j40, 33.501 j70, 24.011 j00, 23.040 j00, 23.122 j70, 38.415 j10, 29.281 j20, 38.412/414 j00, 24.007 j50) were checked against the documents' headings on 2026-10-14. **(T0)** marks a clause in a spec that isn't on disk yet; it is pinned when the spec is fetched in P0.

## How to read this

- **Priority:**
  - **v1** is the first release (build phases P0–P3).
  - **v1.x** comes straight after it (P3b RRC_INACTIVE, P3c AT port, P4 parity).
  - **Ph2** is the phase-2 families.
  - **later** is the user's "later" list.
- **Verification:**
  - **U** unit, KAT or oracle test (tshark, pycrate, pySim, 3GPP/SAGE vectors);
  - **F** fuzz or property test;
  - **I** interop (OCUDU, the Open5GS control core, a real card);
  - **L** lab scenario against kaluza-core;
  - **G** a kaluza-core gate row driven through the contract in [`verification.md`](verification.md) §6;
  - **A** comparison with real-device captures.
- **IDs:** `KS-<AREA>-nnn`. The registers under `docs/compliance/<area>/`, created in P0, add typed rows in kaluza-core's style:

| Suffix | Meaning |
|---|---|
| `-Dn` | defect in the sim |
| `-Bn` | a choice the spec leaves open |
| `-Gn` | declared gap |
| `-Vn` | deviation from a "shall" |
| `-Sn` | spec contradiction, and the reading chosen |
| `-Mn` | mutant |
| `-Tn` | T0 reading or measurement |
| `-Fn` | a kaluza-core defect the sim found (a pointer to `docs/findings/KF-nnn.md`) |
| `-Xn` | retired row |

## 1. Goals and non-goals

**Goals**
1. **A second implementation that catches what a lenient simulator hides.** It finds defects of the kind a real UE found after UERANSIM had passed them for weeks (`/home/amadeus/Development/kaluza-core/docs/compliance/ran/README.md` §3) by following timers, IEs and abnormal cases as the spec says.
2. **Replace UERANSIM in kaluza-core's soft gates.** Today 23 gates start a UERANSIM gNB. They hold 1,633 of the 2,892 rows in `phase-2-final`. The switch should cost the gates only small edits.
3. **Make phase-3 waves testable without radio,** first wave 40's handovers and their failure paths, then RRC_INACTIVE, then positioning with true positions (wave 41).
4. **Use real F1, E1, Xn and NG interfaces,** so OCUDU interop counts as evidence.
5. **Inherit kaluza-core's evidence discipline:** pinned specs, compliance registers, a deviations index, and every gate row accounted for.
6. **Later:** a 10k+ UE load mode with an eBPF data plane, and a FAPI bridge to a real OCUDU DU.

**Non-goals**
- IQ-level PHY or RF. kaluza-sim never touches the B220, UHD or any SDR.
- LTE, EPC and NSA: no E-UTRA, EN-DC, S1, X2 or N26.
- NTN; sidelink, ProSe and V2X; MBS; IAB; carrier aggregation and dual connectivity (one serving cell per UE in v1); beam management.
- Claims about positioning accuracy; AI/ML.
- Being a certified conformance test system. TS 38.523-1 and TS 31.121 are sources of test purposes only: no TTCN, no claimed verdicts.
- Any reuse of kaluza-core code, tables or encoder output ([ADR 0005](adr/0005-independence-from-kaluza-core.md)).

## 2. Requirement catalogue

### 2.1 UICC and USIM (ETSI TS 102 221 V18.4.0; TS 31.101 j00; TS 31.102 j60)
| ID | Requirement | Spec § | Pri | Ver |
|---|---|---|---|---|
| KS-UICC-001 | APDU layer: command cases 1–4, procedure bytes, T=0 handling of 61xx and 6Cxx with GET RESPONSE, status words, ATR. MANAGE CHANNEL with logical channels | 102 221 §10, §11.1 (T0) | v1 | U, I |
| KS-UICC-002 | File system: MF, ADF.USIM and DF.5GS. SELECT by FID, path or AID, returning FCP. READ/UPDATE BINARY, READ/UPDATE/SEARCH RECORD, STATUS. Access conditions through ARR | 102 221 §8, §11.1.1–.7 (T0); 31.101 | v1 | U (pySim-shell reads every EF) |
| KS-UICC-003 | PIN1, PIN2 and ADM1: VERIFY, CHANGE, UNBLOCK, DISABLE/ENABLE; updates gated by ADM | 102 221 §9, §11.1.9–.13 (T0) | v1 | U |
| KS-UICC-004 | EFs: IMSI, AD, UST, EST, ACC, SMSP, SMS, MSISDN, PLMNwAcT, OPLMNwACT, HPPLMN, EHPLMN, FPLMN, LOCI, ARR. DF.5GS (5FC0): 5GS3GPPLOCI 4F01, 5GS3GPPNSC 4F03, 5GAUTHKEYS 4F05, UAC_AIC 4F06, SUCI_Calc_Info 4F07, OPL5G 4F08, SUPI_NAI 4F09, Routing_Indicator 4F0A | 31.102 §4.2, §4.4.11 (T0) | v1 | U |
| KS-UICC-005 | AUTHENTICATE, 3G context (P2 = 0x81): MILENAGE f1–f5* returning RES/CK/IK, or AUTS on synch failure; status word on MAC failure. The ME derives RES*, K_AUSF, K_SEAF and K_AMF | 31.102 §7.1 (T0); 35.206; 33.501 A.2–A.7 | v1 | U, L |
| KS-UICC-006 | SQN freshness with a SEQ/IND array; resynchronisation | 33.102 §6.3.3, §6.3.5, Annex C (T0: the local copy is .doc) | v1 | U, L |
| KS-UICC-007 | SUCI: null scheme, Profile A and Profile B. Computed by the ME (UST service 124) or by the USIM (124 + 125, GET IDENTITY `80 78 00 01`). Includes routing indicator and home-network key ID | 33.501 §6.12.2, C.3, C.4; 31.102 §7.5 (T0); 24.501 §9.11.3.4 | v1 | U (C.4 vectors), L |
| KS-UICC-008 | State persists across power cycles: 5G-GUTI, last visited TAI and update status (4F01); NAS security context (4F03); K_AUSF/K_SEAF (4F05), including the invalidation rules | 31.102 §4.4.11 (T0); 24.501 §4.4.2 | v1 | L (the F-42 class) |
| KS-UICC-009 | Card backends: in-process; vpcd virtual reader (so pySim sees the soft card); PC/SC with real sysmoISIM cards, where K never leaves the card | tooling | v1 (PC/SC in P2) | I |
| KS-UICC-010 | TUAK and MILENAGE-256 as card algorithms (the UDM has them; no device does) | 35.231–236 | v1.x | U, L |
| KS-UICC-011 | USAT: TERMINAL PROFILE, FETCH, proactive commands, ENVELOPE (SMS-PP data download, REFRESH) | 31.111 j40 | later | — |
| KS-UICC-012 | ISIM: IMPI, IMPU, DOMAIN, P-CSCF; IMS-AKA through AUTHENTICATE | 31.103 j10 | Ph2 (IMS UA) | — |
| KS-UICC-013 | eUICC (ISD-R, ES10x) | GSMA SGP.22/SGP.32 | later | — |

### 2.2 NAS 5GMM (TS 24.501 j80)
| ID | Requirement | § | Pri | Ver |
|---|---|---|---|---|
| KS-MM-001 | 5GMM states and substates, update status (5U1–5U3), UE behaviour per substate | §5.1.3.2, §5.2.2, §5.2.3 | v1 | U (model-based), L |
| KS-MM-002 | Initial registration: SUCI or 5G-GUTI (with a kept context), requested NSSAI, capabilities, SMS requested, requested DRX. Processing the accept: TAI list, NSSAI sets, T3512/T3502, SMS allowed, equivalent PLMNs. REGISTRATION COMPLETE when required | §5.5.1.2.2, §5.5.1.2.4 | v1 | L, A |
| KS-MM-003 | Registration reject by cause (#3, #6, #7, #11, #12, #13, #15, #22, #27, #62, #72, #73): forbidden lists, attempt counter, T3510/T3511/T3502/T3346; abnormal cases in the UE | §5.5.1.2.5, §5.5.1.2.7, §5.3.8, §5.3.9 | v1 | L |
| KS-MM-004 | Mobility and periodic registration: TA change, T3512 (network value, else default), after handover, on configuration-update "registration requested"; uplink data status and PDU session status | §5.5.1.3, §5.3.4, §5.3.7 | v1 | L |
| KS-MM-005 | Initial NAS message protection: cleartext IEs only, then the full message in a NAS message container after SMC; RINMR honoured | §4.4.6, §5.4.2 | v1 | L (the AC-09 class) |
| KS-MM-006 | 5G AKA and EAP-AKA′. Checks of MAC, SQN and the separation bit; failures #20, #21 (with AUTS), #26, #71; ngKSI rules; T3520 | §5.4.1.2, §5.4.1.3; 33.501 §6.1.3; RFC 9048 | v1 | U, L (F-44) |
| KS-MM-007 | Security mode control: replayed-capability check; NIA0 refused outside emergency; IMEISV returned when requested; rejects #23 and #24; key change on the fly | §5.4.2; 33.501 §6.7.2, §6.9.4 | v1 | L (F5) |
| KS-MM-008 | NAS COUNT handling, replay protection, ciphering and integrity, discard rules | §4.4.3–4.4.5; 33.501 §6.4 | v1 | U, F |
| KS-MM-009 | Identification; generic UE configuration update; 5GMM STATUS; NAS transport (SMS, and later LPP and UE policy) | §5.4.3–5.4.6 | v1 | L |
| KS-MM-010 | UE-initiated deregistration: normal, switch-off and remove-SIM, from CM-IDLE as well | §5.5.2.2 | v1 | L (the F-46 class) |
| KS-MM-011 | Network-initiated deregistration, including **"re-registration required" followed by a new initial registration**, and collisions | §5.5.2.3 | v1 | L |
| KS-MM-012 | Service request (UL data, paging response, MO SMS, signalling); paging handling | §5.6.1, §5.6.2 | v1 | L |
| KS-MM-013 | Unified access control without self-inflicted barring | §4.5; 38.331 §5.3.14 | v1 | U |
| KS-MM-014 | Congestion: NAS-level (T3346), DNN-based (T3396), S-NSSAI-based (T3585) | §5.3.9–5.3.11, §6.2.7–6.2.8 | v1 | L |
| KS-MM-015 | Requested, allowed, rejected, configured and pending NSSAI, including rejection for maximum UEs reached | §4.6, §5.5.1.2.4 | v1 | L |
| KS-MM-016 | PLMN selection, equivalent PLMNs, roaming with a 999/70 SUPI | 23.122 §4.4; 24.501 §5.3.14 | v1 | L |
| KS-MM-017 | Handling of reject messages without integrity protection | §5.3.20 | v1 | L |
| KS-MM-018 | Unknown or erroneous IEs and messages: unknown non-imperative IEs ignored, never reported as a MAC failure | §7.5–7.8; 24.007 §11.2.4 | v1 | F |
| KS-MM-019 | NSSAA (EAP over NAS) | §5.4.7 | v1.x (P4) | G |
| KS-MM-020 | 5GMM-CONNECTED with RRC inactive indication | §5.3.1.4 | v1.x (P3b) | L |
| KS-MM-021 | SNPN access mode and onboarding | §5.3.x (SNPN); 23.122 §4.9.3 | later | — |

### 2.3 NAS 5GSM (TS 24.501 j80)
| ID | Requirement | § | Pri | Ver |
|---|---|---|---|---|
| KS-SM-001 | 5GSM states in the UE; PTI and PSI rules | §6.1.3.2, §6.2.1 | v1 | U |
| KS-SM-002 | Establishment: IPv4 in v1; IPv6 and IPv4v6 in v1.x (interface identifier, SLAAC, causes #50 and #51). SSC mode; ePCO (DNS, P-CSCF, IPv4 link MTU request); maximum integrity-protected data rate | §6.4.1.2, §6.4.1.3; 24.008 §10.5.6.3A | v1 / v1.x | L, A |
| KS-SM-003 | Rejects: back-off timer and re-attempt indicator (#29 and others), #26 with T3396, #69 with T3585 | §6.4.1.4, §6.2.12, §6.2.7, §6.2.8 | v1 | L |
| KS-SM-004 | Validate accepts and commands: missing "shall include" IEs and semantic errors. React as the spec says, and also emit `CORE_ANOMALY` | §6.4.1.3, §7.5–7.8 | v1 | L (F-22, F-27) |
| KS-SM-005 | QoS rules and flow descriptions (GBR with GFBR/MFBR), session-AMBR, reflective QoS; uplink classification and QFI marking | §6.2.5, §9.11.4.12, §9.11.4.13 | v1 | U, L |
| KS-SM-006 | Network-requested and UE-requested modification | §6.3.2, §6.4.2 | v1 | L |
| KS-SM-007 | UE-requested release (T3582) and network-requested release, including the right order relative to the RAN release | §6.4.3, §6.3.3 | v1 | L (F-23) |
| KS-SM-008 | PDU session authentication: EAP over 5GSM, PAP/CHAP in ePCO | §6.3.1 | v1.x (P4) | G |
| KS-SM-009 | T3580–T3582 retransmission; 5GSM STATUS; maximum number of PDU sessions; session status sync | §10.3; §6.4.1.5 | v1 | U, L |

### 2.4 SMS over NAS (TS 24.011 j00, 23.040 j00, 23.038 j00)
| ID | Requirement | § | Pri | Ver |
|---|---|---|---|---|
| KS-SMS-001 | CM layer (SMC-5G): CP-DATA, CP-ACK, CP-ERROR; TC1* | 24.011 §5.2.2, §7.2, §10 | v1 | U, L |
| KS-SMS-002 | Relay layer: RP-DATA, RP-ACK, RP-ERROR, RP-SMMA; TR1M/TR2M/TRAM. **RP-DA is always filled from EF.SMSP** | 24.011 §6, §7.3, §8.2.5.2 | v1 | L |
| KS-SMS-003 | TPDUs SUBMIT, DELIVER and STATUS-REPORT; TP-MR, VP, SRR, RD; GSM 7-bit and UCS2; concatenation | 23.040 §9.2.2, §9.2.3; 23.038 | v1 | U |
| KS-SMS-004 | Carried over NAS: SMS requested and allowed; payload container type SMS; MO from idle; MT through paging | 24.501 §5.4.5 | v1 | L |
| KS-SMS-005 | Memory full and RP-SMMA notification | 24.011 §6.3.3 | v1 | L |
| KS-SMS-006 | Test hooks used by the SMS gate (replay, resubmit with or without TP-RD, MT acknowledgement mode), clearly labelled as injections | — | v1.x (P4) | G |

### 2.5 RRC, UE side (TS 38.331 j40; TS 38.304 j30)
| ID | Requirement | § | Pri | Ver |
|---|---|---|---|---|
| KS-RRCU-001 | System information (MIB, SIB1, SIB2–4); cell barring and reservation | 38.331 §5.2.2 | v1 | U, L |
| KS-RRCU-002 | Cell selection and reselection: S-criterion, ranking, priorities, Treselection | 38.304 §5.2.3, §5.2.4 (T0) | v1 | L |
| KS-RRCU-003 | Connection establishment: 5G-S-TMSI part 1 or a random value; establishment cause from NAS; selected PLMN, registered AMF, NSSAI; RRCReject; T300 | 38.331 §5.3.3 | v1 | U, L |
| KS-RRCU-004 | Initial AS security activation; RRC and UP keys | 38.331 §5.3.4; 33.501 §6.7.4, A.8 | v1 | U, I |
| KS-RRCU-005 | Reconfiguration (SRB2, DRBs with SDAP and PDCP config, NAS PDU list). Failure leads to re-establishment | 38.331 §5.3.5 | v1 | I |
| KS-RRCU-006 | Handover: reconfiguration with sync, masterKeyUpdate with NCC, T304, contention-free RA | 38.331 §5.3.5.5.2; 33.501 §6.9.2.3 | v1 | L, I |
| KS-RRCU-007 | Measurements: configuration, layer-3 filtering, events A1–A5, periodic reports | 38.331 §5.5, §5.5.2, §5.5.3.2, §5.5.4.2–5.5.4.6 | v1 | U, L |
| KS-RRCU-008 | Radio link failure (T310/N310/N311) and re-establishment (T311/T301) | 38.331 §5.3.10, §5.3.7 | v1 | L |
| KS-RRCU-009 | RRC release (with or without suspend, with redirect); actions on going to RRC_IDLE | 38.331 §5.3.8, §5.3.11 | v1 | L |
| KS-RRCU-010 | UE capability transfer from personas | 38.331 §5.6.1 | v1 | A |
| KS-RRCU-011 | DL/UL information transfer; paging on PF/PO with DRX | 38.331 §5.7.1, §5.7.2, §5.3.2; 38.304 §7 (T0) | v1 | U, L |
| KS-RRCU-012 | RRC_INACTIVE: suspend, RNA update, resume and its failure, T319 | 38.331 §5.3.13, §5.3.8.3 | v1.x (P3b) | L |

### 2.6 RRC, CU side (TS 38.331 j40; TS 38.300 j40)
| ID | Requirement | § | Pri | Ver |
|---|---|---|---|---|
| KS-RRCC-001 | Connection management; release on inactivity; re-establishment checks | 38.331 §5.3.3, §5.3.7, §5.3.8 | v1 | L |
| KS-RRCC-002 | Ordering with Initial Context Setup: SMC before DRBs. Ask the UE for its capabilities only if the ICS carries none, then send UE Radio Capability Info Indication | 38.331 §5.3.4, §5.6.1; 38.413 §8.14.1 | v1 | L (N-21) |
| KS-RRCC-003 | QFI-to-DRB mapping; GBR admission, with configurable refusals | 38.300 §12 (T0 reading) | v1 | L |
| KS-RRCC-004 | Handover decision on A3/A5: Xn if an Xn peer exists, N2 otherwise. Can be forced from the CLI | 38.300 §9.2.3 (T0 reading) | v1 | L |
| KS-RRCC-005 | CN paging dispatched to cells; RAN paging (v1.x) | 38.300 §9.2.5 (T0 reading) | v1 | L |
| KS-RRCC-006 | RRC_INACTIVE driven by CN assistance information; context retrieval; path switch on resume | 38.300 §9.2.2 (T0 reading) | v1.x (P3b) | L |

### 2.7 PDCP (TS 38.323 j10), SDAP (TS 37.324 j00), security keys (TS 33.501 j70)
| ID | Requirement | § | Pri | Ver |
|---|---|---|---|---|
| KS-PDCP-001 | Entities for SRBs and DRBs; 12- or 18-bit SNs; state variables; t-Reordering; in-order or out-of-order delivery | 38.323 §5.1–5.2 (T0) | v1 | U, F |
| KS-PDCP-002 | Ciphering and integrity per COUNT, BEARER and DIRECTION. On an SRB, integrity failure leads to re-establishment; on a DRB the packet is discarded and counted | 38.323 §5.8–5.9 (T0); 33.501 §6.5, §6.6, Annex D | v1 | U (KATs) |
| KS-PDCP-003 | UP integrity per the UP security policy and the maximum integrity-protected data rate | 33.501 §6.6.1 | v1 | L |
| KS-PDCP-004 | Re-establishment, data recovery, status reports; export and import of COUNT for SN status transfer | 38.323 §5.1.2, §5.4, §5.5 (T0) | v1 | L, I |
| KS-SDAP-001 | Header configuration, QFI-to-DRB mapping, default DRB | 37.324 §5.2, §5.3, §6.2 (T0) | v1 | U |
| KS-SDAP-002 | DL RDI/RQI and reflective mapping. A packet with an unknown QFI is discarded and counted, never silently accepted | 37.324 §5.3.2 (T0) | v1 | L |
| KS-SDAP-003 | UL QFI marking; end-marker control PDU when a flow is remapped | 37.324 §5.2.1, §5.3.1 (T0) | v1 | U |
| KS-SEC-001 | Key hierarchy: K_AUSF, K_SEAF, K_AMF, algorithm keys, K_gNB, NH, K_NG-RAN\*, K_AMF′. The UE derives NH from its own K_AMF, which checks the AMF's NH independently | 33.501 A.2, A.6–A.11, A.13; 33.220 Annex B.2 | v1 | U (independent Python oracle), L |
| KS-SEC-002 | Keys across CM/RRC transitions and handover: horizontal and vertical derivation, NCC | 33.501 §6.8.1.2, §6.8.2, §6.9.2.3 | v1 | L |
| KS-SEC-003 | NEA and NIA 0–3 (SNOW 3G under the GSMA SAGE undertaking) | 33.501 Annex D; 35.215–223; 33.401 Annex C | v1 | U |

### 2.8 Ideal RLC/MAC and radio environment
| ID | Requirement | Spec | Pri | Ver |
|---|---|---|---|---|
| KS-L2R-001 | Ideal RLC with AM/UM/TM semantics. Latency, jitter, loss and rate configurable per link; "max retransmissions reached" maps to RLF | 38.322 j30 (semantics) | v1 | U |
| KS-L2R-002 | Abstract MAC: C-RNTI; random access as a timed exchange with real contention resolution; a grant-delay model; no HARQ | 38.321 j40 (semantics) | v1 | U |
| KS-L2R-003 | Radio model: cells (PCI, NCI, ARFCN, TAC, position, power, antenna) and UE trajectories. The pathloss model is a recorded choice (a B-row, e.g. TR 38.901 UMa/UMi/InH); shadowing is seeded. Outputs SS-RSRP, SS-RSRQ and SS-SINR | 38.215 j40 | v1 | U (determinism) |
| KS-L2R-004 | Radio link monitoring: SINR mapped to in-sync and out-of-sync | 38.133 j60 (T0) | v1 | L |
| KS-L2R-005 | Events: cell off/on, attenuation steps, UE battery pull, sudden loss | — | v1 | L |
| KS-L2R-006 | Measurement gaps (inter-frequency); full RLC/MAC with an abstract PHY | 38.331 §5.5.2; 38.321; 38.322 | v1.x / Ph2 | L |

### 2.9 NGAP (TS 38.413 j40; transport TS 38.412 j00)
| ID | Requirement | § | Pri | Ver |
|---|---|---|---|---|
| KS-NGAP-001 | SCTP with PPID 60. Stream 0 for non-UE-associated messages, one stream per UE, within the negotiated count. Re-establish the association after loss and redo NG Setup, honouring Time to wait. Several AMFs and AMF sets | 38.412 §7; 38.413 §8.7.1 | v1 | U, L |
| KS-NGAP-002 | NG Setup; RAN Configuration Update; AMF Configuration Update | §8.7.1–8.7.3 | v1 | L |
| KS-NGAP-003 | Initial UE Message; DL/UL NAS Transport; NAS Non Delivery Indication | §8.6.1–8.6.4 | v1 | L |
| KS-NGAP-004 | Initial Context Setup and its failure (CN assistance information for INACTIVE in v1.x) | §8.3.1 | v1 | L |
| KS-NGAP-005 | UE Context Release Request (user inactivity, **radio connection with UE lost**, failures); Release Command and Complete | §8.3.2, §8.3.3 | v1 | L |
| KS-NGAP-006 | UE Context Modification | §8.3.4 | v1 | L |
| KS-NGAP-007 | PDU Session Resource Setup, Release, Modify, Notify and Modify Indication. A command for an unknown session is refused cleanly, never a crash | §8.2.1–8.2.5 | v1 | L, F |
| KS-NGAP-008 | Paging | §8.5.1 | v1 | L |
| KS-NGAP-009 | N2 handover: Handover Preparation, Resource Allocation, Notification, Cancellation; UL/DL RAN Status Transfer; forwarding tunnels | §8.4.1–8.4.3, §8.4.5–8.4.7 | v1 | L |
| KS-NGAP-010 | Path Switch Request carrying **the UE's real security capabilities**; NH/NCC handling | §8.4.4; 33.501 §6.7.3 | v1 | L |
| KS-NGAP-011 | Error Indication and the error-handling rules of clause 10 (AP IDs per §10.6, criticality) | §8.7.5, §10, §10.6 | v1 | F, L |
| KS-NGAP-012 | NG Reset, full and partial, both directions, any list size | §8.7.4 | v1 | U, L (N-20) |
| KS-NGAP-013 | AMF Status Indication: mark GUAMIs unavailable and select the backup AMF | §8.7.6 | v1 | L |
| KS-NGAP-014 | UE Radio Capability Info Indication | §8.14.1 | v1 | L |
| KS-NGAP-015 | Reroute NAS Request; Overload Start/Stop; RRC Inactive Transition Report | §8.6.5, §8.7.7, §8.7.8, §8.3.5 | v1.x | L |
| KS-NGAP-016 | 128- and 160-bit TransportLayerAddress; NG over IPv6 | 38.414 §5.1 | later | — |

### 2.10 XnAP (TS 38.423 j40; 38.420 j10, 38.422 j00, 38.424 j00), F1AP (TS 38.473 j40; 38.470 j20, 38.472 j00, 38.474 j00), E1AP (TS 37.483 j40; 37.480 j10, 37.482 j00)
| ID | Requirement | § | Pri | Ver |
|---|---|---|---|---|
| KS-XNAP-001 | SCTP (PPID 61, port 38422); Xn Setup; NG-RAN node configuration update; Error Indication; Reset | 38.423 §8.4 (T0) | v1 | I, L, F |
| KS-XNAP-002 | Handover Preparation with the UE context (security capabilities, K_NG-RAN\*, NCC, PDU sessions, RRC container); Ack and Failure; SN Status Transfer; Handover Cancel; UE Context Release | 38.423 §8.2 (T0) | v1 | I, L |
| KS-XNAP-003 | Xn-U forwarding (DL, and UL when offered) with NR-U framing; End Marker relayed | 38.424; 38.425 | v1 | L |
| KS-XNAP-004 | Retrieve UE Context; RAN Paging; Xn-U Address Indication | 38.423 §8.2 (T0) | v1.x (P3b) | L |
| KS-F1AP-001 | The DU opens SCTP (PPID 62, port 38472); F1 Setup with a DU-built MIB and SIB1; gNB-DU/CU configuration updates | 38.472; 38.473 §8.2 (T0) | v1 | I |
| KS-F1AP-002 | Initial UL RRC Message Transfer, DL and UL RRC Message Transfer (SRB ID width per the ASN.1) | 38.473 §8.4 (T0) | v1 | I, U |
| KS-F1AP-003 | UE Context Setup, Modification and Release; Release Request from the DU on RLF; Modification Required; Paging | 38.473 §8.3 (T0) | v1 | I |
| KS-F1AP-004 | F1-U: the DU allocates the DL TEID; NR-U | 38.470; 38.474; 38.425 | v1 | I |
| KS-F1AP-005 | Handover between DUs under one CU | 38.401 j30 (T0) | v1 | L |
| KS-E1AP-001 | SCTP (PPID 64, port 38462); E1 Setup from either side | 37.482; 37.483 §8.2 (T0) | v1 | I |
| KS-E1AP-002 | Bearer Context Setup, Modification and Release (plus Modification Required and Release Request), with UP security and PDCP COUNT status for handover | 37.483 §8.3 (T0) | v1 | I, L |
| KS-E1AP-003 | Inactivity notification, which drives the NGAP user-inactivity release; DL Data Notification (v1.x) | 37.483 §8.3 (T0) | v1 / v1.x | L |

### 2.11 GTP-U, NR-U and the PDU Session Container
| ID | Requirement | § | Pri | Ver |
|---|---|---|---|---|
| KS-GTPU-001 | GTPv1-U; Echo; Error Indication (sent for an unknown TEID, acted on when received); Supported Extension Headers Notification | 29.281 §5, §7.2, §7.3.1 | v1 | U, F |
| KS-GTPU-002 | PDU Session Container: DL type 0 (QFI, RQI, PPP/PPI) and UL type 1; padding; unknown optional fields skipped | 38.415 §5.5.2, §5.5.3, §5.6 | v1 | U |
| KS-GTPU-003 | End Marker sent, relayed and handled at handover | 29.281 §7.3.2 | v1 | L |
| KS-GTPU-004 | NR-U DL USER DATA and DL DATA DELIVERY STATUS | 38.425 j10 (T0) | v1 | I |
| KS-GTPU-005 | IP fragmentation and reassembly of GTP-U packets; realistic MTU, no jumbo frames | 38.414 §5.3 | v1 | L (the F-28 class) |
| KS-GTPU-006 | DSCP marking from 5QI/ARP | 38.414 §5.4 | v1.x | U |

### 2.12 Control, observability and scenarios
| ID | Requirement | Pri | Ver |
|---|---|---|---|
| KS-CTL-001 | Every node runs as a daemon with a control endpoint. It survives SSH loss and works under systemd | v1 | G |
| KS-CTL-002 | `ksim-ctl` keeps nr-cli's verbs and its `<node> --exec '<cmd>'` form. Output is KEY=value by default, `--json` or `--format=nrcli` on request. Fixed exit codes ([`cli.md`](cli.md) §2) | v1 | G |
| KS-CTL-003 | NDJSON event stream with stable names, each registered with its spec clause; a `wait` primitive | v1 | G |
| KS-CTL-004 | pcapng per interface. Uu RRC and NAS as Exported-PDU; PDCP as `pdcp-nr`; F1AP/E1AP/NGAP/XnAP; GTP-U; APDUs as GSMTAP-SIM. Plaintext NAS only when asked for | v1 | U (tshark decodes everything) |
| KS-CTL-005 | Prometheus metrics: procedures, causes, latencies, per-QFI bytes, handover outcomes, RLF; RAN counters labelled with TS 28.552 names | v1 | L |
| KS-CTL-006 | Fault injection, off by default and recorded in the run manifest. Plus named negative controls that reproduce old UERANSIM leniencies on purpose | v1 | L |
| KS-CTL-007 | `capabilities`, `VERSION`, `COMMIT` and `SPEC_PINS` queries | v1 | G |
| KS-SCN-001 | Scenario YAML: topology (AMFs, CU-CPs, CU-UPs, DUs, cells, Xn links), UE groups (IMSI ranges, card template, persona, mobility, sessions), timeline, assertions | v1 | U |
| KS-SCN-002 | Seeded randomness, deterministic internal ordering, replay against a recorded core | v1 | U |
| KS-SCN-003 | Assertions print kaluza-core's row format (`  PASS  name got=…`) | v1 | G |
| KS-SCN-004 | Device personas modelled on the S22+, OnePlus 9 Pro, RM520N and RG255C, from captures plus the U1/U2 capability tables | v1 (v0) / v1.x | A |
| KS-SCN-005 | Up to 100 UEs: ramp-up, idle/connected churn, trajectories, cell outages, forced handovers | v1 | L |

### 2.13 AT port, optional (TS 27.007 j60, TS 27.005 j00, ITU-T V.250)
| ID | Requirement | Pri | Ver |
|---|---|---|---|
| KS-AT-001 | Per-UE AT interface on a pty or TCP, using V.250 syntax, result codes, +CMEE and URCs | v1.x (P3c) | U |
| KS-AT-002 | TS 27.007 core: +CGSN, +CIMI, +CFUN, +CPIN, +COPS, +C5GREG, +CGDCONT, +CGACT, +CGPADDR, +C5GNSSAI, +CSQ, +CEER | v1.x | U, L |
| KS-AT-003 | SIM access passthrough to the card: +CSIM, +CRSM, +CCHO, +CCHC, +CGLA (so lpac's AT backend and pySim over AT work) | v1.x | I |
| KS-AT-004 | TS 27.005 SMS: +CMGF, +CSCA, +CMGS, +CNMI, +CMGR/+CMGL/+CMGD | v1.x | L |
| KS-AT-005 | Quectel extension subset for the RM520N and RG255C personas (QENG, QNWPREFCFG, QNETRC, QRSRP/QRSRQ/QSINR, QSIMSTAT). Written from the manuals' behaviour, never from their text ([research/quectel.md](research/quectel.md)) | v1.x | A |

### 2.14 Phase-2 and later families (placeholders; each gets its own catalogue when scheduled)
| ID prefix | Family | Main specs | Pri |
|---|---|---|---|
| KS-POS | LPP (UE) and NRPPa (gNB) with ground-truth geometry: E-CID, UL-RTOA, SRS-RSRP, DL-TDOA, AoA | 37.355 j30, 38.455 j30, 24.571, 38.305 | Ph2, first |
| KS-IMS | IMS UA: ISIM AKA, sec-agree ESP, VoNR call flows, SMS over IP | 24.229, 33.203, 31.103, GSMA NG.114 | Ph2 |
| KS-E2, KS-O1 | E2 agents (KPM, RC, CCC); O1 NETCONF/YANG, VES, PM files | O-RAN WG3, WG10; TS 28.541/28.552 | Ph2 |
| KS-N3G | Non-3GPP access (NWu, NWt, N5CW); two-access UE | 24.502, 33.501 §7A | Ph2 |
| KS-L2 | Real RLC and MAC with an abstract PHY | 38.321, 38.322, 38.214 (MCS tables) | Ph2 |
| KS-XP, KS-FAPI | eBPF express data path and scale mode; FAPI bridge to an OCUDU DU | SCF 222.10 | later |
| KS-URSP, KS-ETH, KS-SNPN, KS-DS, KS-ATSSS | URSP; Ethernet PDU and 5G LAN; SNPN with EAP-TLS/TTLS; dual-stack transport; ATSSS | 24.526, 24.501, 23.122 §4.9.3, 38.414, 24.193 | later |

## 3. Non-functional requirements

### 3.1 Fidelity
- Every mandatory and conditional IE, every timer, and the abnormal cases of each procedure listed above.
- When the core breaks a rule, the UE reacts as the spec says, and the sim also emits `CORE_ANOMALY` with the clause.

**UERANSIM leniencies that must not be repeated:**

| # | Leniency (where it is recorded) | kaluza-sim rule |
|---|---|---|
| L1 | No UE CONTEXT RELEASE REQUEST when a UE vanishes; the gNB only logs "signal lost" (measured by kaluza-core 2026-09-13) | RLF or radio loss leads to a release request with "radio connection with UE lost" (KS-NGAP-005, KS-L2R-005) |
| L2 | No registration after "re-registration required" (UERANSIM `src/ue/nas/mm/dereg.cpp`: a TODO) | KS-MM-011 |
| L3 | The back-off timer after #29 is ignored: the request is resent every 3–5 s (`kaluza-core/docs/compliance/dn-aaa/`) | KS-SM-003 |
| L4 | T3396 run for #69 where T3585 is due; the first request after a refusal is lost (`compliance/nsacf/` AC-G15) | KS-MM-014 |
| L5 | An unknown optional IEI reported as a MAC mismatch (`compliance/nsacf/` S13-h) | KS-MM-018 |
| L6 | The downlink QFI is ignored (`compliance/ran/README.md`) | KS-SDAP-002, KS-GTPU-002 |
| L7 | RP-DA is sent empty (`compliance/smsf/`). The kaluza-core SMS docs give two RP-DA length bounds; the T0 reading settles it as an `-S` row | KS-SMS-002 |
| L8 | AMF STATUS INDICATION is only logged (`docs/dev/handoff/2026-09-13-packaging.md`) | KS-NGAP-013 |
| L9 | PATH SWITCH REQUEST carries hard-coded UE security capabilities (UERANSIM `CU-DU-SPLIT-STATUS.md`) | KS-NGAP-010, KS-XNAP-002 |
| L10 | SCTP stream IDs are ignored (`ignoreStreamIds`, `docs/dev/handoff/2026-09-12-amf-t2.md`) | KS-NGAP-001 |
| L11 | The gNB never re-associates after an AMF restart | KS-NGAP-001 |
| L12 | A session set up from the CLI while connected is barred by UAC (fixed in the fork at `020936fc`; `compliance/roaming/` RM-G17) | KS-MM-013 |
| L13 | The host kernel sends RS and MLD into every `uesimtun` (kaluza-core P-33) | Each UE has its own netns; IPv6 sysctls are set before link-up; IPv6 is off unless the session is IPv6 |
| L14 | No initial-NAS protection or RINMR behaviour (`compliance/nsacf/` AC-09) | KS-MM-005 |
| L15 | Robustness and limits: a crash at `-n 4`, a 512-UE cap, a ~180 Mbit/s ceiling, a malformed GTP-U packet kills `nr-gnb` (fork docs) | No network input may end a sim process (F); §3.5 |

### 3.2 Independence and clean room
- **Independence:** the rules are in [ADR 0005](adr/0005-independence-from-kaluza-core.md). No kaluza-core code or tables, and no output of its encoders used as an expected value.
- **Clean room:** the rules are in [ADR 0004](adr/0004-clean-room-licensing.md).
  - UERANSIM (AGPL-3.0), Duranta/OAI (CSSL v1.0) and onomondo-uicc (GPL-3.0) are read only for facts, never copied.
  - Wireshark and pySim (GPL) and pycrate (LGPL) run only as external oracles, never linked.
  - OCUDU (BSD-3-Clause-Open-MPI) and PacketRusher (Apache-2.0) may be copied, with attribution.
  - Every source is a lead, never a spec.

### 3.3 Determinism
- **Seeds:** one seed per run. Per-UE seeds are derived from it for ECIES ephemeral keys, RRC transaction IDs, random UE identities, TEIDs and NGAP IDs.
- **Run manifest:** records the sim commit, config hash, seed, spec pins, asn1c commit, and peer versions (kaluza-core tag, OCUDU commit).
- **Replay:** replaying recorded N2/N3 traffic against a mock core regenerates byte-identical UE-originated PDUs. `--insecure-deterministic-crypto` exists for that purpose and refuses any non-loopback AMF.

### 3.4 Observability
- KS-CTL-003 to KS-CTL-005, plus logs correlated per UE: SUPI, RNTI, NGAP/F1AP/E1AP/XnAP IDs.
- SUPIs may appear in lab logs. Key material never does (§3.6).

### 3.5 Performance in fidelity mode (proposed; calibrate on kaluza-uesim in P0)
| Metric | Target |
|---|---|
| One UE with NEA2 on the DRB | ≥ 200 Mbit/s DL, ≥ 100 Mbit/s UL |
| With NIA2 UP integrity at full rate | ≥ 50 Mbit/s |
| 100 UEs, aggregate DL | ≥ 400 Mbit/s |
| Added processing latency, excluding configured link delay | median ≤ 1 ms, p99 ≤ 5 ms |
| 100 UEs registered with one session each, 10 attaches in parallel | ≤ 60 s |
| Memory | ≤ 2 GiB |

The on-air link measures 41 Mbit/s DL and 7 Mbit/s UL, so the sim is never the bottleneck for QoS rows.

### 3.6 Key material
- **The `SecretBytes` type** holds K, OPc, ADM, PIN, K_AUSF and every key below it, CK/IK, RES/XRES and NH. It refuses to print.
- **Where keys come from:** only 0600 files (checked at start) or sealed card secrets.
- **Key logs:** the test-only key log is opt-in, recorded in the manifest, and written 0600. Only AS keys can be exported (for `pdcp-nr` decryption); K and OPc have no export path.
- **Real cards:** the PC/SC backend keeps K inside the card.
- **Provisioning:** K and OPc reach the core's UDR only inside `ksim-sim`'s API calls. Bodies are built in memory and never logged, and the client credential is a 0600 file on the dev PC ([ADR 0008](adr/0008-subscriber-provisioning-api.md)).
- **Lab card files:** never copy them into the repo or any log. `/home/amadeus/Development/ran/usim/*.md` holds keys and an ADM1 PIN in clear text.
- **CI canary:** the "secret canary" runs a scenario with a known test K and expects 0 hits in every log, event and pcap.

### 3.7 Operability
- **Host:** kaluza-uesim (Proxmox VM 105), VLAN 30.
- **Addresses:** kaluza-uesim holds .20–.23 (UERANSIM, n3iwue and their aliases). kaluza-sim's RAN nodes use **172.30.30.30–.39**, each in its own ipvlan (L2) netns on `ens19`, and bind their own GTP-U port 2152. The V-UPF pins `ens19`'s MAC for these addresses, so macvlan or another NIC is not an option. F1 and E1 stay on a host-internal bridge ([`lab.md`](lab.md)).
- **ID collisions:** gNB IDs, NCIs and PCIs must not collide with OCUDU or UERANSIM. A startup check refuses collisions it can see.
- **TACs are shared:** every cell advertises one the AMF serves (000001; 000003 on SNPN cells; 000007 from wave 40) and never a non-3GPP TAC ([`lab.md`](lab.md) §3).
- **No RF:** no RF libraries. The systemd units use PrivateDevices, except `/dev/net/tun`.
- **Lab etiquette:**
  - stop processes with `pkill -x`, never `pkill -f`;
  - run only in windows agreed with the kaluza-core session, and never during another session's set;
  - read-only on kaluza-core and k3s.
