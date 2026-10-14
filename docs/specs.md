# Specifications: pinned index

**Rule:** use the highest Rel-19 (`j`) version on the 3GPP archive on the day, and re-read the archive at each build phase's T0.
- Rel-20 (`k`) is taken only after Rel-20's ASN.1/OpenAPI freeze (June 2027), item by item. kaluza-core follows the same rule. Some `k` versions already exist (31.102, 27.007, 38.133); they are ignored.
- The versions below were **read from the archive on 2026-10-14**. The archive refuses curl's default User-Agent, so send a browser one.
- **Documents are not tracked in git** (3GPP copyright, size). P0 fetches them into `spec/3gpp/<series>/` (gitignored) and records each sha256 and what is derived from it in `spec/INDEX.tsv`. Extracted ASN.1 and NAS tables are committed with their source's sha256.
- URL pattern: `https://www.3gpp.org/ftp/Specs/archive/<series>_series/<spec>/<file>`, e.g. `38_series/38.473/38473-j40.zip`. Version letters: `j` = Rel-19, so `j40` = V19.4.0.

**Local copies:** kaluza-core keeps many of these at `/home/amadeus/Development/kaluza-core/docs/3gpp/ts/<series>/` (marked "local" below). Read them there or copy them into `spec/3gpp/`. Never cite kaluza-core's interpretation of them.

## 1. v1: needed now

| Spec | Version | Local? | For |
|---|---|---|---|
| TS 24.501 | j80 (V19.8.0) | local | NAS 5GMM/5GSM, UE policy container framing, cause and timer tables |
| TS 24.007 / 24.008 | j50 / j50 | local | L3 message structure (§11 error handling); ePCO containers (§10.5.6.3A) |
| TS 24.011 / 23.040 / 23.038 | j00 / j00 / j00 | local | SMS CP/RP; TPDU; alphabets |
| TS 23.003 | j80 | local | Identities (SUPI, SUCI, GUTI, GUAMI, PEI) |
| TS 23.122 | j70 | local | PLMN selection; SNPN selection (§4.9.3, later) |
| TS 23.501 / 23.502 | j90 / j90 | local | Architecture and procedures (reading, not codecs) |
| TS 38.300 | j40 | local | NR stage 2 (handover §9.2.3, paging §9.2.5, INACTIVE §9.2.2) |
| TS 38.331 | j40 | local | RRC (UE and CU); ASN.1 incl. `NR-InterNodeDefinitions` |
| TS 38.413 / 38.412 / 38.414 | j40 / j00 / j00 | local | NGAP; NG signalling transport (SCTP); NG-U transport |
| TS 38.415 | j10 | local | PDU Session user plane protocol (PDU Session Container) |
| TS 29.281 | j20 | local | GTP-U |
| TS 33.501 | j70 | local | Security: AKA, SMC, key hierarchy (Annex A), SUCI (Annex C), NULL algorithms (Annex D) |
| TS 33.102 / 33.220 / 33.401 / 33.402 | j10 / j10 / j20 / j00 | local | SQN management (Annex C); KDF (Annex B.2); AES test data (Annex C); EAP-AKA′ key derivation |
| TS 35.205–208 / 35.215–223 / 35.231–236 | j00 | local | MILENAGE and its test data; SNOW 3G and ZUC and their test data; TUAK; MILENAGE-256 |
| **TS 38.473** | **j40** | fetch | F1AP |
| **TS 38.470 / 38.472 / 38.474** | j20 / j00 / j00 | fetch | F1 general, signalling transport, data transport |
| **TS 37.483** | **j40** | fetch | E1AP (37.483 since Rel-17; was 38.463) |
| **TS 37.480 / 37.482** | j10 / j00 | fetch | E1 general; signalling transport |
| **TS 38.423** | **j40** | fetch | XnAP |
| **TS 38.420 / 38.422 / 38.424** | j10 / j00 / j00 | fetch | Xn general, signalling transport, data transport |
| **TS 38.425** | j10 | fetch | NR user plane protocol (NR-U) |
| **TS 38.401** | j30 | fetch | NG-RAN architecture (F1/E1 procedures across nodes) |
| **TS 38.323** | j10 | fetch | PDCP |
| **TS 37.324** | j00 | fetch | SDAP |
| **TS 38.322 / 38.321** | j30 / j40 | fetch | RLC and MAC (v1: semantics of the ideal link; Ph2: full) |
| **TS 38.304** | j30 | fetch | UE idle and inactive procedures (cell selection, paging occasions) |
| **TS 38.133 / 38.215** | j60 / j40 | fetch | RRM (RLM thresholds); physical-layer measurements (RSRP, RSRQ, SINR) |
| **TR 38.901** | j50 | fetch | Channel models (pathloss, shadowing) |
| **TS 38.306** | j40 | fetch | UE radio access capabilities (personas) |
| **TS 31.101 / 31.102** | j00 / **j60** | fetch | UICC-terminal interface (3GPP); USIM application (DF.5GS, GET IDENTITY) |
| **ETSI TS 102 221** | **V18.4.0** | fetch (etsi.org) | UICC-terminal interface: physical and logical characteristics |
| **TS 31.121** | j00 | fetch | USIM conformance tests (a checklist only) |
| **TS 38.523-1 / 38.508-1** | j60 / j50 | fetch | 5GS UE protocol conformance and the common test environment (sources of test purposes only) |

## 2. v1.x

| Spec | Version | For |
|---|---|---|
| TS 27.007 | j60 | AT command set (the optional AT port) |
| TS 27.005 | j00 | SMS AT commands |
| ITU-T V.250 | current | Basic AT syntax and result codes |
| TS 35.231–236 | j00 (local) | TUAK and MILENAGE-256 card blocks |

## 3. Phase 2

| Spec | Version | For |
|---|---|---|
| TS 37.355 | j30 | LPP |
| TS 38.455 | j30 | NRPPa |
| TS 38.305 / 24.571 | j30 / j50 | NR positioning stage 2; UE–LMF NAS transport |
| TS 24.229 / 33.203 / 31.103 | j70 (local) / j10 (local) / j10 | IMS UA: SIP, IMS-AKA and sec-agree, ISIM |
| GSMA NG.114 | v11.0 (local at `/home/amadeus/Development/kaluza-core/docs/gsma/ng-series/`) | IMS profile for voice, video and messaging over 5GS |
| TS 24.502 | j40 (local) | Non-3GPP access NAS |
| TS 38.214 | j50 | MCS and TBS tables for the full-L2 PHY abstraction |
| TS 28.541 / 28.552 | local | NRM for O1; PM counter names (already used as metric labels in v1) |
| **O-RAN Alliance** (free registration) | latest at download | WG3: E2GAP, E2AP, E2SM-KPM, E2SM-RC, E2SM-CCC. WG10: O1 Interface, OAM architecture and information model. WG1: architecture description. WG4: CUS and M-plane (only if an O-RU facade is built). WG5: C-plane and U-plane profiles for F1/E1/Xn/NG interop |

## 4. Later

| Spec | Version | For |
|---|---|---|
| TS 24.526 | j40 | URSP / UE policies |
| TS 31.111 / 31.115 / 31.116 | latest `j` | USAT; secured packets (SoR and UPU via the card) |
| SCF 222.10 (FAPI) | latest | FAPI bridge to an OCUDU DU |
| GSMA SGP.22 / SGP.32 | latest | eUICC (consumer / IoT RSP) |
| TS 24.193 | j60 | ATSSS |

## 5. IETF (fetched as needed; kaluza-core keeps many at `/home/amadeus/Development/kaluza-core/docs/ietf/`)

| RFC | For |
|---|---|
| RFC 9260 (SCTP), RFC 6458 (sockets API) | NG, F1, E1, Xn transport |
| RFC 768, 791, 8200 | UDP, IPv4, IPv6 |
| RFC 4861, 4862, 4291 | IPv6 ND and SLAAC on PDU sessions (v1.x) |
| RFC 9048 (EAP-AKA′), RFC 3748 (EAP) | EAP-AKA′ primary authentication |
| RFC 1334, 1994 | PAP and CHAP in ePCO (v1.x) |
| RFC 8415 | DHCPv6 (later) |
