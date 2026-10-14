# The soft UICC: a SIM spoken to with real APDUs

**Requirement (user, 2026-10-14):** the UE must talk to a SIM using the actual standards.

In kaluza-sim the UE's ME side never holds K or OPc. It sends APDUs (ETSI TS 102 221, 3GPP TS 31.101/31.102) to a card, and the card does the AKA, the SQN check and, when provisioned to, the SUCI.

The card can be one of three kinds behind the same interface:
- **our soft card**, in-process (for scale) or behind a virtual PC/SC reader;
- **a real sysmoISIM card** in the OmniKey reader.

Requirements: [`requirements.md`](requirements.md) §2.1. Research: [`research/sim-tools.md`](research/sim-tools.md).

## 1. Why build our own card

No open soft card implements DF.5GS, GET IDENTITY (SUCI on the card) and TUAK together.
- onomondo-uicc is the most complete, but it is GPL-3.0 and Milenage-only, with no DF.5GS.
- swSIM, vsmartcard's vicc and jCardSim lack the USIM/5G parts.

pySim (`/home/amadeus/Development/ran/usim/pysim-src`) has a full TS 31.102 model and APDU decoders, which makes it the **oracle**, not the card.

Realistic SIM behaviour also buys protocol coverage the core cares about:
- **GUTI re-registration** from a stored context (EF.5GS3GPPLOCI / 5GS3GPPNSC; the AMF F-42 class);
- **SUCI computed on the card**;
- **forbidden-PLMN lists that persist**;
- **SoR and UPU updates** written back to the USIM (later).

## 2. Card OS (`src/uicc/os`)

- **File types:**
  - MF, DF, ADF and EF (transparent, linear fixed, cyclic, BER-TLV);
  - FCP templates (tags 82, 83, 84, 8A, 8B, 80, 81, 88, C6);
  - SFI addressing; life-cycle status.
- **Access control:** ARR in expanded format (EF.ARR 2F06 under MF, 6F06 inside ADF.USIM), with AM_DO/SC_DO evaluated per command.
- **PINs:** PIN1 (key reference 01), PIN2 (81), ADM1 (0A), with retry counters and enable/disable/change/unblock.
- **Logical channels:** MANAGE CHANNEL, 4 by default and configurable. Each channel has its own current file and per-application security status.
- **Commands:**
  - SELECT, STATUS, READ/UPDATE BINARY, READ/UPDATE/SEARCH RECORD, GET RESPONSE;
  - the PIN commands;
  - **AUTHENTICATE** with P2 = 0x81, the 3G context, which 5G AKA uses;
  - **GET IDENTITY** (`80 78 00 01`, when UST 124 + 125 are set);
  - ACTIVATE/DEACTIVATE FILE;
  - TERMINAL PROFILE.
  - FETCH and ENVELOPE are stubs in v1; USAT comes later.
- **T=0 semantics are on by default** (61xx → GET RESPONSE; 6Cxx → resend with Le), so the ME's T=0 handling is exercised the same way against soft and real cards.
- **Persistence:** write-through NVM with a journal and atomic rename.

## 3. Files present in v1

| Where | Files |
|---|---|
| MF | EF.ICCID 2FE2, EF.DIR 2F00 (the USIM AID, plus the ISIM AID in phase 2), EF.PL 2F05, EF.ARR 2F06 |
| ADF.USIM | EF.IMSI 6F07, EF.AD 6FAD, EF.UST 6F38, EF.EST 6F56, EF.KEYS 6F08, EF.KEYSPS 6F09, EF.LOCI 6F7E, EF.PSLOCI 6F73, EF.FPLMN 6F7B, EF.HPPLMN 6F31, EF.PLMNwAcT 6F60, EF.OPLMNwACT 6F61, EF.HPLMNwAcT 6F62, EF.EHPLMN 6FD9, EF.ACC 6F78, EF.SPN 6F46, EF.MSISDN 6F40, EF.SMS 6F3C, EF.SMSP 6F42, EF.SMSS 6F43, EF.ARR 6F06, EF.START-HFN 6F5B, EF.THRESHOLD 6F5C |
| DF.5GS 5FC0 | EF.5GS3GPPLOCI 4F01 (service 122), EF.5GS3GPPNSC 4F03 (122), EF.5GAUTHKEYS 4F05 (123), EF.UAC_AIC 4F06 (126), EF.SUCI_Calc_Info 4F07 (124), EF.OPL5G 4F08 (129), EF.SUPI_NAI 4F09 (130), EF.Routing_Indicator 4F0A (124). Phase 2 or later: 4F02/4F04 (non-3GPP LOCI and NSC), EF.URSP 4F0B, EF.TN3GPPSNN, EF.CAG, EF.SOR-CMCI, EF.KAUSF_DERIVATION (145) |
| Key files (write-only, ADM1) | Encoded like sysmoISIM's **EF.USIM_AUTH_KEY (AF20)**: an algorithm byte (Milenage or TUAK), K, OP/OPc. Plus **EF.USIM_SQN (AF30)**. One burn path then serves soft and real cards. Layout reference: `/home/amadeus/Development/ran/usim/pysim-src/pySim/sysmocom_sja2.py` |

The FIDs and service numbers above follow pySim's TS 31.102 model (`pySim/ts_31_102.py`). P0 re-checks them against TS 31.102 j60 (an `-T` row).

An opt-in `personality: sysmoISIM-SJA5` also presents that card's ATR, so stock pySim applies its card model.

## 4. Algorithms (`src/crypto`)

| Algorithm | Spec / KATs | Notes |
|---|---|---|
| MILENAGE f1–f5\* | TS 35.206; KATs from TS 35.208 | |
| TUAK | TS 35.231; KATs from TS 35.233 | Our own Keccak-f[1600] |
| MILENAGE-256 | TS 35.234–235; KATs from TS 35.236 | Our own Rijndael-256 (OpenSSL has no 256-bit block cipher) |
| SQN management | TS 33.102 Annex C | IND array, wrap-around, AUTS generation |
| ECIES Profile A (X25519) and B (compressed P-256) | TS 33.501 C.3; vectors from C.4 | Used by GET IDENTITY on the card, or by the ME |
| 5G key derivations | TS 33.501 A.2 (FC 0x6A), A.4 (0x6B), A.6 (0x6C), A.7 (0x6D); TS 33.220 Annex B.2 | ME side: RES\*, K_AUSF, K_SEAF, K_AMF |

**5G AKA through the card:**
- **Command:** `00 88 00 81 22 | 10 RAND | 10 AUTN`.
- **Success:** `DB 08 RES 10 CK 10 IK [08 Kc]`.
- **Synch failure:** `DC 0E AUTS`.
- **MAC failure:** SW 9862.
- **ME side:** the ME derives RES\*, K_AUSF, K_SEAF and K_AMF itself. The K_AUSF input SQN⊕AK is simply AUTN[0..5], so an opaque real card doesn't matter.
- **Storage:** with service 123, K_AUSF and K_SEAF go to EF.5GAUTHKEYS. With service 122, the ME uses EF.5GS3GPPLOCI and EF.5GS3GPPNSC.

## 5. APDU transport (`src/uicc/transport`)

The interface is asynchronous:
```
IApduTransport { reset(cb); transmit(capdu, cb); }
```

| Backend | What | Use |
|---|---|---|
| `InProc` | Calls the soft card directly; still completes through the shard queue | 100 UEs (pcsc-lite's default is only 16 readers) |
| `Vpcd` | vsmartcard protocol over TCP 35963+n. A 2-byte big-endian length frame; a 1-byte frame is a control code (0 off, 1 on, 2 reset, 4 ATR) | Card-side client: the soft card connects to pcscd's vpcd, so **pySim-shell sees it as a PC/SC reader**. Terminal-side server: a remote card connects without pcscd |
| `Pcsc` | pcsc-lite on the blocking pool: SCardConnect (T0 or T1), SCardTransmit | Real sysmoISIM cards in the OmniKey 3x21 on the dev PC (setup: `/home/amadeus/.claude/projects/-home-amadeus-Development-ran/memory/pysim-setup-ran.md`); K stays in the card |
| Card bridge | `ksim-sim serve --pcsc` on the dev PC exposes a real card over the vpcd framing. A UE in the lab VM connects with its `Vpcd` transport in the terminal role | Real cards for UEs running on kaluza-uesim, with no USB passthrough ([`lab.md`](lab.md) §7) |

A card is attached to exactly one terminal at a time, as a physical card sits in one reader. `ksim-ctl ue <n> sim remove|insert|swap` models card removal and swap ([`cli.md`](cli.md)).

**AT passthrough (v1.x).** On the optional AT port, +CSIM, +CRSM and +CCHO/+CCHC/+CGLA forward APDUs to the same transport. lpac's AT backend, which uses CCHO/CGLA, can then reach the card.

## 6. Tracing

A decorator on the transport emits GSMTAP type SIM (0x04), sub-type APDU or ATR, in the layout `pySim-trace.py gsmtap-udp` parses. It goes to 127.0.0.1:4729 and to the run's pcap.

**Redaction is on by default.** These are masked:
- CK, IK and Kc in AUTHENTICATE responses;
- VERIFY data;
- reads and writes of EF.5GAUTHKEYS (4F05), EF.5GS3GPPNSC (4F03), AF20 and AF30.

Unredacted traces need an explicit test-only flag and land in a 0600 file.

## 7. Card images (`src/uicc/image`, `cards/`)

- **Native format:** YAML, a DF/EF tree with FCP attributes and contents in hex or typed form. YAML because it is diffable and round-trips through the pySim oracle.
- **Secrets:** K, OPc or TOPc, ADM1 and PINs live in **a separate sealed file** (AES-256-GCM under a KEK held in a 0600 file or systemd-creds), never in the YAML.
- **Import:** from pySim-shell `fsdump --json`. **Export:** as a pySim-shell script with keys excluded. SAIP profile packages are imported later.
- **Templates:** `cards/usim-5g.yaml` and similar templates set UST/EST, SUCI_Calc_Info (scheme, key ID, home network public key, which is public topology config), the routing indicator, and the PLMN lists.

## 8. Test subscriber ranges and provisioning

**Decision (user, 2026-10-14):** a dedicated range for the simulator.

| Block | IMSIs | Use |
|---|---|---|
| 001/01 sim range | `001010000300000` – `001010000300999` (1,000) | All v1 scenarios |
| 999/70 sim range | `999700000300000` – `999700000300999` | Roaming scenarios |
| Reserved | `0010100010xxxxx` (100k) | The later scale mode |

**Collision check (2026-10-14, by ID only):**
- The core seeds use 001010000000121–001010000000384 (12 IMSIs, `deploy/nf/udr/subscribers.json`) and 999700000000001–999700000118893 (`deploy/k8s/plmn/h99970/udr/subscribers.json`).
- The phone and modem cards are 0010100001188{94,96,99} and 001010000001000.
- All are clear of the ranges above. kaluza-core checked the same against its seeds, by ueId only, and agreed (2026-10-14).
- `ksim-sim` re-checks before every import, printing only ueIds, never subscriber bodies.

**Sub-blocks of 100,** each a profile YAML:
- DNNs, S-NSSAIs, AMBR, SMS, SUCI scheme (null, A or B), routing indicator;
- the algorithm: Milenage now; TUAK and MILENAGE-256 blocks in v1.x.

**Default profiles.** They are modelled on the lab's existing subscribers, as kaluza-core described them on 2026-10-14:

| | 001/01 range | 999/70 range (roamers into 001/01) |
|---|---|---|
| S-NSSAI | 1/000001 (the default) | sst 1, no SD |
| DNNs | `internet` (5QI 9, IPv4v6) and `ims` (5QI 5, IPv4) | `internet`, IPv4, with `lboRoamingAllowed`. am-data scoped by `servingPlmn` |
| Home-routed | — | One sub-block (initially `9997000003001xx`) also gets `home` with `lboRoamingAllowed` false, so one UE holds both an LBO and a home-routed session. The `home` sm-data goes into the 999/70 UDR too |
| AMBR | UE-AMBR and Session-AMBR 1 Gbps | 1 Gbps as well. kaluza-core named no separate value |
| Other | `subsRegTimer` 3600; a GPSI (msisdn) per UE, collision-checked like the IMSIs | No IMS voice (IMS-VoPS 0) |
| SUCI | Null scheme, routing indicator **0000** | Null scheme, routing indicator **0000**; a few cards carry the default **0** to cover that path |
| SMS | `sms-data` and `sms-mng-data` only in sub-blocks whose profile tests SMS | as 001/01 |

- **Left out until the sim implements them:** S-NSSAI 1/000002 (it requires NSSAA), the `corp` DNN (DN-AAA secondary authentication) and `hcorp` (home-routed plus secondary authentication at the home DN-AAA). All three belong to P4.
- **Routing indicator.**
  - For a 001/01 home UE, the AMF sends no routing-indicator discovery factor. The 001/01 AUSF serves any RI, so the value changes nothing there; 0000 copies the gates.
  - For a 999/70 roamer, the visited AMF passes the RI to the home NRF, and the 999/70 UDM lists only `0000`. The default `0` (TS 23.003 §2.2B) also works. **Any other value fails** registration with UECM 400 NF_DISCOVERY_FAILURE.
- **SUCI scheme (user, 2026-10-14):** null on every sim card until P1 reaches its SUCI rows. The user then picks the Profile A/B key ids that the UDM's `kaluza.udm.suci.private-key.<id>` must hold. The UERANSIM fork's ML-KEM schemes 13/14 have no counterpart in kaluza-core.
- **Home-routed sessions** run V-UPF → SeGW-v → ipx-router → SeGW-h → H-UPF, through the H-SMF in namespace `kaluza-h99970`. Between UPF-VPP's W5 (phase 3 39A) and W7 (39B), home-routed runs on eUPF only.
- **IMS capacity:** the SMF's `ims` pool holds about 250 concurrent sessions, which is enough for v1. A 1000-UE `ims` run needs a kaluza-core change ([`lab.md`](lab.md) §8).

**Keys from one master secret:**
- The master secret lives in a 0600 file **outside both repos**, e.g. `~/.kaluza-sim/secrets/range-master.key`.
- Per IMSI, K = first 128 bits of HMAC-SHA-256(master, "K" ‖ IMSI). OPc is derived the same way under its own label (or computed from a per-range OP). TUAK and 256-bit blocks take wider outputs.
- The soft cards' sealed secrets and the core's subscriptions (provisioning bundles, or the fallback seed fragment) therefore come from one source. **A clear list of keys never exists**, and nothing prints a key.

**The provisioning flow** ([ADR 0008](adr/0008-subscriber-provisioning-api.md)):
1. `ksim-sim range derive --block 001010000300000/100` writes sealed card secrets for the block. It prints only the IMSIs and a fingerprint `K_FPR` (HMAC of a batch salt and K, truncated).
2. `ksim-sim range provision --block …` puts the block into the home PLMN's UDR through kaluza-core's provisioning API. `ksim-sim range deprovision --block …` removes it.
   - **Calls.** One `PUT …/provisioning/v1/subscribers/imsi-<IMSI>` per subscriber, or `DELETE` to remove one. They go to the UDR's provisioning listener on `:7779`, in namespace `kaluza` for 001/01 and `kaluza-h99970` for 999/70.
   - **From the dev PC only.** The UDR's NetworkPolicy admits only the OAM and the node. No pod restarts.
   - **Identity.** kaluza-sim's own Keycloak client (named by kaluza-core), which is exempt from key-entry step-up. Its credential is a 0600 file on the dev PC, e.g. under `~/.kaluza-sim/secrets/`, and is never printed.
   - **Keys.** K and OPc travel in clear inside the API's mTLS, and the UDR seals them itself. The bundle never carries `protectionParameterId`: beside key values, the UDR refuses it with PROTECTED_KEY_UNSUPPORTED.
   - **Output.** Bodies are built in memory from the derived keys and the profile, and are never logged or written to disk. The tool prints only the ueId, the HTTP status and `K_FPR`.
   - **Scope.** It refuses any IMSI outside the sim ranges above. Tell the core session before a first import or a bulk delete.
3. **Fallback:** `ksim-sim range seed --block …` writes the same bundles as a **0600 seed fragment** outside the repo, for a kaluza-core session to import. The seed is a create-only bootstrap, read at UDR start: it needs an `apply.sh` roll and cannot remove anyone. It is used only if the API is unavailable. This repo never edits kaluza-core files.
4. `ksim-sim burn` writes a real card over PC/SC: VERIFY ADM1 from the sealed file, then the EFs and AF20. **The user runs this step**, never an agent. Real cards outside the sim ranges keep the core's rule that **K/OPc are typed by a person**.

**The SubscriberBundle** (one per subscriber, the same documents as the core's seed entries; the models are the TS 29.505 and TS 29.519 types as served):

```json
{"ueId": "imsi-001010000300000",
 "documents": [
   {"resource": "subscription-data:identity-data", "body": {…}},
   {"resource": "subscription-data:provisioned-data:sm-data", "servingPlmn": "", "memberId": "1-000001", "body": {…}},
   …]}
```

- **Documents:**
  - `identity-data` and `authentication-subscription`;
  - provisioned `am-data`, and `sm-data` per slice;
  - `smf-selection-subscription-data`;
  - policy `am-data` and policy `sm-data`;
  - optionally `ue-policy-set`;
  - `sms-data` and `sms-mng-data` only for SMS profiles.
- **Scoping:** per-slice documents carry `memberId`, and per-PLMN documents carry `servingPlmn`.
- **Independence:** `ksim-sim` builds them from the spec's OpenAPI types and our own profile YAML, not from kaluza-core's code or seeds ([ADR 0005](adr/0005-independence-from-kaluza-core.md)).

**Never print:** subscriber seeds, sealed secrets, the provisioning credential, provisioning request bodies, `/home/amadeus/Development/ran/usim/*.md` (which hold keys and an ADM1 PIN in clear), or card images' secret files. When a seed must be read, parse the JSON and drop the authentication-data entries by `resource` before anything is printed. Never `head`, `cat` or `sed` a seed, not even behind a grep.
