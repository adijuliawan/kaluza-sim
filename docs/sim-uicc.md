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
| DF.5GS 5FC0 | EF.5GS3GPPLOCI 4F01, EF.5GSN3GPPLOCI 4F02, EF.5GS3GPPNSC 4F03 and EF.5GSN3GPPNSC 4F04 (all four with service 122), EF.5GAUTHKEYS 4F05 (123; 110 octets with 133), EF.UAC_AIC 4F06 (126), EF.SUCI_Calc_Info 4F07 (124), EF.OPL5G 4F08 (129), EF.Routing_Indicator 4F0A (124). EF.SUPI_NAI 4F09 only with service 130, which the P1 card leaves off. Phase 2 or later: EF.URSP 4F0B, EF.TN3GPPSNN, EF.CAG, EF.SOR-CMCI, EF.KAUSF_DERIVATION (145) |
| Key files (write-only, ADM1) | Encoded like sysmoISIM's **EF.USIM_AUTH_KEY (AF20)**: an algorithm byte (Milenage or TUAK), K, OP/OPc. Plus **EF.USIM_SQN (AF30)**. One burn path then serves soft and real cards. Layout reference: `/home/amadeus/Development/ran/usim/pysim-src/pySim/sysmocom_sja2.py` |

The FIDs and service numbers above were re-checked against TS 31.102 j60 and ETSI TS 102 221 V18.4.0 in P1 (KS-UICC-T3): all match. TS 31.102 §4.2.8 also requires service 133 (5G Security Parameters extended) whenever service 123 is available, so a card with EF.5GAUTHKEYS sets both. Services 136 (several NAS security context records) and 146 (NID) are optional and unset in P1.

What each service brings was checked only in N14, by `ksim-sim validate`'s service table: 122 brings the non-3GPP LOCI and NSC too (§4.4.11.3, §4.4.11.5), and with 133 EF.5GAUTHKEYS is 110 octets (§4.4.11.6). The N3 template had neither (KS-UICC-D3). `ksim-sim validate <image>` checks every image against that table, the ARR references, FIDs and SFIs, record sizes and EF.DIR. It also checks that key files stay unreadable even after ADM1. pySim-shell reads every EF of the template over vpcd, PYSIM_EF_READ=39/39 (KS-UICC-T5).

An opt-in `personality: sysmoISIM-SJA5` (in an image, or `ksim-sim serve --personality`) presents that card's ATR, so stock pySim applies its card model and also tries AF20 and AF30, which the card refuses (ARR 5: never).

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

**vpcd as built (P1 N14).**
- **Card side, `ksim-sim serve`:** connects to pcscd's vpcd driver on 35963 + n, so `Virtual PCD 00 0n` shows a card. The driver asks for the ATR every few hundred milliseconds to see that the card is still there. Only the ATR after a reset or power-on goes into the trace; a presence poll is answered and reset nothing.
- **Terminal side, `VpcdTransport`:** one exchange at a time over a stream a card connected; a reset sends 2 then 4.
- **Readers:** CI uses reader 1 and leaves reader 0 for people. On Ubuntu the vpcd driver listens on 0.0.0.0, not loopback; that is the package's reader.conf, not ours.

**PC/SC and the card bridge as built (P2 Q1; rows KS-UICC-B11 to B13, T7).**
- **`Pcsc`:** pcsc-lite's SCardConnect (exclusive, T=0 or T=1), SCardTransmit and SCardReconnect, on the 2-thread blocking pool, one call at a time per card. It is built only with `KSIM_PCSC` (off in release-lab).
- **A UE's card outside the process:** `card: {pcsc: {reader: <name, #n or a unique part>}}` on the dev PC, or `card: {bridge: <host:port>}` on the lab VM; one UE per such group. `sim info` then prints `READER=pcsc:…` or `READER=bridge:…`, and `sim read` is refused. The card must have PIN1 disabled: the UE never sends VERIFY PIN1.
- **The bridge:** `ksim-sim serve --pcsc <reader> --listen <host:port> --allow <address> [--admin]`. One client at a time, from that address only. Without `--admin` it answers 6982 itself to VERIFY/CHANGE/DISABLE/ENABLE/UNBLOCK of an ADM key, to UPDATE while AF20 or AF30 is selected, and to CREATE, DELETE and TERMINATE.
- **The burn:** `ksim-sim adm1 seal --out <file> --kek <file>`, then `ksim-sim burn --pcsc <reader> --imsi <IMSI> --master <file> --adm1 <file> --kek <file> [--dry-run]` (section 8, step 4). It stops before any VERIFY when ADM1 has fewer than 3 tries; it verifies ADM1 once; it writes AF20 and the personalising EFs, reads the IMSI back, and checks K and OPc with one AUTHENTICATE at SQN 0 (a RES, or an AUTS whose MAC-S checks). Only K_FPR is printed.
  - PIN1's state comes from ADF.USIM's PIN status template DO (§9.5.2, PS_DO), and from VERIFY's answer only without one. A sysmoISIM answers VERIFY with no data with 63Cx for a disabled PIN1 too (KS-UICC-D4). The AUTHENTICATE check needs PIN1 disabled.
  - The first real card, imsi-001010000300100, was burned by the user on 2026-10-16. It registers through PC/SC on the dev PC against the stub (KS-UICC-T8). It goes on kaluza-core in a window agreed with the core session (LW4).
- **CI:** `tools/ci.d/57-pcsc.sh` runs all of it on pcscd's vpcd reader 1, with our soft card dressed as a sysmoISIM-SJA5, and kills the mutants `pcsc_response_truncated` and `bridge_admin_open`.

A card is attached to exactly one terminal at a time, as a physical card sits in one reader. `ksim-ctl ue <n> sim remove|insert|swap` models card removal and swap ([`cli.md`](cli.md)).

**AT passthrough (v1.x).** On the optional AT port, +CSIM, +CRSM and +CCHO/+CCHC/+CGLA forward APDUs to the same transport. lpac's AT backend, which uses CCHO/CGLA, can then reach the card.

## 6. Tracing

A decorator on the transport (`uicc/trace`) emits GSMTAP type SIM (0x04), sub-type APDU (0x00) or ATR (0x01), in the layout `pySim-trace.py gsmtap-udp` parses: CLA INS P1 P2 P3, the command data, the response data, SW1 SW2.
- **Records are APDUs, not T=0 TPDUs.** An answer of 61xx or 6Cxx is held and merged with the GET RESPONSE, or the command sent again, that follows on its channel. pySim-trace's GSMTAP source takes each record as a whole APDU, and would otherwise see a SELECT ending in 61xx as failed and lose its place (KS-UICC-B9).
- **Where records go.** In a run, `ksim-ctl ue <n> sim trace on|off` writes them to the run's `sim.pcapng`. `ksim-sim serve` writes them to `--trace-udp` (127.0.0.1:4729) and `--trace-pcap`.
- **Selection is always followed.** The decorator tracks the selected file even while the trace is off, so a trace switched on mid-session still masks what it must.

**Redaction is on by default.** These are masked:
- CK, IK and Kc in AUTHENTICATE responses;
- VERIFY data;
- reads and writes of the key files, by FID or by SFI in the ADF and DF.5GS. Those are EF.KEYS and EF.KEYSPS (3G CK and IK), the NAS security contexts (4F03, 4F04), EF.5GAUTHKEYS (4F05), AF20 and AF30. The same set is refused by `sim read` and left out of `ksim-sim export` (`os::key_fid`).

Unredacted traces need an explicit test-only flag and land in a 0600 file.

## 7. Card images (`src/uicc/image`, `cards/`)

- **Native format:** YAML, a DF/EF tree with FCP attributes and contents in hex or typed form. YAML because it is diffable and round-trips through the pySim oracle.
- **Secrets:** K, OPc or TOPc, ADM1 and PINs live in **a separate sealed file** (AES-256-GCM under a KEK held in a 0600 file or systemd-creds), never in the YAML.
- **Import:** `ksim-sim import --fsdump <file> --template <yaml> --out <yaml>` takes the contents from a pySim-shell `fsdump` (without `--json`), file by file by name, into a copy of the template. Key files and NAS state are kept from the template. **Export:** `ksim-sim export` writes a pySim-shell script (`select`, `update_binary`, `update_record`). It leaves out the key files, EF.ARR, the PINs and whatever the ARR keeps from a reader. SAIP profile packages are imported later.
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
| DNNs | `internet` (5QI 9, IPv4v6) and `ims` (5QI 5, IPv4) | `internet`, IPv4, with `lboRoamingAllowed`. am-data twice: unscoped, and with `servingPlmn` `00101`, which is what the visited AMF reads |
| Home-routed | — | One sub-block (initially `9997000003001xx`) also gets `home` with `lboRoamingAllowed` false, so one UE holds both an LBO and a home-routed session. The `home` sm-data goes into the 999/70 UDR too. Pattern: the core seed's own roamers `999700000000001` (LBO) and `999700000000007` (LBO + HR) |
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
- The soft cards' sealed secrets and the core's subscriptions (API bundles for 001/01, the seed file for 999/70) therefore come from one source. **A clear list of keys never exists**, and nothing prints a key.

**The provisioning flow** ([ADR 0008](adr/0008-subscriber-provisioning-api.md)):
1. `ksim-sim range derive --block 001010000300000/100` writes sealed card secrets for the block. It prints only the IMSIs and a fingerprint `K_FPR` (HMAC of a batch salt and K, truncated).
2. **001/01: `ksim-sim range provision --block …`** puts the block into the 001/01 UDR through kaluza-core's provisioning API. `ksim-sim range deprovision --block …` removes it.
   - **Calls.** One `PUT …/provisioning/v1/subscribers/imsi-<IMSI>` per subscriber, or `DELETE` to remove one. They go to the UDR's provisioning listener on `:7779` in namespace `kaluza`. Only 001/01 has one ([step 3](#the-999-70-range)).
   - **From the dev PC only.** The UDR's NetworkPolicy admits only the OAM and the node. No pod restarts. The UDR's pod IP changes when it restarts, so every run reads it again.
   - **Identity.** The Keycloak client `kaluza-sim-key-entry` in realm `kaluza`, created by kaluza-core on 2026-10-14 (16:11 KST, core `71af2b9d`).
     - It has the single role `oam-key-entry` (read, write, delete, keys, SQN reset), the audience `kaluza-udr-provisioning` only, and is exempt from key-entry step-up.
     - Tokens are ES256 and last 300 s.
   - **Two credentials, both required.** The UDR's listener checks an **mTLS client certificate as well as the token**. Both live in `~/.config/kaluza-sim/provisioning/` (directory 0700, files 0600) on the dev PC:
     - `client-secret`, with no trailing newline. It is passed as `--data-urlencode "client_secret@client-secret"`, never on a command line;
     - `tls-chain.pem` and `tls.key`: the client certificate, CN `kaluza-sim.kaluza.internal`, from the management issuing CA 001-001, valid to 2027-10-14;
     - `root.pem`, which verifies Keycloak and the UDR;
     - a README with the token URL, the UDR URL and the `--resolve` targets.

     These files are never opened in a session, never printed, and never deployed to the VM.
   - **Proven by kaluza-core** with exactly these files on `imsi-001010000300999`: a token, then GET 404, PUT 201 (no step-up asked, stored sealed), GET 200, DELETE 204, GET 404.
   - **Keys.** K and OPc travel in clear inside the API's mTLS, and the UDR seals them itself. The bundle never carries `protectionParameterId`: beside key values, the UDR refuses it with PROTECTED_KEY_UNSUPPORTED.
   - **Output.** Bodies are built in memory from the derived keys and the profile, and are never logged or written to disk. The tool prints only the ueId, the HTTP status and `K_FPR`.
   - **Scope.** It refuses any IMSI outside the sim ranges above. Tell the core session before a first import or a bulk delete.
3. <a id="the-999-70-range"></a>**999/70: the seed file** (user's decision, 2026-10-14). The home UDR (`kaluza-h99970`) has **no provisioning listener**: the home PLMN has no OAM and no IdP. So:
   1. `ksim-sim range seed --block 999700000300000/…` writes the block as one JSON list, mode 0600, at `~/.config/kaluza-sim/seed/h99970-sim.json` on the dev PC. It is never printed.
   2. We tell the core session it is there. kaluza-core merges it into the home UDR's gitignored seed with a script that never echoes bodies and refuses any ueId outside the range or already present.
   3. kaluza-core restarts that UDR alone, in an agreed window. The import seals K/OPc to the home UDM's key, and core reports counts back.
   4. The seed is create-only, so removing subscribers later is a DB step on core's side.

   The same file format is the fallback for 001/01 if the API is ever unavailable. This repo never edits kaluza-core files.
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

**The 999/70 seed file** uses the seed's flat shape: a JSON list of `{ueId, resource, body}`, plus `servingPlmn` or `memberId` where shown. Keys go in clear in `encPermanentKey` and `encOpcKey`, never with `protectionParameterId`. Per subscriber (kaluza-core, 2026-10-14):

| Resource | Body |
|---|---|
| `subscription-data:authentication-data:authentication-subscription` | `authenticationMethod`, `encPermanentKey`, `encOpcKey`, `authenticationManagementField` `8000`, `sequenceNumber` |
| `subscription-data:identity-data` | `supiList` [`imsi-…`], `gpsiList` [`msisdn-…`] |
| `policy-data:ues:am-data` | `{}` or `subscCats` |
| `policy-data:ues:sm-data` | `smPolicySnssaiData` {`"1"`: {`snssai` {sst 1}, `smPolicyDnnData` {`internet`, plus `home` for HR}}} |
| `subscription-data:provisioned-data:am-data`, **twice** | Unscoped, and with `"servingPlmn": "00101"`: `gpsis`, `subsRegTimer` 3600, `subscribedUeAmbr`, `nssai.defaultSingleNssais` [{sst 1}] |
| `subscription-data:provisioned-data:smf-selection-subscription-data` | `subscribedSnssaiInfos` {`"1"`: {`dnnInfos` [{`internet`, `lboRoamingAllowed` true, `defaultDnnIndicator` true}, plus {`home`, `lboRoamingAllowed` false} for HR]}} |
| `subscription-data:provisioned-data:sm-data`, with `"memberId": "1"` | `singleNssai` {sst 1}; `dnnConfigurations`: `internet` (IPv4, SSC 1, 5QI 9, Session-AMBR), plus `home` in the same shape for the HR sub-block |

SMS documents are left out unless the UE tests SMS. The 999/70 range uses no SD, and its cards keep routing indicator 0000.

**Never print:** subscriber seeds, sealed secrets, the provisioning credentials (`~/.config/kaluza-sim/provisioning/`), the 999/70 seed file (`~/.config/kaluza-sim/seed/`), provisioning request bodies, `/home/amadeus/Development/ran/usim/*.md` (which hold keys and an ADM1 PIN in clear), or card images' secret files. When a seed must be read, parse the JSON and drop the authentication-data entries by `resource` before anything is printed. Never `head`, `cat` or `sed` a seed, not even behind a grep.
