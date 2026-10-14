# Research: simulating the SIM with real APDUs (2026-10-14)

**Goal (user):** the UE really talks to a SIM using the actual standards: ETSI TS 102 221, 3GPP TS 31.101, 31.102 and 31.103, and TS 31.111.

The design is in [`../sim-uicc.md`](../sim-uicc.md).

## Options surveyed

| Option | What | Reach | DF.5GS / GET IDENTITY | Algorithms | ISIM | Verdict |
|---|---|---|---|---|---|---|
| onomondo-uicc (https://github.com/onomondo/onomondo-uicc), GPL-3.0 | C implementation of the TS 102 221 file system and ADF.USIM; access rules, PINs, limited proactive support, OTA RFM (TS 102 225/226) | vpcd, SIMtrace2 cardem, embedded | None by default (data-driven; could be added) | Milenage only | No | The most complete open soft USIM, but GPL and not 5G-ready. **Read only** |
| swSIM + swICC + swicc-pcsc (BSD-3) | C card with a JSON file system and a proactive module | swICC over TCP to a PC/SC IFD handler | None found | Milenage | No | Hobby-grade |
| vsmartcard (vpcd + vicc) | A virtual PC/SC reader plus a Python card | PC/SC | No SIM card type | — | — | **The transport is reused**: the vpcd protocol is trivial |
| jCardSim | Java Card 3.0.5 simulator | javax.smartcardio; vpcd via remote-card | No ETSI UICC/USAT APIs; no open USIM applet | — | — | Not practical |
| SIMtrace2 cardem, osmo-remsim | Hardware that presents a PC/SC or software card to a real phone | Hardware | — | — | — | Only needed to drive real handsets |
| **pySim** (`/home/amadeus/Development/ran/usim/pysim-src`) | Reference model, programmer and tracer: full DF.5GS model (`pySim/ts_31_102.py`), `get_identity`, APDU decoders, `pySim-trace` | PC/SC, serial, AT+CSIM | Yes (model) | — | Yes | **The oracle** |
| **sysmoISIM-SJA2/SJA5 (real cards)** | Programmable with ADM1. SJA5 has a Rel-17 profile (USIM, ISIM, SIM, HPSIM); the 9FV variant computes SUCI in the ME, S17 on the card | PC/SC | Yes | EF.USIM_AUTH_KEY (AF20) selects Milenage, TUAK, … (`pySim/sysmocom_sja2.py`) | Yes | **Real-card backend** |

**UE stacks that speak APDUs:**
- srsUE's `pcsc_usim` (3G AUTHENTICATE on the card, 5G keys derived in software; no SUCI, no 5G files);
- hostap's `/home/amadeus/Development/hostap/src/utils/pcsc_funcs.c` (clean reference for T=0 handling).

UERANSIM, OAI and PacketRusher keep K/OPc in config.

**Conclusion:** build our own soft card, with DF.5GS, GET IDENTITY and TUAK, behind one APDU interface with three backends (in-process, vpcd, PC/SC). pySim is the oracle.

## Spec facts (checked against pySim)

- **AUTHENTICATE has no "5G context".** P2 contexts: GSM 0x80, 3G 0x81, VGCS/VBS 0x82, GBA 0x84. **5G AKA uses the 3G context:**
  - Command: `00 88 00 81 22 | 10 RAND | 10 AUTN`.
  - Success: `DB 08 RES 10 CK 10 IK [08 Kc]`.
  - Synch failure: `DC 0E AUTS`.
  - MAC failure: SW `9862`.
  - The ME derives RES\*, K_AUSF, K_SEAF and K_AMF. The K_AUSF input SQN⊕AK is AUTN[0..5].
- **SUCI on the card:** when UST services 124 and 125 are both set, the ME sends GET IDENTITY `80 78 00 01 00` and receives an `A1` TLV holding the SUCI. P2 = 02 is the NSWO context. With 124 alone, the ME computes SUCI from EF.SUCI_Calc_Info (4F07) and EF.Routing_Indicator (4F0A).
- **Storage:**
  - Service 123: K_AUSF and K_SEAF in EF.5GAUTHKEYS (4F05).
  - Service 122: EF.5GS3GPPLOCI (4F01) and EF.5GS3GPPNSC (4F03).
  - EF.KAUSF_DERIVATION (service 145) only selects MSK versus EMSK for EAP-AKA′ in an SNPN.
- **ISIM:** AID `A0000000871004`; EF.IMPI 6F02, EF.DOMAIN 6F03, EF.IMPU 6F04, EF.IST, EF.P-CSCF 6F09. IMS-AKA uses the same 3G context.
- **USAT (TS 31.111):** TERMINAL PROFILE `80 10`; SW `91xx` → FETCH `80 12`; TERMINAL RESPONSE `80 14`; ENVELOPE `80 C2`. Uses: SMS-PP download, call control on PDU session (service 128), REFRESH.

## Transports

| Transport | Details |
|---|---|
| **PC/SC** (real cards) | `SCardEstablishContext` → `SCardListReaders` → `SCardConnect(SHARED, T0\|T1)` → `SCardStatus` (ATR) → `SCardBeginTransaction` → `SCardTransmit`. T=0 case 4: on `61xx`, send `00 C0 00 00 xx`; on `6Cxx`, resend with Le = xx. CLA `00` (UICC). A typical UE flow: read EF.DIR (2F00), SELECT the USIM by AID (`00 A4 04 04 …`, starting `A0000000871002`), then READ BINARY/RECORD |
| **vpcd** | pcscd's vpcd listens on TCP 35963 (35964, …). Frames are a 2-byte big-endian length plus payload; a 1-byte payload is a control code (0 off, 1 on, 2 reset, 4 ATR), anything else a C-APDU, answered with an R-APDU including SW. pySim-shell can then provision and inspect a soft card |
| **In-process** | `ATR()`, `Reset()`, `Transmit(cAPDU) → rAPDU`, with optional T=0 emulation so every path shares one ME code path. pcsc-lite supports only 16 readers by default (`PCSCLITE_MAX_READERS_CONTEXTS`), so 100 UEs need in-process cards |
| **Tracing** | GSMTAP-SIM on UDP 4729, decoded live by `pySim-trace.py gsmtap-udp` |

## eUICC / eSIM

- SGP.22 (consumer: LPA ↔ SM-DP+ over ES9+, LPA ↔ ISD-R over ES10x APDUs) and SGP.32 (IoT: eIM and IPA).
- Test eUICCs need SGP.26 test certificates (the user has a sysmoEUICC1-C2T). Tools: pySim's `osmo-smdpp` (proof of concept), `pySim/euicc.py`, lpac.
- **For core validation it is mostly not needed:** the SM-DP+ and eIM sit outside the 5GC. What is core-relevant is a profile switch (a new SUPI and keys plus a REFRESH or reset, then re-registration) and SoR/UPU updates to USIM files. Those go through the USIM layer later.
- Kaluza-core's phase-4 plan has the eSIM provisioning path.

## Local context (no secrets reproduced)

**pySim setup:**
- Clone `/home/amadeus/Development/ran/usim/pysim-src`, venv `/home/amadeus/Development/ran/usim/.venv-pysim`.
- pcscd, libccid, and a polkit rule `/etc/polkit-1/rules.d/50-pcsc-amadeus.rules`.
- The OmniKey 3x21 (076b:3031) needs `udevadm trigger -c add`.

**Card inventory** (`/home/amadeus/Development/ran/usim/2026-09-21-test-sims.md`; the vendor key sheet `sysmocom.md` is **secret**):
- Five sysmocom cards, all programmable.
- ⚠ The inventory file holds an **ADM1 PIN in clear text** (around line 172). Never print it.
- The card model (SJA2 or SJA5, 9FV or S17) is not recorded; pySim-shell's ATR autodetect would settle it.

**Notes on specific cards:**
- The S22+ card (…968) sends a null-scheme SUCI, so service 124 is off or not provisioned (`pysim-src/docs/suci-tutorial.rst` shows how to enable it).
- Its ISIM is present but IMPI, IMPU and DOMAIN are empty, so Samsung falls back to the IMSI-derived identity.
- OnePlus card …943 = IMSI 001010000118894.
