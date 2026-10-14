# Research: Quectel AT manuals and firmware (2026-10-14)

**Material (the user's, local):**
- `/home/amadeus/Development/ran/firmware/Quectel/Quectel_RG520N&RG525F&RG5x0F&RM5x0N_Series_AT_Commands_Manual_V1.1.pdf` (282 pages, V1.1, 2025-02-20)
- `/home/amadeus/Development/ran/firmware/Quectel/Quectel_RG255C_Series&RM255C-GL_AT_Commands_Manual_V1.1.pdf`
- `/home/amadeus/Development/ran/firmware/Quectel/RM520NGLAAR03A03M4G_A0.305.A0.305.zip` (RM520N-GL firmware A0.305, SDX65)
- `/home/amadeus/Development/ran/firmware/Quectel/RG255CGLABR01A05M4G_A0.302.A0.302.zip` (RG255C-GL firmware A05 A0.302, SDX35, RedCap)
- `/home/amadeus/Development/ran/firmware/Quectel-SNPN-study.md` (the user's offline study, 2026-10-12)

## ⚠ Confidentiality

The manuals' "Use and Disclosure Restrictions" mark them **confidential**: no copying, no distribution. So:
- **No text from them is copied into this repo.** It refers to them by path.
- The AT port's Quectel subset is written from the behaviour they document.
- **Firmware images are never copied or redistributed.** Facts come only from read-only inspection, as the SNPN study did.

## What the manuals cover (by command name, for orientation)

Sections of the RM5x0N manual:
- 2 general;
- 3 status control (`+CEER`, `+QCFG` family);
- 4 (U)SIM (`+CIMI`, `+ICCID`, `+CPIN`, **`+CSIM`**, **`+CRSM`**, **`+CCHO`/`+CCHC`/`+CGLA`**, `+QSIMSTAT`, `+QUIMSLOT`);
- 5 network service (`+COPS`, `+CREG`/`+CGREG`/`+CEREG`/**`+C5GREG`**, `+CGDCONT`, **`+C5GNSSAI`**, `+C5GNSSAIRDP`, `+CSQ`, `+QRSRP`/`+QRSRQ`/`+QSINR`, **`+QENG`**, **`+QNETRC`**, `+QNWCFG`, **`+QNWPREFCFG`** with mode_pref, nr5g_band, srv_domain, voice_domain, ue_usage_setting, nr5g_disable_mode, …);
- 6 call;
- 7 phonebook;
- 8 SMS (TS 27.005: `+CMGF`, `+CSCA`, `+CMGS`, `+CNMI`, …);
- 9 packet domain (`+CGATT`, `+CGACT`, `+CGPADDR`, `+CGEREP`, …);
- 10 supplementary services;
- 11 hardware;
- 12 QMAP;
- 13 appendices: CME/CMS error codes, URC summary, `+CEER` release-cause texts.

Most commands are 3GPP TS 27.007/27.005 standard commands. The `+Q…` commands are Quectel extensions.

## Firmware facts (from the user's SNPN study)

| | RM520N-GL (A0.305, MPSS.DE.3.0-02154, SDX65) | RG255C-GL (A05 A0.302, MPSS.CY.1.0-01270.2, SDX35) |
|---|---|---|
| SNPN in the modem firmware | Yes (compiled in) | Yes (compiled in) |
| Documented AT command for SNPN | None | None |
| Host-side SNPN control in the package | None (no RIL) | Yes: the on-module RIL `qcrilNrd` plus `qcrilnr-console-app` (SNPN access mode, NID selection, SNPN scan) |

Carrier configs carry no SNPN/CAG items, so the firmware defaults apply. Open items (ADB on the RG255C, the QMI route on the RM520N, SNPN credentials) are in the study file.

## What kaluza-sim takes

- **Personas:**
  - The RM520N and RG255C personas take their UE radio capability and NAS bits from N2 pcaps captured on NEA0. The RG255C is RedCap.
  - The manuals add defaults and the documented control surface: mode preference, `ue_usage_setting`, voice domain, NR5G disable modes, RRC release-version settings.
  - The SNPN study adds that both modems have SNPN in firmware, for later SNPN personas.
- **The optional AT port (P3c)** ([`../cli.md`](../cli.md) §6):
  - the TS 27.007/27.005 standard set;
  - SIM passthrough (`+CSIM`, `+CRSM`, `+CCHO`/`+CCHC`/`+CGLA`);
  - a Quectel subset (`+QENG`, `+QNWPREFCFG`, `+QNETRC`, `+QRSRP`/`+QRSRQ`/`+QSINR`, `+QSIMSTAT`).

  Your modem scripts and lpac's AT backend can then drive a simulated RM520N or RG255C.
- **Lab rule from experience:** keep the real RM520N at `CFUN=0` when not in use, and check it with `AT+CFUN?`, because ModemManager's view can be stale.
