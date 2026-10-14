# ADR 0007: positioning is the first phase-2 family

- **Status:** accepted, 2026-10-14 (user)
- **Context:**
  - **The phase-2 families:** positioning (LPP/NRPPa), IMS UA, E2 + O1, non-3GPP access and full L2.
  - **What wave 41 (LMF + GMLC) needs:**
    - LPP over N1;
    - NRPPa over NGAP: E-CID, UL-RTOA and SRS-RSRP, plus DL PRS for DL-TDOA.
  - **What the lab can show on air:**
    - only the OnePlus advertises LPP;
    - OCUDU's PHY gives UL-RTOA and SRS-RSRP but no AoA;
    - accuracy can't be claimed, because the antennas share one bench and a 20 MHz cell resolves to several metres.
- **Decision:** positioning comes first in phase 2, timed to land with wave 41.
  - UE-side LPP: capabilities; location information from the scene's true position (GNSS); NR E-CID; DL-TDOA RSTD.
  - gNB-side NRPPa: E-CID; TRP information; UL-RTOA, SRS-RSRP and **AoA**, all computed from ground-truth geometry.
  - **Accuracy can be measured,** because the true position is known.
  - The order of the remaining families is decided later.
- **Consequences:**
  - New codecs: TS 37.355 j30 and TS 38.455 j30 (ASN.1).
  - The radio model's geometry becomes a test oracle for the LMF.
