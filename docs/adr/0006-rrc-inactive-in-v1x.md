# ADR 0006: RRC_INACTIVE in v1.x (build phase P3b)

- **Status:** accepted, 2026-10-14 (user)
- **Context:**
  - The user kept v1 to the baseline. RRC_INACTIVE was not among the families offered, but it is **wave 40's step 4**. There the AMF owes things only a RAN plus a UE can test:
    - Core Network Assistance Information in the Initial Context Setup;
    - the RRC Inactive Transition Report (an NGAP codec gap in kaluza-core today);
    - the path switch when a UE resumes at another gNB;
    - CN paging as the fallback when RAN paging fails.
  - On air, only the OnePlus and the RM520N advertise `inactiveState`. OCUDU has it but switched off (`enable_rrc_inactive`). Resume at another gNB, RNA update, T319 and RAN-paging failure can't be forced reliably on air.
- **Decision:** RRC_INACTIVE is build phase **P3b (v1.x)**, straight after the v1 handover milestone (P3) and before gate parity (P4). It covers:
  - suspend and resume;
  - RNA update and RAN paging;
  - Retrieve UE Context over Xn;
  - the Transition Report;
  - CN assistance information;
  - the CN-paging fallback;
  - T319;
  - the resume keys of TS 33.501 §6.8.2.
- **Consequences:** v1's exit stays at wave 40 steps 1–2. P3b reuses Xn-C, E1, Path Switch and the RRC procedures already built in P3, so it is sized M.
