# ADR 0005: independence from kaluza-core (separate spec readings, not a separate language)

- **Status:** accepted, 2026-10-14 (user; clarified the same day)
- **Context:**
  - A test catches a misreading of the spec only if the two sides were built separately. If the simulator reused kaluza-core's reading (its codecs, tables or encoder outputs), both sides would agree and the test would pass while both were wrong.
  - kaluza-core's own records show this three times:
    1. **K_AMF's input** was fed the `imsi-`-prefixed SBI spelling instead of the SUPI digits.
    2. **Null-scheme SUCI** was written as the hex of BCD octets instead of the MSIN digits.

       Both passed 2,571 tier-1 tests, because the core's encoder and decoder agreed with each other. They were caught only when UERANSIM, a separate implementation, met the core (kaluza-core project memory, 2026-09-12).
    3. **NGAP N-20:** a SIZE bound coded wrong "by encoder and decoder alike", caught when OCUDU sent a partial NG RESET (`/home/amadeus/Development/kaluza-core/docs/compliance/ran/README.md` §3).
  - The question is not the programming language. A Java simulator sharing nothing would be just as independent. A C++ port of the core's tables would not be.
- **Decision:**
  - **Forbidden:**
    - copying or porting kaluza-core code or generated tables;
    - using values produced by kaluza-core's own encoders as expected results;
    - asking kaluza-core to compute an expected value.
  - **Allowed:**
    - reading kaluza-core docs, compliance registers and deviations to decide **what** to test;
    - citing the same spec clauses;
    - using vectors of **external origin** (3GPP/SAGE KATs; captures from phones, modems or OCUDU, even when they sit in `/home/amadeus/Development/kaluza-core/testkit/kaluza-testkit-vectors`), with the origin recorded per vector.
  - **Two kinds of check:**
    - *oracles* decode our bytes: tshark, pycrate, pySim, published KATs;
    - *peers and controls* run the other end: OCUDU, the Open5GS fork core, free5gc.

    A difference with a peer is a lead. **The spec text decides.**
  - **kaluza-core is never an oracle for the sim,** and the sim is never one for kaluza-core. Defects found go to `docs/findings/KF-nnn.md` for a kaluza-core session to take up.
- **Consequences:**
  - More work: our own codecs and our own key-derivation code, checked against KATs and a separate minimal Python key-chain oracle.
  - A guard against co-adaptation: P1's exit also runs the scenarios against the Open5GS fork core ([`../roadmap.md`](../roadmap.md)).
  - Separate sessions work on kaluza-sim and kaluza-core.
