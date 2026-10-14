# ADR 0010: The Open5GS fork as P1's control core

- **Status:** accepted, 2026-10-15 (user, through kaluza-core-1e and the P1 plan)
- **Context:**
  - P1's exit runs the same scenarios against the Open5GS fork core as against kaluza-core. A second, unrelated core tells sim defects from core defects and keeps the sim from being tuned to kaluza-core (ADR 0005).
  - No kaluza-core gate has run the fork as a full core since wave 14. The rig VM `amadeus-open5gs` (VMware on the dev PC, vmnet8 192.168.134.128) still has every NF binary in `~/open5gs-n3iwf/install/bin`, a working PostgreSQL, and an `amf.yaml` with NGAP on 192.168.134.128:38412 for 001/01 TAC 1. kaluza-core-1e checked this on 2026-10-15.
  - kaluza-core's gates also start single fork NFs on the rig as peers, from the same `install/etc/open5gs`.
  - The fork has no SMS over NAS: its AMF never sets "SMS allowed" in the registration result.
  - `open5gs-dbctl-pgsql add <imsi> <ki> <opc>` takes the keys on its command line, which `requirements.md` §3.6 forbids.
- **Decision:**
  1. A full 001/01 fork core runs on the rig for P1 control runs, driven from the dev PC over vmnet8 only. The user agreed on 2026-10-15 under these conditions:
     - never while a kaluza-core gate set runs (fork peers from the same install would collide on the NRF, ports and loopback addresses), so each run is checked with the active kaluza-core session first;
     - it runs from kaluza-sim's own copy of the config directory, never `install/etc/open5gs` in place;
     - every NF it started is stopped and `ogstun` removed afterwards;
     - no run during a kaluza-core roll, which flaps vmnet8 for about 5 s.
  2. **Provisioning:** `ksim-sim range provision --target open5gs` builds SQL in memory and pipes it to `psql` over ssh stdin, so K and OPc never appear in argv, logs or files. Removal is the matching `deprovision`.
  3. **The allow-list:** known Open5GS deviations go in `gates/allow/open5gs.tsv` (allow id, row, reason, clause, Open5GS source reference). A row is scored PASS, or ALLOWED by an entry. Any other difference is triaged against the spec into a sim -D row, an allow entry, or an -S row when the spec is ambiguous.
  4. **The SMS rows** are allow-listed on Open5GS (no SMSF or SMS over NAS; the user, 2026-10-15). One row there checks that the UE honours "SMS not allowed".
  5. Rows only a core-side change can trigger are scored on Open5GS where the fork offers a way to cause the change, and allow-listed where it does not (ADR 0009 consequences).
  6. Each run's manifest pins the fork's commit (`adijuliawan/open5gs`) and the rig config's hash.
- **Consequences:**
  - Open5GS runs are recorded evidence, not CI steps. The rig is shared, so a run that cannot be agreed waits.
  - The dev-PC guard (ADR 0009, point 11) allows 192.168.134.0/24, because vmnet8 is host-only and carries no lab traffic.
