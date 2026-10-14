# Findings: kaluza-core defects found by kaluza-sim

Each finding is a file `KF-nnn.md`, numbered in order and never renumbered. A kaluza-core session picks it up and records it in its own register. kaluza-sim's register keeps an `-F` row pointing here. This repo never edits kaluza-core ([ADR 0005](../adr/0005-independence-from-kaluza-core.md)).

**Template:**

```
# KF-nnn: <one-line symptom>

- Found: <date KST>, kaluza-sim <commit>, kaluza-core <tag or sha>, scenario <file>, seed <n>
- Clause: <spec, version, clause> — the text the core does not follow (quote ≤ 2 lines)
- Expected (per spec): …
- Observed: …
- Evidence: <run dir>/pcap/<iface>.pcapng (frames …), events.ndjson (seq …–…)
- Cross-check: Open5GS fork core <same / different> (a lead, not a verdict)
- Sim mutant that would hide it: <switch>, if any
- Handed to: <kaluza-core session name>, <date>; their register row: <id> (filled in when known)
```

**Rules:**
- **Evidence never contains key material.** pcaps are taken without the opt-in key export, and SUPIs are allowed (lab).
- **The clause decides.** When the Open5GS control agrees with kaluza-core against the spec, the finding stands, and the agreement is recorded.
