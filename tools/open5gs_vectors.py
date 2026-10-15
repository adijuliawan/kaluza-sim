#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""NAS vectors from the Open5GS control runs (P1 N19; plan: only Open5GS and
phone captures become vectors, ADR 0005).

  tools/open5gs_vectors.py runs/open5gs-<stamp> [...]

Reads each run's uu.pcapng, where the UE wrote every 5GMM message in clear as
it took it (after the integrity check and deciphering) with a "DL" comment,
and keeps the downlink 5GMM and 5GSM messages: the octets the fork's AMF and
SMF encoded. They are independent of kaluza-sim's encoders. Duplicates go;
at most three of a type. The identities in them are the sim range's
(001/01, imsi-0010100003000xx), not a device's.

Writes tests/vectors/sources/open5gs-nas.tsv, which tools/corpus_ingest.py
appends to the NAS index; the run directories need not exist afterwards.
kaluza-core's runs never go here (ADR 0005: they are fuzz seeds at most).
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests" / "oracles"))
sys.path.insert(0, str(ROOT / "tools"))
from ksimoracle import pcap  # noqa: E402
import corpus_ingest  # noqa: E402

CAP = 3
FIELDS = ["id", "pdu", "octets", "sha256", "direction", "run", "capture_sha256", "locator", "hex"]


def main() -> int:
    runs = [Path(a) for a in sys.argv[1:]]
    if not runs:
        print(__doc__)
        return 2
    rows, seen = [], set()
    for run in sorted(runs):
        if not run.name.startswith("open5gs-"):
            print(f"OPEN5GS_VECTORS=REFUSED ({run.name}: only Open5GS runs)")
            return 2
        f = run / "uu.pcapng"
        data = f.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        for frame, name, pdu, comment in pcap.read_pcapng_exported(data):
            if name != "nas-5gs" or not comment.endswith(" DL") or pdu in seen:
                continue
            named = corpus_ingest.nas_name(pdu)
            if named is None:
                continue
            msg, direction = named
            if direction == "uplink" or sum(1 for r in rows if r["pdu"] == msg) >= CAP:
                continue
            seen.add(pdu)
            rows.append({"id": f"nas-open5gs-{len(rows) + 1:03d}", "pdu": msg, "octets": str(len(pdu)),
                         "sha256": hashlib.sha256(pdu).hexdigest(), "direction": "downlink", "run": run.name,
                         "capture_sha256": digest, "locator": f"uu.pcapng frame {frame}", "hex": pdu.hex()})
            # The 5GSM message a DL NAS TRANSPORT carries (payload container type 1, N1 SM
            # information, TS 24.501 8.2.11): the fork's SMF encoded it.
            if msg == "DL NAS TRANSPORT" and len(pdu) > 6 and (pdu[3] & 0x0F) == 1:
                plen = pdu[4] << 8 | pdu[5]
                sm = pdu[6:6 + plen]
                inner = corpus_ingest.nas_name(sm) if len(sm) == plen else None
                if inner is not None and sm not in seen and sum(1 for r in rows if r["pdu"] == inner[0]) < CAP:
                    seen.add(sm)
                    rows.append({"id": f"nas-open5gs-{len(rows) + 1:03d}", "pdu": inner[0], "octets": str(len(sm)),
                                 "sha256": hashlib.sha256(sm).hexdigest(), "direction": "downlink",
                                 "run": run.name, "capture_sha256": digest,
                                 "locator": f"uu.pcapng frame {frame} (the DL NAS TRANSPORT's payload container)",
                                 "hex": sm.hex()})
    out = ROOT / "tests" / "vectors" / "sources" / "open5gs-nas.tsv"
    lines = ["# SPDX-FileCopyrightText: 2026 Adi Juliawan", "# SPDX-License-Identifier: LicenseRef-kaluza-sim-private",
             "# Downlink NAS from the Open5GS fork (741c29d8d) in kaluza-sim's control runs, written by",
             "# tools/open5gs_vectors.py; tools/corpus_ingest.py reads it. Do not edit.", "\t".join(FIELDS)]
    lines += ["\t".join(r[k] for k in FIELDS) for r in rows]
    out.write_text("\n".join(lines) + "\n")
    types = sorted({r["pdu"] for r in rows})
    print(f"OPEN5GS_VECTORS={len(rows)} types={len(types)}: {', '.join(types)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
