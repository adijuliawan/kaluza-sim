#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""nm hygiene of the ASN.1 libraries (plan M6, row KS-PLAT-B3).

    tools/asn1_nm_check.py --lib PREFIX=path.a ... [--lib =runtime.a]
    tools/asn1_nm_check.py --self-test

Every global symbol a protocol library defines must carry its prefix (as
"PREFIX_" at the start or after an underscore, e.g. asn_DEF_NGAP_Cause), and no
global may be defined in two libraries. Static archives resolve duplicates
silently (the first object wins), so a clash would bind one protocol's type to
another's descriptor with no error. That is why this check exists.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys


def globals_of(archive: str) -> set[str]:
    out = subprocess.run(["nm", "--defined-only", "-g", archive], capture_output=True, text=True,
                         check=True).stdout
    return {f[2] for f in (ln.split() for ln in out.splitlines()) if len(f) == 3}


def check(libs: dict[str, set[str]]) -> list[str]:
    problems: list[str] = []
    for prefix, syms in libs.items():
        if not prefix:
            continue
        pat = re.compile(rf"(^|_){re.escape(prefix)}_")
        bare = sorted(s for s in syms if not pat.search(s))
        problems += [f"UNPREFIXED {prefix}: {s}" for s in bare[:20]]
        if len(bare) > 20:
            problems.append(f"UNPREFIXED {prefix}: ... {len(bare) - 20} more")
    owners: dict[str, list[str]] = {}
    for prefix, syms in libs.items():
        for s in syms:
            owners.setdefault(s, []).append(prefix or "runtime")
    dup = sorted((s, o) for s, o in owners.items() if len(o) > 1)
    problems += [f"DUPLICATE {s}: {', '.join(o)}" for s, o in dup[:20]]
    if len(dup) > 20:
        problems.append(f"DUPLICATE ... {len(dup) - 20} more")
    return problems


def self_test() -> int:
    clean = {"": {"asn_DEF_BOOLEAN", "aper_encode"}, "NGAP": {"asn_DEF_NGAP_Cause", "NGAP_Cause_constraint"},
             "XNAP": {"asn_DEF_XNAP_Cause"}}
    if check(clean):
        print("SELFTEST asn1-nm: FAIL (clean set flagged)")
        return 1
    dirty = {"": {"asn_DEF_BOOLEAN"}, "NGAP": {"asn_DEF_NGAP_Cause", "asn_DEF_Cause"},
             "XNAP": {"asn_DEF_XNAP_Cause", "asn_DEF_BOOLEAN"}}
    got = check(dirty)
    want = {"UNPREFIXED NGAP: asn_DEF_Cause", "UNPREFIXED XNAP: asn_DEF_BOOLEAN",
            "DUPLICATE asn_DEF_BOOLEAN: runtime, XNAP"}
    if set(got) != want:
        print(f"SELFTEST asn1-nm: FAIL got={got}")
        return 1
    print("SELFTEST asn1-nm: OK (caught an unprefixed and a duplicated global)")
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--lib", action="append", default=[], help="PREFIX=archive ('' = runtime)")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        sys.exit(self_test())
    libs = {}
    for spec in a.lib:
        prefix, _, path = spec.partition("=")
        libs[prefix] = globals_of(path)
    problems = check(libs)
    for p in problems:
        print(p)
    total = sum(len(s) for s in libs.values())
    print(f"ASN1_NM={'FAIL' if problems else 'PASS'} libraries={len(libs)} globals={total} "
          f"problems={len(problems)}")
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
