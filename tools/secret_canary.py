#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""The secret canary (plan M14, requirements §3.6): run tests/canary's
ksim_canary, which sends a known K through Milenage, the 5G key chain, NAS
integrity and ciphering, the log, a pcapng capture and the APDU JSON, then look
for K and every key derived from it in what it wrote:

    raw octets, lower and upper hex, base64 (at any alignment), and BCD (nibbles
    swapped, raw and hex), for K, OPc, CK, IK, K_AUSF, K_SEAF, K_AMF, the NAS,
    RRC and UP keys, K_gNB, NH, K_NG-RAN*, CK' and IK'.

The derived keys come from the Python key-chain oracle (tests/oracles/
keychain.py), not from the program under test. Zero hits passes. The
must-fail cases rerun the program with KSIM_CANARY_LEAK=1, which logs K, and
with 2, which captures the card's AUTHENTICATE response unredacted: both have to
be found.

    tools/secret_canary.py [--binary build/dev/tests/canary/ksim_canary]
"""

from __future__ import annotations

import argparse
import base64
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests" / "oracles"))
import keychain  # noqa: E402

# The canary's inputs, as in tests/canary/canary.cpp.
K = "6b73696d2d63616e6172792d6b2d3031"
OPC = "6b73696d2d63616e6172792d6f706331"
RAND = "0123456789abcdef0123456789abcdef"
SQN = "000000000021"
AMF = "8000"
SUPI = "001010000300042"
SECRET_FIELDS = ["CK", "IK", "K_AUSF", "K_SEAF", "K_AMF", "K_NASenc", "K_NASint", "K_gNB", "K_RRCenc", "K_RRCint",
                 "K_UPenc", "K_UPint", "NH", "K_NG-RAN*", "CK'", "IK'"]


def secrets() -> dict[str, bytes]:
    vals = keychain.chain(bytes.fromhex(K), bytes.fromhex(OPC), bytes.fromhex(RAND), bytes.fromhex(SQN),
                          bytes.fromhex(AMF), "001", "01", SUPI, bytes(2), 0, 0, 0)
    named = dict(zip(keychain.FIELDS, vals))
    out = {"K": bytes.fromhex(K), "OPc": bytes.fromhex(OPC)}
    out.update({f: bytes.fromhex(named[f]) for f in SECRET_FIELDS})
    return out


def forms(name: str, v: bytes) -> list[tuple[str, bytes]]:
    swapped = bytes(((b & 0x0F) << 4) | (b >> 4) for b in v)
    out = [("raw", v), ("hex", v.hex().encode()), ("HEX", v.hex().upper().encode()),
           ("bcd raw", swapped), ("bcd hex", swapped.hex().encode()), ("bcd HEX", swapped.hex().upper().encode())]
    for shift in range(3):   # base64 of the value at each alignment, without the edge groups
        for enc in (base64.b64encode, base64.urlsafe_b64encode):
            b = enc(bytes(shift) + v)
            core = b[4:-4] if len(b) > 12 else b
            out.append((f"base64+{shift}", core))
    return out


def scan(outdir: Path) -> list[str]:
    hits = []
    secret = secrets()
    for f in sorted(outdir.iterdir()):
        data = f.read_bytes()
        for name, v in secret.items():
            for form, needle in forms(name, v):
                if needle and needle in data:
                    hits.append(f"{f.name}: {name} as {form}")
    return hits


def run(binary: Path, leak: str = "") -> tuple[list[str], list[str]]:
    with tempfile.TemporaryDirectory() as td:
        env = dict(os.environ)
        env.pop("KSIM_CANARY_LEAK", None)
        if leak:
            env["KSIM_CANARY_LEAK"] = leak
        r = subprocess.run([str(binary), td], env=env, capture_output=True)
        (Path(td) / "stdout.txt").write_bytes(r.stdout)
        (Path(td) / "stderr.txt").write_bytes(r.stderr)
        if r.returncode != 0:
            return [], [f"ksim_canary exited with {r.returncode}: {r.stderr.decode(errors='replace')[:200]}"]
        files = sorted(p.name for p in Path(td).iterdir())
        return scan(Path(td)), files


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--binary", default=str(ROOT / "build" / "dev" / "tests" / "canary" / "ksim_canary"))
    a = ap.parse_args()
    binary = Path(a.binary)
    if not binary.is_file():
        print(f"CANARY=SKIP (no {binary}; build the dev preset)")
        return 77
    n_secrets = len(secrets())
    hits, files = run(binary)
    for h in hits:
        print(f"CANARY_HIT {h}")
    leak_hits, _ = run(binary, "1")
    log_caught = any(h.startswith("canary.log: K as") for h in leak_hits)
    print(f"CANARY_MUSTFAIL {'CAUGHT' if log_caught else 'MISSED'} K in the log (KSIM_CANARY_LEAK=1)")
    pcap_hits, _ = run(binary, "2")
    pcap_caught = any(h.startswith("canary.pcapng: CK as") for h in pcap_hits) and \
        any(h.startswith("canary.pcapng: IK as") for h in pcap_hits)
    print(f"CANARY_MUSTFAIL {'CAUGHT' if pcap_caught else 'MISSED'} CK and IK in an unredacted SIM capture "
          f"(KSIM_CANARY_LEAK=2)")
    caught = log_caught and pcap_caught
    ok = not hits and caught and "canary.pcapng" in files
    print(f"CANARY={'PASS' if ok else 'FAIL'} secrets={n_secrets} forms_each={len(forms('K', b'0' * 16))} "
          f"files={','.join(files)} hits={len(hits)}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
