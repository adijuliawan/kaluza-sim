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

With --run-dir (P1 N8) it scans a ksim run directory instead: every file in it
(manifest, events, log, captures, the gates' ksim-ctl output) for K and OPc of
each card, derived from the run's throwaway range master, and for the whole
chain of every authentication the run's Uu capture shows:

    tools/secret_canary.py --run-dir <run> --master <file> --block <first IMSI>/<n>
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


def run_dir_secrets(run: Path, master: bytes, imsis: list[str], pci: int, arfcn: int) -> tuple[dict[str, bytes], int]:
    """Every key a run used (P1 N8): K and OPc of each card from the range master
    (sim-uicc.md section 8: the first 16 octets of HMAC-SHA-256(master, label ||
    IMSI)), and for each AUTHENTICATION REQUEST in the run's Uu capture the
    whole chain from its RAND and AUTN (SQN = SQN^AK ^ AK), with K_gNB for the
    first uplink NAS COUNTs. Returns the keys and the challenges seen."""
    import hashlib
    import hmac as hmac_
    from ksimoracle import pcap
    out: dict[str, bytes] = {}
    keys = {}
    for imsi in imsis:
        k = hmac_.new(master, b"K" + imsi.encode(), hashlib.sha256).digest()[:16]
        opc = hmac_.new(master, b"OPc" + imsi.encode(), hashlib.sha256).digest()[:16]
        keys[imsi] = (k, opc)
        out[f"K {imsi}"] = k
        out[f"OPc {imsi}"] = opc
    challenges = 0
    uu = run / "uu.pcapng"
    records = pcap.read_pcapng_exported(uu.read_bytes()) if uu.is_file() else []
    for _, name, pdu, comment in records:
        # A plain AUTHENTICATION REQUEST (TS 24.501 8.2.1): EPD, SHT, type 0x56,
        # ngKSI, ABBA (LV), then RAND (TV 0x21) and AUTN (TLV 0x20).
        if name != "nas-5gs" or len(pdu) < 6 or pdu[0] != 0x7E or pdu[1] != 0x00 or pdu[2] != 0x56:
            continue
        supi = comment.split(" ")[0].removeprefix("imsi-")
        if supi not in keys:
            continue
        abba_len = pdu[4]
        abba = pdu[5:5 + abba_len]
        pos, rand, autn = 5 + abba_len, None, None
        while pos < len(pdu):
            iei = pdu[pos]
            if iei == 0x21:
                rand = pdu[pos + 1:pos + 17]
                pos += 17
            elif iei == 0x20:
                ln = pdu[pos + 1]
                autn = pdu[pos + 2:pos + 2 + ln]
                pos += 2 + ln
            else:
                break
        if rand is None or autn is None or len(autn) != 16:
            continue
        challenges += 1
        k, opc = keys[supi]
        ak = keychain.milenage(k, opc, rand, bytes(6), bytes(2))["ak"]
        sqn = bytes(a ^ b for a, b in zip(autn[:6], ak))
        for count in range(4):
            vals = keychain.chain(k, opc, rand, sqn, autn[6:8], supi[:3], supi[3:5], supi, abba, count, pci, arfcn)
            named = dict(zip(keychain.FIELDS, vals))
            for f in SECRET_FIELDS:
                out[f"{f} {supi} #{challenges}/{count}"] = bytes.fromhex(named[f])
            # The chain's RRC and UP keys are for one algorithm each; a run may use
            # any (P1 N10: K_UPenc and K_UPint go over E1 for NEA2/NIA2), so every
            # algorithm key of TS 33.501 A.8 from this K_gNB is scanned for.
            kgnb = bytes.fromhex(named["K_gNB"])
            for dist, label in ((3, "K_RRCenc"), (4, "K_RRCint"), (5, "K_UPenc"), (6, "K_UPint")):
                for alg_id in (1, 2, 3):
                    out[f"{label} {supi} #{challenges}/{count}/alg{alg_id}"] = \
                        keychain.kdf(kgnb, 0x69, bytes([dist]), bytes([alg_id]))[16:]
    return out, challenges


def scan_tree(root: Path, secret: dict[str, bytes]) -> tuple[list[str], int]:
    hits, files = [], 0
    for f in sorted(root.rglob("*")):
        if f.is_symlink() or not f.is_file():
            continue
        files += 1
        data = f.read_bytes()
        for name, v in secret.items():
            for form, needle in forms(name, v):
                if needle and needle in data:
                    hits.append(f"{f.relative_to(root)}: {name.split(' ')[0]} as {form}")
    return hits, files


def main_run_dir(a) -> int:
    master = Path(a.master).read_bytes()
    first, _, count = a.block.partition("/")
    imsis = [f"{int(first) + i:015d}" for i in range(int(count or "1"))]
    secret, challenges = run_dir_secrets(Path(a.run_dir), master, imsis, a.pci, a.arfcn)
    hits, files = scan_tree(Path(a.run_dir), secret)
    for h in sorted(set(hits)):
        print(f"CANARY_HIT {h}")
    # Must-fail: the same scan finds a K written into a file in clear hex, and a
    # K_UPenc for NEA2 as raw octets (an E1AP capture that was not redacted).
    k0 = secret[f"K {imsis[0]}"]
    caught = any(needle in (b"x" + k0.hex().encode() + b"x") for _, needle in forms("K", k0))
    print(f"CANARY_MUSTFAIL {'CAUGHT' if caught else 'MISSED'} K as hex in a file")
    up = next((v for n, v in secret.items() if n.startswith("K_UPenc ") and n.endswith("/alg2")), None)
    up_caught = up is not None and any(needle in (b"\x00\x80" + up + b"\x00") for _, needle in forms("K_UPenc", up))
    print(f"CANARY_MUSTFAIL {'CAUGHT' if up_caught else 'MISSED'} K_UPenc (NEA2) in an unredacted E1AP frame")
    caught = caught and up_caught
    ok = not hits and caught and challenges > 0
    print(f"CANARY_RUN={'PASS' if ok else 'FAIL'} keys={len(secret)} challenges={challenges} files={files} "
          f"hits={len(set(hits))}")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--binary", default=str(ROOT / "build" / "dev" / "tests" / "canary" / "ksim_canary"))
    ap.add_argument("--run-dir", help="scan a ksim run directory instead (P1 N8)")
    ap.add_argument("--master", help="with --run-dir: the run's range master file")
    ap.add_argument("--block", help="with --run-dir: <first IMSI>/<count> of the run's cards")
    ap.add_argument("--pci", type=int, default=101)
    ap.add_argument("--arfcn", type=int, default=632628)
    a = ap.parse_args()
    if a.run_dir:
        if not a.master or not a.block:
            ap.error("--run-dir needs --master and --block")
        return main_run_dir(a)
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
