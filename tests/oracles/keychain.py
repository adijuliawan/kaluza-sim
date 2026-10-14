#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Key-chain oracle (plan M9): the 5G AKA key chain recomputed in Python from
the specification text, compared with our C++ on random synthetic inputs.

    tests/oracles/keychain.py --cxx build/dev/tests/unit/crypto/keychain_dump [--n 10000] [--seed 1]

Independent of src/crypto: AES-128 is written here from FIPS 197 (MILENAGE's
kernel, TS 35.206 §4.1), MILENAGE from TS 35.206 §4.1, the KDF from TS 33.220
B.2.0, and every derivation from TS 33.501 Annex A and TS 33.402 A.2. Only
HMAC-SHA-256 and SHA-256 come from the standard library. The inputs are random
test values, never a real subscriber's keys.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import random
import subprocess
import sys

# ---- AES-128, FIPS 197 -------------------------------------------------------------


def _xtime(a: int) -> int:
    a <<= 1
    return (a ^ 0x11B) if a & 0x100 else a


def _gmul(a: int, b: int) -> int:
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


def _sbox() -> list[int]:
    inv = [0] * 256
    for x in range(1, 256):
        for y in range(1, 256):
            if _gmul(x, y) == 1:
                inv[x] = y
                break
    out = []
    for x in range(256):
        b, r = inv[x], 0x63
        for i in range(8):
            bit = ((b >> i) ^ (b >> ((i + 4) % 8)) ^ (b >> ((i + 5) % 8)) ^ (b >> ((i + 6) % 8))
                   ^ (b >> ((i + 7) % 8))) & 1
            r ^= bit << i
        out.append(r)
    return out


SBOX = _sbox()
MUL2 = [_gmul(x, 2) for x in range(256)]
MUL3 = [_gmul(x, 3) for x in range(256)]


def aes128_key_schedule(key: bytes) -> list[list[int]]:
    w = [list(key[4 * i:4 * i + 4]) for i in range(4)]
    rcon = 1
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = [SBOX[t[1]] ^ rcon, SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]]
            rcon = _xtime(rcon)
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    return [sum(w[4 * r:4 * r + 4], []) for r in range(11)]


def aes128_encrypt(rk: list[list[int]], block: bytes) -> bytes:
    s = [b ^ k for b, k in zip(block, rk[0])]     # s[r + 4c]: row r, column c
    for rnd in range(1, 11):
        s = [SBOX[b] for b in s]
        s = [s[(r + 4 * ((c + r) % 4))] for c in range(4) for r in range(4)]   # ShiftRows
        if rnd != 10:
            t = []
            for c in range(4):
                a0, a1, a2, a3 = s[4 * c:4 * c + 4]
                t += [MUL2[a0] ^ MUL3[a1] ^ a2 ^ a3, a0 ^ MUL2[a1] ^ MUL3[a2] ^ a3,
                      a0 ^ a1 ^ MUL2[a2] ^ MUL3[a3], MUL3[a0] ^ a1 ^ a2 ^ MUL2[a3]]
            s = t
        s = [b ^ k for b, k in zip(s, rk[rnd])]
    return bytes(s)


def _selftest_aes() -> None:
    # FIPS 197 Appendix C.1.
    rk = aes128_key_schedule(bytes(range(16)))
    got = aes128_encrypt(rk, bytes.fromhex("00112233445566778899aabbccddeeff")).hex()
    assert got == "69c4e0d86a7b0430d8cdb78070b4c55a", got


# ---- MILENAGE, TS 35.206 §4.1 -------------------------------------------------------

def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _rot(x: bytes, r_bits: int) -> bytes:
    r = r_bits // 8                                 # towards the most significant bit
    return x[r:] + x[:r]


def milenage(k: bytes, opc: bytes, rand: bytes, sqn: bytes, amf: bytes) -> dict[str, bytes]:
    rk = aes128_key_schedule(k)
    e = lambda x: aes128_encrypt(rk, x)             # noqa: E731
    temp = e(_xor(rand, opc))
    in1 = sqn + amf + sqn + amf
    c = [None, bytes(16)] + [bytes(15) + bytes([1 << (n - 2)]) for n in range(2, 6)]
    r = [None, 64, 0, 32, 64, 96]
    out1 = _xor(e(_xor(_xor(temp, _rot(_xor(in1, opc), r[1])), c[1])), opc)
    out = {n: _xor(e(_xor(_rot(_xor(temp, opc), r[n]), c[n])), opc) for n in range(2, 6)}
    return {"mac_a": out1[:8], "mac_s": out1[8:], "res": out[2][8:], "ak": out[2][:6],
            "ck": out[3], "ik": out[4], "ak_star": out[5][:6]}


# ---- KDF, TS 33.220 B.2.0, and TS 33.501 Annex A ------------------------------------

def kdf(key: bytes, fc: int, *params: bytes) -> bytes:
    s = bytes([fc]) + b"".join(p + len(p).to_bytes(2, "big") for p in params)
    return hmac.new(key, s, hashlib.sha256).digest()


def snn(mcc: str, mnc: str) -> str:
    return f"5G:mnc{mnc.zfill(3)}.mcc{mcc}.3gppnetwork.org"      # TS 24.501 9.12.1


# --mutate: commit one of the known key traps on the Python side; the run must then fail.
MUTATIONS = ("kamf-bcd", "kgnb-3-octet-count", "snn-no-pad")
MUTATE: str | None = None


def _bcd(digits: str) -> bytes:
    d = digits + ("F" if len(digits) % 2 else "")
    return bytes(int(d[i + 1], 16) << 4 | int(d[i], 16) for i in range(0, len(d), 2))


def chain(k, opc, rand, sqn, amf, mcc, mnc, supi, abba, count, pci, arfcn) -> list[str]:
    m = milenage(k, opc, rand, sqn, amf)
    name = snn(mcc, mnc) if MUTATE != "snn-no-pad" else f"5G:mnc{mnc}.mcc{mcc}.3gppnetwork.org"
    sn = name.encode()
    ck_ik = m["ck"] + m["ik"]
    sqn_ak = _xor(sqn, m["ak"])
    kausf = kdf(ck_ik, 0x6A, sn, sqn_ak)                                  # A.2
    res_star = kdf(ck_ik, 0x6B, sn, rand, m["res"])[16:]                  # A.4
    hres = hashlib.sha256(rand + res_star).digest()[16:]                  # A.5
    kseaf = kdf(kausf, 0x6C, sn)                                          # A.6
    p0 = _bcd(supi) if MUTATE == "kamf-bcd" and supi.isdigit() else supi.encode()
    kamf = kdf(kseaf, 0x6D, p0, abba)                                     # A.7
    alg = lambda key, d, a: kdf(key, 0x69, bytes([d]), bytes([a]))[16:]   # A.8  # noqa: E731
    kgnb = kdf(kamf, 0x6E, count.to_bytes(3 if MUTATE == "kgnb-3-octet-count" else 4, "big"), b"\x01")  # A.9
    nh = kdf(kamf, 0x6F, kgnb)                                            # A.10
    kstar = kdf(kgnb, 0x70, pci.to_bytes(2, "big"), arfcn.to_bytes(3, "big"))   # A.11
    ckik_p = kdf(ck_ik, 0x20, sn, sqn_ak)                                 # TS 33.402 A.2
    vals = [m["mac_a"], m["res"], m["ck"], m["ik"], m["ak"], m["ak_star"], m["mac_s"], name, sqn_ak,
            kausf, res_star, hres, kseaf, kamf, alg(kamf, 1, 2), alg(kamf, 2, 2), kgnb, alg(kgnb, 3, 2),
            alg(kgnb, 4, 2), alg(kgnb, 5, 1), alg(kgnb, 6, 1), nh, kstar, ckik_p[:16], ckik_p[16:]]
    return [v if isinstance(v, str) else v.hex() for v in vals]


FIELDS = ["MAC-A", "RES", "CK", "IK", "AK", "AK*", "MAC-S", "SNN", "SQN^AK", "K_AUSF", "RES*", "HXRES*",
          "K_SEAF", "K_AMF", "K_NASenc", "K_NASint", "K_gNB", "K_RRCenc", "K_RRCint", "K_UPenc", "K_UPint",
          "NH", "K_NG-RAN*", "CK'", "IK'"]


def random_input(rng: random.Random) -> tuple:
    b = lambda n: bytes(rng.getrandbits(8) for _ in range(n))   # noqa: E731
    mcc = f"{rng.randrange(1000):03d}"
    mnc = f"{rng.randrange(100):02d}" if rng.random() < 0.5 else f"{rng.randrange(1000):03d}"
    if rng.random() < 0.9:
        supi = mcc + mnc + "".join(str(rng.randrange(10)) for _ in range(15 - 3 - len(mnc)))
    else:
        supi = f"user{rng.randrange(10**6)}@nai.5gc.mnc{mnc.zfill(3)}.mcc{mcc}.3gppnetwork.org"
    abba = b"\x00\x00" if rng.random() < 0.8 else b(2)
    count = (rng.randrange(1 << 16) << 8) | rng.randrange(256)
    return (b(16), b(16), b(16), b(6), b(2), mcc, mnc, supi, abba, count, rng.randrange(1008),
            rng.randrange(3279166))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cxx", required=True, help="the keychain_dump test binary")
    ap.add_argument("--n", type=int, default=10000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--mutate", choices=MUTATIONS, help="must-fail: commit a key trap in the oracle")
    a = ap.parse_args()
    global MUTATE
    MUTATE = a.mutate
    _selftest_aes()
    rng = random.Random(a.seed)
    inputs = [random_input(rng) for _ in range(a.n)]
    lines = []
    for (k, opc, rand, sqn, amf, mcc, mnc, supi, abba, count, pci, arfcn) in inputs:
        lines.append(" ".join([k.hex(), opc.hex(), rand.hex(), sqn.hex(), amf.hex(), mcc, mnc, supi, abba.hex(),
                               str(count), str(pci), str(arfcn)]))
    proc = subprocess.run([a.cxx], input="\n".join(lines) + "\n", capture_output=True, text=True, check=True)
    got = proc.stdout.splitlines()
    if len(got) != len(inputs):
        print(f"KEYCHAIN_ORACLE=FAIL lines={len(got)} expected={len(inputs)}")
        return 1
    bad: dict[str, int] = {}
    for inp, line in zip(inputs, got):
        want = chain(*inp)
        have = line.split(" ")
        for f, w, h in zip(FIELDS, want, have + [""] * len(FIELDS)):
            if w != h:
                bad[f] = bad.get(f, 0) + 1
    verdict = "PASS" if not bad else "FAIL"
    detail = " ".join(f"{f}={n}" for f, n in bad.items())
    mut = f" mutate={a.mutate}" if a.mutate else ""
    print(f"KEYCHAIN_ORACLE={verdict} n={len(inputs)} values={len(inputs) * len(FIELDS)} seed={a.seed}{mut} {detail}")
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
