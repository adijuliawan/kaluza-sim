# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""pySim-shell and pySim-trace over our soft card on a virtual reader (P1 N14).

ksim-sim serve puts the card (test keys only) on pcscd's vpcd reader; pySim,
run as a separate program with its own interpreter, reads it as it reads a real
card. Nothing of pySim is copied or linked.

  1. Generic UICC: pySim-shell `fsdump --json` reads every file pySim knows.
     Each EF of our image that pySim models is read and decoded when its ARR
     grants READ after a reset (ksim-sim validate --access), or refused with
     SW 6982 when not. pySim-trace (gsmtap-udp) decodes the card's live
     GSMTAP-SIM: every EF read appears at its own path, with no unknown file
     and no exception; tshark reads the same records from the trace pcapng.
  2. The sysmoISIM-SJA5 personality (that card's ATR): pySim adds its own
     files, so AF20 and AF30 are tried, and refused. The plain `fsdump` goes
     through ksim-sim import into a new image that ksim-sim validate accepts.

Prints KEY=value lines; exit 0 pass, 1 fail, 77 skip (no pcscd, vpcd, pySim
or free reader).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

TEST_K = "465b5ce8b199b49faa5f0a2ee238a6bc"     # TS 35.208 test set 1: must never show in a trace
TEST_OPC = "cd63cb71954a9f4e48a5994e37a02baf"


def skip(why: str) -> int:
    print(f"PYSIM=SKIP ({why})")
    return 77


def dump_json(text: str) -> dict:
    a, b = text.find("{"), text.rfind("}")
    return json.loads(text[a:b + 1]) if a >= 0 and b > a else {}


def by_name(dump: dict) -> dict:
    """pySim's files by their path of names, lower case (mf/adf.usim/ef.imsi)."""
    return {p.lower(): f for p, f in dump.get("files", {}).items()}


class Serve:
    """ksim-sim serve for one pySim run."""

    def __init__(self, args, tmp: Path, extra: list[str]):
        cmd = [args.ksim_sim, "serve", "--test-keys", "--template", args.template, "--vpcd",
               f"127.0.0.1:{35963 + args.reader}", "--seconds", "180"] + extra
        self.p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.lines: list[str] = []
        self.tmp = tmp

    def wait_connected(self, timeout: float) -> bool:
        os.set_blocking(self.p.stdout.fileno(), False)
        end = time.time() + timeout
        while time.time() < end:
            line = self.p.stdout.readline()
            if line:
                self.lines.append(line.strip())
                if line.startswith("READER=connected"):
                    return True
            elif self.p.poll() is not None:
                return False
            else:
                time.sleep(0.05)
        return False

    def stop(self) -> dict:
        if self.p.poll() is None:
            self.p.send_signal(signal.SIGTERM)
        try:
            out, _ = self.p.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            self.p.kill()
            out, _ = self.p.communicate()
        self.lines += out.splitlines()
        return dict(l.split("=", 1) for l in self.lines if "=" in l)


def pysim_shell(args, env: dict, script: str, tmp: Path, name: str) -> tuple[int, str]:
    sp = tmp / f"{name}.script"
    sp.write_text(script)
    r = subprocess.run([args.pysim_py, str(Path(args.pysim_dir) / "pysim-src" / "pySim-shell.py"),
                        "--pcsc-regex", f"Virtual PCD 00 {args.reader:02d}", "--noprompt", "--script", str(sp)],
                       env=env, capture_output=True, text=True, timeout=240)
    (tmp / f"{name}.out").write_text(r.stdout)
    (tmp / f"{name}.err").write_text(r.stderr)
    return r.returncode, r.stdout


def main() -> int:
    ap = argparse.ArgumentParser()
    root = Path(__file__).resolve().parents[2]
    ap.add_argument("--ksim-sim", default=str(root / "build/dev/apps/ksim-sim/ksim-sim"))
    ap.add_argument("--template", default=str(root / "cards/usim-5g.yaml"))
    ap.add_argument("--pysim-dir", default=os.environ.get("KSIM_PYSIM_DIR", "/home/amadeus/Development/ran/usim"))
    ap.add_argument("--reader", type=int, default=1, help="vpcd reader n (port 35963+n); 0 is left for people")
    ap.add_argument("--keep", help="copy the run's files here")
    args = ap.parse_args()
    args.pysim_py = str(Path(args.pysim_dir) / ".venv-pysim/bin/python")
    if not Path(args.ksim_sim).is_file():
        return skip("no ksim-sim; build the dev preset")
    if not Path(args.pysim_py).is_file():
        return skip(f"no pySim venv in {args.pysim_dir}")
    env = dict(os.environ, PYTHONPATH=str(Path(args.pysim_dir) / "pysim-src"), PYTHONUNBUFFERED="1")

    # pcscd starts on its socket's first client; its vpcd driver then listens.
    r = subprocess.run([args.pysim_py, "-c", "from smartcard.System import readers; print('\\n'.join(map(str, readers())))"],
                       env=env, capture_output=True, text=True, timeout=30)
    reader = f"Virtual PCD 00 {args.reader:02d}"
    if reader not in r.stdout:
        return skip(f"pcscd has no '{reader}' (vsmartcard-vpcd)")

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        rc = run(args, env, tmp)
        if args.keep:
            Path(args.keep).mkdir(parents=True, exist_ok=True)
            (Path(args.keep) / "summary.txt").write_text("\n".join(SUMMARY) + "\n")
            for f in tmp.iterdir():
                if f.is_file():
                    (Path(args.keep) / f.name).write_bytes(f.read_bytes())
        return rc


SUMMARY: list[str] = []


def say(line: str) -> None:
    print(line)
    SUMMARY.append(line)


def run(args, env: dict, tmp: Path) -> int:
    fails: list[str] = []
    # What our image grants after a reset.
    v = subprocess.run([args.ksim_sim, "validate", "--access", args.template], capture_output=True, text=True)
    if v.returncode != 0:
        print(v.stdout)
        print("PYSIM=FAIL (the template does not validate)")
        return 1
    expect = {}
    for m in re.finditer(r"^EF=(\S+) NAME=(\S+) READ=(granted|denied)$", v.stdout, re.M):
        expect[m.group(2).lower()] = (m.group(1), m.group(3))

    # pySim-trace on GSMTAP's port, if it is free; pyshark is imported by sources we do not use.
    trace_on = True
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 4729))
        s.close()
    except OSError:
        trace_on = False
    stub = tmp / "stub" / "pyshark"
    stub.mkdir(parents=True)
    (stub / "__init__.py").write_text("# stand-in: pySim-trace's gsmtap-udp source does not use pyshark\n")
    tenv = dict(env, PYTHONPATH=env["PYTHONPATH"] + os.pathsep + str(tmp / "stub"))
    tracer = None
    if trace_on:
        tracer = subprocess.Popen([args.pysim_py, "-u", str(Path(args.pysim_dir) / "pysim-src" / "pySim-trace.py"),
                                   "gsmtap-udp", "-i", "127.0.0.1"],
                                  env=tenv, stdout=open(tmp / "trace.out", "w"), stderr=subprocess.STDOUT)
        time.sleep(2)

    # 1. The generic card.
    serve = Serve(args, tmp, ["--trace-udp", "127.0.0.1:4729", "--trace-pcap", str(tmp / "sim.pcapng")])
    if not serve.wait_connected(15):
        serve.stop()
        if tracer:
            tracer.terminate()
        return skip(f"the card did not get onto the reader: {' | '.join(serve.lines[-3:])}")
    rc, out = pysim_shell(args, env, "fsdump --json\n", tmp, "generic")
    s1 = serve.stop()
    if tracer:
        time.sleep(1)
        tracer.terminate()
        tracer.wait(timeout=10)
    d1 = by_name(dump_json(out))
    if rc != 0 or not d1:
        fails.append(f"pySim-shell rc={rc}, no dump")

    # 2. The sysmoISIM-SJA5 personality, plain fsdump, then import.
    serve = Serve(args, tmp, ["--personality", "sysmoISIM-SJA5"])
    d2 = {}
    if serve.wait_connected(15):
        rc2, out2 = pysim_shell(args, env, "fsdump\n", tmp, "sja5")
        d2 = by_name(dump_json(out2))
        (tmp / "sja5.fsdump").write_text(out2)
        if rc2 != 0 or not d2:
            fails.append(f"pySim-shell (SJA5) rc={rc2}, no dump")
    else:
        fails.append("the SJA5 card did not get onto the reader")
    serve.stop()

    # Every EF of ours that pySim models: read and decoded, or refused with 6982.
    ok, modelled, unmodelled = 0, 0, []
    for name, (path, read) in sorted(expect.items()):
        f = d1.get(name) or d2.get(name)
        if f is None:
            unmodelled.append(name)
            continue
        modelled += 1
        if read == "granted":
            body = (d1.get(name) or {}).get("body")
            if body is not None and "error" not in (d1.get(name) or {}):
                ok += 1
            else:
                fails.append(f"{name} ({path}): READ granted but pySim got {f.get('error')}")
        else:
            sw = (f.get("error") or {}).get("sw_actual", "")
            if str(sw).lower() == "6982":
                ok += 1
            else:
                fails.append(f"{name} ({path}): READ denied but pySim got {sw or 'its contents'}")
    say(f"PYSIM_EF_READ={ok}/{modelled}")
    say(f"PYSIM_EF_UNMODELLED={len(unmodelled)}{' ' + ' '.join(unmodelled) if unmodelled else ''}")
    say(f"SERVE_APDUS={s1.get('APDUS', '?')} SERVE_TRACED={s1.get('TRACED', '?')}")

    # pySim-trace: every EF read decoded at its own path, nothing unknown.
    if trace_on:
        t = re.sub(r"\x1b\[[0-9;]*m", "", (tmp / "trace.out").read_text())
        read_paths = set(re.findall(r"^\d+ READ (?:BINARY|RECORD)\s+(\S+)", t, re.M))
        unknown = len(re.findall(r"UNKNOWN FID", t))
        tbs = len(re.findall(r"Traceback", t))
        want = {n for n, (p, rd) in expect.items() if rd == "granted" and n in d1}
        seen = {p.lower() for p in read_paths}
        missing = sorted(want - seen)
        say(f"PYSIM_TRACE_READS={len(want) - len(missing)}/{len(want)} PYSIM_TRACE_UNKNOWN={unknown} "
              f"PYSIM_TRACE_EXCEPTIONS={tbs}")
        if missing or unknown or tbs:
            fails.append(f"pySim-trace: missing {missing}, unknown {unknown}, exceptions {tbs}")
    else:
        say("PYSIM_TRACE=SKIP (UDP 4729 is taken)")

    # tshark on the same records; the canary on the trace.
    pcap = (tmp / "sim.pcapng").read_bytes() if (tmp / "sim.pcapng").exists() else b""
    t = subprocess.run(["tshark", "-r", "-", "-Y", "gsm_sim"], input=pcap, capture_output=True, timeout=120)
    frames = len(t.stdout.splitlines())
    m = subprocess.run(["tshark", "-r", "-", "-Y", "_ws.malformed || _ws.expert.severity >= error"], input=pcap,
                       capture_output=True, timeout=120)
    bad = len(m.stdout.splitlines())
    hits = sum(pcap.count(bytes.fromhex(k)) for k in (TEST_K, TEST_OPC))
    say(f"TSHARK_SIM_FRAMES={frames} TSHARK_SIM_MALFORMED={bad} TRACE_KEY_HITS={hits}")
    if frames == 0 or bad or hits:
        fails.append(f"tshark: {frames} frames, {bad} malformed; key hits {hits}")

    # import: the SJA5 dump into a new image, which validates.
    if d2:
        out_img = tmp / "imported.yaml"
        im = subprocess.run([args.ksim_sim, "import", "--fsdump", str(tmp / "sja5.fsdump"), "--template",
                             args.template, "--out", str(out_img)], capture_output=True, text=True)
        va = subprocess.run([args.ksim_sim, "validate", str(out_img)], capture_output=True, text=True)
        imported = re.search(r"IMPORTED=(\d+)", im.stdout)
        say(f"IMPORT={imported.group(1) if imported else '?'} IMPORT_VALID={'1' if va.returncode == 0 else '0'}")
        if im.returncode != 0 or va.returncode != 0 or not imported or int(imported.group(1)) == 0:
            fails.append(f"import: {im.stdout.strip()} {im.stderr.strip()} / {va.stdout.strip()}")

    for f in fails:
        print(f"PROBLEM={f}")
    say(f"PYSIM={'PASS' if not fails else 'FAIL'}")
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
