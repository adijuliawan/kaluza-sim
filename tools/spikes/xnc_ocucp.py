#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""P3 R0 spike 1 (ADR 0013 point 4): the Xn-C socket shape against OCUDU's CU-CP.

  tools/spikes/xnc_ocucp.py [--keep]

On loopback only, with the pinned OCUDU build (tools/ocudu-peer.sh build) and our scripted
core as its AMF. OCUDU's Xn-C gateway is one SCTP socket bound to port 38422 that both
listens and connects, and it accepts an association only from a configured peer address,
port included (lib/cu_cp/cu_cp_controller/xnc_connection_manager.cpp). The spike checks the
shape kaluza-sim's CU-CP will use, a one-to-many socket bound to 38422 that listens and
connects (both ends 38422, as TS 38.422 §7 names the port), in three cases:
  A  OCUDU dials us: our one-to-many socket on 127.0.0.21:38422 takes its association, and
     its first message (an XnAP PDU, PPID 61) is read
  B  we dial OCUDU from our one-to-many socket (source port 38422): accepted, no rejection
  C  we dial OCUDU from an ephemeral port (a one-to-one socket, no bind): rejected
Prints SPIKE_XNC_A/B/C=PASS|FAIL and SPIKE_XNC=PASS|FAIL. Nothing leaves 127.0.0.0/8.
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PIN = Path.home() / "kaluza-sim-peers/ocudu-d9d2263f4d/PIN"
B = ROOT / "build/dev/apps"
OURS, THEIRS, PORT, PPID = "127.0.0.21", "127.0.0.20", 38422, 61

CFG = """gnb_id: 417
gnb_id_bit_length: 22
ran_node_name: ocudu-cucp-xn
cu_cp:
  amf:
    addrs: 127.0.0.1
    port: {amf_port}
    bind_addrs: 127.0.0.5
    supported_tracking_areas:
      - tac: 1
        plmn_list:
          - plmn: "00101"
            tai_slice_support_list:
              - sst: 1
  e1ap:
    bind_addrs: 127.0.20.1
  f1ap:
    bind_addrs: 127.0.10.1
  xnap:
    no_connection_init: {no_init}
    gateways:
      - bind_addrs: {theirs}
        connections:
          - peer_addrs: {ours}
log:
  filename: {d}/ocucp.log
  all_level: info
pcap:
  xnap_enable: true
  xnap_filename: {d}/xnap.pcap
"""


def ocucp_bin() -> str:
    for line in PIN.read_text().splitlines():
        if line.startswith("ocucp="):
            return line.split("=", 1)[1].split()[0]
    raise SystemExit("no ocucp in the PIN file (tools/ocudu-peer.sh build)")


def start_ocucp(d: Path, amf_port: int, no_init: bool) -> subprocess.Popen:
    cfg = d / f"ocucp-{'b' if no_init else 'a'}.yml"
    cfg.write_text(CFG.format(amf_port=amf_port, no_init=str(no_init).lower(), theirs=THEIRS, ours=OURS, d=d))
    out = open(d / f"ocucp-{'b' if no_init else 'a'}.out", "w")
    return subprocess.Popen([ocucp_bin(), "-c", str(cfg)], stdout=out, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)


def wait_for(path: Path, pat: str, secs: float) -> bool:
    end = time.time() + secs
    while time.time() < end:
        if path.is_file() and re.search(pat, path.read_text(errors="replace"), re.M):
            return True
        time.sleep(0.1)
    return False


def rejections_above(log: Path, before: int, secs: float) -> bool:
    end = time.time() + secs
    while time.time() < end:
        if log.is_file() and log.read_text(errors="replace").count("Rejecting new CU-CP connection") > before:
            return True
        time.sleep(0.2)
    return False


def stop(p: subprocess.Popen) -> None:
    if p.poll() is None:
        p.send_signal(signal.SIGINT)
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()


def one_to_many() -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_SEQPACKET, socket.IPPROTO_SCTP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((OURS, PORT))
    s.listen(4)
    return s


def main() -> int:
    if subprocess.run(["pgrep", "-x", "gnb"], capture_output=True).returncode == 0:
        print("SPIKE_XNC=REFUSED (a gnb process runs: a B220 cell)")
        return 2
    d = Path(tempfile.mkdtemp(prefix="ksim-xnc-spike-"))
    keys = d / "keys"
    results: dict[str, str] = {}
    stub = None
    try:
        subprocess.run([str(B / "ksim-sim/ksim-sim"), "range", "init", "--master", str(keys / "master.key"),
                        "--kek", str(keys / "kek.key")], check=True, capture_output=True)
        amf_port = 39422
        stub_out = open(d / "stub.out", "w")
        stub = subprocess.Popen([str(B / "ksim-corestub/ksim-corestub"), "--listen", f"127.0.0.1:{amf_port}",
                                 "--master", str(keys / "master.key"), "--block", "001010000300001/2",
                                 "--ctl", str(d / "stub.sock")], stdout=stub_out, stderr=subprocess.STDOUT)
        if not wait_for(d / "stub.out", r"^CTL=", 5):
            print("SPIKE_XNC=FAIL (the scripted core did not start)")
            return 1

        # A: OCUDU dials our one-to-many socket.
        s = one_to_many()
        s.settimeout(15)
        p = start_ocucp(d, amf_port, no_init=False)
        try:
            data, anc, flags, addr = s.recvmsg(65536)
            first = data[:4].hex()
            ok = addr[0] == THEIRS and addr[1] == PORT and len(data) > 4 and data[0] == 0x00
            results["A"] = "PASS" if ok else "FAIL"
            print(f"SPIKE_XNC_A={results['A']} peer={addr[0]}:{addr[1]} first_octets={first} bytes={len(data)}")
        except (socket.timeout, OSError) as e:
            results["A"] = "FAIL"
            print(f"SPIKE_XNC_A=FAIL ({e})")
        stop(p)
        s.close()
        time.sleep(1)

        # B and C: OCUDU waits (no_connection_init); we dial it.
        p = start_ocucp(d, amf_port, no_init=True)
        log = d / "ocucp.log"
        wait_for(d / "ocucp-b.out", r"Xn-C.*Listening|Listening for new connections.*38422", 10)
        time.sleep(1)
        c = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_SCTP)   # C: ephemeral port
        c.bind((OURS, 0))
        c.settimeout(5)
        try:
            c.connect((THEIRS, PORT))
        except OSError as e:
            print(f"  C connect: {e}")
        eph = c.getsockname()[1]
        time.sleep(2)
        c.close()
        time.sleep(1)
        s = one_to_many()   # B: from 38422
        s.settimeout(5)
        try:
            s.connect((THEIRS, PORT))
            connected = True
        except OSError as e:
            connected = False
            print(f"  B connect: {e}")
        time.sleep(2)
        s.close()
        time.sleep(1)
        stop(p)   # OCUDU's log file is complete once it has stopped
        text = log.read_text(errors="replace") if log.is_file() else ""
        rejected_c = f"peer address {OURS}:{eph}" in text
        rejected_b = f"peer address {OURS}:{PORT}" in text or "is already connected" in text
        accepted_b = "Xn-C peer 0 disconnected" in text
        results["C"] = "PASS" if rejected_c else "FAIL"
        print(f"SPIKE_XNC_C={results['C']} source_port={eph} rejected={int(rejected_c)}")
        results["B"] = "PASS" if connected and accepted_b and not rejected_b else "FAIL"
        print(f"SPIKE_XNC_B={results['B']} source_port={PORT} connected={int(connected)} accepted={int(accepted_b)} rejected={int(rejected_b)}")
        for line in text.splitlines():
            if "Rejecting new CU-CP connection" in line:
                print(f"  OCUDU: {line.strip()[:200]}")
    finally:
        if stub is not None:
            stub.terminate()
            stub.wait(5)
        if "--keep" in sys.argv:
            print(f"SPIKE_DIR={d}")
        else:
            shutil.rmtree(d, ignore_errors=True)
    verdict = "PASS" if all(results.get(k) == "PASS" for k in "ABC") else "FAIL"
    print(f"SPIKE_XNC={verdict}")
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
