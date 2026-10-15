#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Device personas from phone captures (P1 N15; architecture section 6).

  tools/persona_extract.py --capture <Exported-PDU pcap> [--imeisv-from <pcap>]
                           --name <name> --device <text> --out personas/<name>.yaml
  tools/persona_extract.py --check personas/*.yaml [--captures <dir>]

Extraction reads, from a capture the phone's modem logged (kaluza-ue, classic
pcap of DLT 252, NR RRC and 5GS NAS in clear):
  - the UE-CapabilityRAT-ContainerList of the first UECapabilityInformation:
    each container's RAT type and its octets, as the phone sent them;
  - from the first REGISTRATION REQUEST that has them: the 5GMM capability, UE
    security capability, S1 UE network capability, UE's usage setting and
    requested NSSAI, as the IE value octets;
  - from an IMEISV (SECURITY MODE COMPLETE or IDENTITY RESPONSE), if one is
    seen: the TAC (8 digits, the model) and the SVN. The serial number never.
A persona holds nothing that identifies a subscriber or a handset: the tool
refuses to write one that contains the capture's IMSI or IMEI digits.

--check decodes every container of each persona with pycrate (our Rel-19 RRC)
and tshark (nr-rrc.ue_nr_cap_msg), and, with --captures, extracts again and
compares byte for byte. pycrate re-encodes the phones' containers longer than
they came; that is noted, not failed (the UE sends the phone's octets). Prints PERSONA=<name> lines and PERSONAS=PASS|FAIL.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests" / "oracles"))
from ksimoracle import pcap, rrc  # noqa: E402

RAT_DISSECTOR = {"nr": "nr-rrc.ue_nr_cap_msg", "eutra-nr": "nr-rrc.ue_mrdc_cap_msg", "eutra": "lte-rrc.ue_eutra_cap_msg"}
RAT_TYPE = {"nr": "UE-NR-Capability", "eutra-nr": "UE-MRDC-Capability"}
# pycrate's IE name, the persona's key, and the IEI of the REGISTRATION REQUEST (TS 24.501 8.2.6).
NAS_IES = [("5GMMCap", "mm_capability", 0x10), ("UESecCap", "ue_security_capability", 0x2E),
           ("S1UENetCap", "s1_ue_network_capability", 0x17), ("UEUsage", "ue_usage_setting", 0x18),
           ("NSSAI", "requested_nssai", 0x2F)]


def nas5g():
    from pycrate_mobile import NAS5G
    return NAS5G


def present(msg, name: str) -> bool:
    """pycrate keeps an absent optional IE in the message, transparent."""
    return name in msg._by_name and msg[name].get_trans() is False


def tlv_value(ie, iei: int) -> bytes:
    """The value octets of a TLV IE (IEI, one length octet, value)."""
    b = ie.to_bytes()
    if len(b) < 2 or b[0] != iei or len(b) < 2 + b[1]:
        raise ValueError(f"IE {ie._name}: not a TLV with IEI {iei:02x}")
    return b[2:2 + b[1]]


def bcd_digits(b: bytes) -> str:
    out = ""
    for o in b:
        for n in (o & 0x0F, o >> 4):
            if n <= 9:
                out += str(n)
    return out


def extract(capture: Path, imeisv_from: Path | None) -> tuple[dict, set[str]]:
    """The persona's fields, and the identity digit strings seen (for the guard)."""
    recs = pcap.read_exported_pdu(capture.read_bytes())
    NAS5G = nas5g()
    ul = rrc.obj("UL-DCCH-Message")
    out: dict = {"containers": [], "nas": {}, "frames": {}}
    identities: set[str] = set()
    for n, name, pdu in recs:
        if name == "nr-rrc.ul.dcch" and not out["containers"]:
            try:
                ul.from_uper(pdu)
            except Exception:
                continue
            c1 = ul.get_val()["message"][1]
            if c1[0] == "ueCapabilityInformation":
                lst = c1[1]["criticalExtensions"][1].get("ue-CapabilityRAT-ContainerList", [])
                out["containers"] = [(c["rat-Type"], bytes(c["ue-CapabilityRAT-Container"])) for c in lst]
                out["frames"]["capability"] = n
        if name == "nas-5gs":
            m, err = NAS5G.parse_NAS5G(pdu)
            if err or m is None:
                continue
            msgs = [m]
            if m._name == "5GMMSecurityModeComplete":
                try:
                    inner = m["NASContainer"][-1].get_val()
                    m2, e2 = NAS5G.parse_NAS5G(inner)
                    if m2 is not None and not e2:
                        msgs.append(m2)
                except Exception:
                    pass
            for mm in msgs:
                if present(mm, "5GSID"):   # the identity's digits, to refuse them in the output
                    identities.add(bcd_digits(mm["5GSID"].to_bytes())[-10:])
                if mm._name == "5GMMRegistrationRequest" and present(mm, "5GMMCap") and not out["nas"]:
                    for ie_name, key, iei in NAS_IES:
                        if present(mm, ie_name):
                            out["nas"][key] = tlv_value(mm[ie_name], iei)
                    out["frames"]["registration"] = n
    if imeisv_from is not None:
        t = subprocess.run(["tshark", "-r", "-", "-Y", "nas-5gs.mm.type_id == 5", "-T", "fields", "-e", "nas-5gs.mm.imeisv"],
                           input=imeisv_from.read_bytes(), capture_output=True, timeout=120)
        v = next((l.strip() for l in t.stdout.decode().splitlines() if re.fullmatch(r"\d{16}", l.strip().split(",")[0])), "")
        v = v.split(",")[0]
        if v:
            out["imeisv"] = {"tac": v[:8], "svn": v[14:16]}
            identities.add(v[8:14])   # the serial number: never in a persona
    return out, identities


def to_yaml(name: str, device: str, sources: list[tuple[Path, str]], p: dict) -> str:
    lines = ["# SPDX-FileCopyrightText: 2026 Adi Juliawan", "# SPDX-License-Identifier: LicenseRef-kaluza-sim-private", "#",
             f"# Persona {name} (P1 N15): written by tools/persona_extract.py from the captures named below.",
             "# Capabilities as the phone sent them; no subscriber or handset identity (only the IMEISV's TAC and SVN).",
             "# The UE applies them intersected with what kaluza-sim implements (node/ue/persona, row KS-SCN-B1).",
             f"name: {name}", f"device: {device}", "sources:"]
    for path, digest in sources:
        lines.append(f"  - {{capture: {path.parent.name}/{path.name}, sha256: {digest}}}")
    if "imeisv" in p:
        lines.append(f"imeisv: {{tac: \"{p['imeisv']['tac']}\", svn: \"{p['imeisv']['svn']}\"}}")
    lines.append("nas:")
    for _, key, _ in NAS_IES:
        if key in p["nas"]:
            lines.append(f"  {key}: {p['nas'][key].hex()}")
    lines.append("rrc:")
    lines.append("  ue_capability_rat_containers:")
    for rat, b in p["containers"]:
        lines.append(f"    - rat: {rat}")
        lines.append(f"      uper: {b.hex()}")
    return "\n".join(lines) + "\n"


def from_yaml(text: str) -> dict:
    """Our own layout back (no YAML library in the oracle venv)."""
    p: dict = {"nas": {}, "containers": [], "sources": []}
    rat = None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("#") or not s:
            continue
        if m := re.match(r"name: (\S+)$", s):
            p["name"] = m.group(1)
        elif m := re.match(r"- \{capture: (\S+), sha256: ([0-9a-f]+)\}$", s):
            p["sources"].append((m.group(1), m.group(2)))
        elif m := re.match(r'imeisv: \{tac: "(\d{8})", svn: "(\d{2})"\}$', s):
            p["imeisv"] = {"tac": m.group(1), "svn": m.group(2)}
        elif m := re.match(r"(mm_capability|ue_security_capability|s1_ue_network_capability|ue_usage_setting|requested_nssai): ([0-9a-f]+)$", s):
            p["nas"][m.group(1)] = bytes.fromhex(m.group(2))
        elif m := re.match(r"- rat: (\S+)$", s):
            rat = m.group(1)
        elif m := re.match(r"uper: ([0-9a-f]+)$", s):
            p["containers"].append((rat, bytes.fromhex(m.group(1))))
    return p


def check(files: list[Path], captures: Path | None) -> int:
    bad = 0
    for f in files:
        p = from_yaml(f.read_text())
        problems: list[str] = []
        notes: list[str] = []
        for rat, b in p["containers"]:
            if rat in RAT_TYPE:
                o = rrc.obj(RAT_TYPE[rat])
                try:
                    o.from_uper(b)
                except Exception as e:
                    problems.append(f"{rat}: pycrate: {str(e)[:80]}")
                else:
                    # pycrate re-encodes the phones' containers longer (KS-SCN-T2):
                    # noted, not a failure; the octets the UE sends are the phone's.
                    try:
                        same = o.to_uper() == b
                    except Exception:
                        same = False
                    notes.append(f"{rat}: pycrate re-encodes {'the same' if same else 'differently'}")
            diss = RAT_DISSECTOR.get(rat)
            if diss:
                cap = pcap.exported_pdu([(diss, b)])
                t = subprocess.run(["tshark", "-r", "-", "-Y", "_ws.malformed || _ws.expert.severity >= warning"],
                                   input=cap, capture_output=True, timeout=60)
                if t.stdout.strip():
                    problems.append(f"{rat}: tshark: {t.stdout.decode()[:120]}")
        if captures is not None:
            for src, digest in p["sources"][:1]:
                path = captures / src
                if not path.is_file():
                    problems.append(f"no capture {src} under {captures}")
                    continue
                if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                    problems.append(f"{src}: not the capture extracted from")
                    continue
                again, _ = extract(path, None)
                if [c for c in again["containers"]] != p["containers"]:
                    problems.append("the containers differ from the capture")
                for key, v in p["nas"].items():
                    if again["nas"].get(key) != v:
                        problems.append(f"nas {key} differs from the capture")
        status = "PASS" if not problems else "FAIL"
        print(f"PERSONA={p.get('name', f.stem)} {status} containers={len(p['containers'])} "
              f"nas={len(p['nas'])} imeisv_tac={'yes' if 'imeisv' in p else 'no'}")
        for pr in problems:
            print(f"  PROBLEM {pr}")
        for nt in notes:
            print(f"  NOTE {nt}")
        bad += bool(problems)
    print(f"PERSONAS={'PASS' if bad == 0 else 'FAIL'}")
    return 0 if bad == 0 else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--capture", type=Path)
    ap.add_argument("--imeisv-from", type=Path)
    ap.add_argument("--name")
    ap.add_argument("--device", default="")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--check", nargs="*", type=Path)
    ap.add_argument("--captures", type=Path, help="with --check: the capture directory to extract again from")
    a = ap.parse_args()
    if a.check is not None:
        return check(a.check, a.captures)
    if not (a.capture and a.name and a.out):
        ap.error("--capture, --name and --out")
    p, identities = extract(a.capture, a.imeisv_from)
    if not p["containers"] or not p["nas"]:
        print("PERSONA=FAIL (no UECapabilityInformation or REGISTRATION REQUEST with capabilities in the capture)")
        return 1
    sources = [(a.capture, hashlib.sha256(a.capture.read_bytes()).hexdigest())]
    if a.imeisv_from:
        sources.append((a.imeisv_from, hashlib.sha256(a.imeisv_from.read_bytes()).hexdigest()))
    text = to_yaml(a.name, a.device, sources, p)
    flat = text.replace(" ", "")
    if any(d and len(d) >= 6 and d in flat for d in identities):
        print("PERSONA=REFUSED (an identity's digits would be in the persona)")
        return 1
    a.out.write_text(text)
    print(f"PERSONA={a.name} WRITTEN containers={len(p['containers'])} nas={len(p['nas'])} "
          f"frames={p['frames']} imeisv_tac={'yes' if 'imeisv' in p else 'no'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
