#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""The run capture check (P1 N8; verification.md section 2): every frame of a
run's ngap.pcapng, f1ap.pcapng, e1ap.pcapng and uu.pcapng through two decoders
that are not ours, (P1 N10) every frame of gtpu.pcapng (N3 and F1-U as
IPv4/UDP 2152) through tshark, and (P1 N14) every frame of sim.pcapng (the card
traces, GSMTAP-SIM) through tshark when a trace was on.

  tshark   the whole capture on stdin (AppArmor keeps it out of ~/Development);
           a frame fails on a malformed mark or an expert item of severity
           warning or error. PDCP integrity is not verified there: a run never
           hands its keys to a tool, so Wireshark would compute every MAC-I
           with no key and flag it (our PDCP entities verify every MAC-I, and a
           failure is an event the gates read).
  pycrate  each PDU on its own: NGAP, F1AP and E1AP (APER) and RRC (UPER, by the
           channel the frame names) from our extracted Rel-19 modules, NAS
           with pycrate_mobile's 5GS parser.

Run it with the oracle venv:

    .venv/bin/python -I tools/pcap_check.py <run dir>

It prints PCAP_FRAMES, PCAP_MALFORMED (tshark), PYCRATE_FAILED and
PCAP_CHECK=PASS|FAIL, with one PCAP_BAD line per failed frame. Two kinds of
gtpu.pcapng frame tshark cannot read are judged again: an F1-U frame on its GTP-U
and NR-U headers alone (P2 Q12), and an Echo Request or Response, such as the Open5GS
rig UPF's with a Recovery Time Stamp, on TS 29.281 by ksimoracle.gtpu (P2 Q13,
counted as PCAP_GTPU_ECHO_REJUDGED). A capture
without frames is a failure: a run that captured nothing proves nothing.

A run with an interop peer (P2 Q4, <run>/peer/ from gates/run.sh) has no NGAP
or E1AP capture of ours: the peer's CU-CP holds those links. The peer's own
captures (peer/*.pcap) go through tshark alone and are reported apart, as
PEER_PCAP_FRAMES and PEER_PCAP_MALFORMED: they are the peer's encodings, not a
verdict on ours.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests" / "oracles"))
from ksimoracle import asn, gtpu, pcap, tshark  # noqa: E402

CAPTURES = ("ngap.pcapng", "f1ap.pcapng", "e1ap.pcapng", "uu.pcapng")
RAW_CAPTURES = ("gtpu.pcapng",)   # raw IPv4 frames: tshark only (pycrate has no GTP-U)
SIM_CAPTURE = "sim.pcapng"        # GSMTAP-SIM (N14): tshark's gsm_sim; frames only while a trace was on
PEER_HELD = ("ngap.pcapng", "e1ap.pcapng")   # with a peer CU-CP: its links, its captures
RRC = {
    "nr-rrc.bcch.bch": "BCCH_BCH_Message",
    "nr-rrc.bcch.dl.sch": "BCCH_DL_SCH_Message",
    "nr-rrc.pcch": "PCCH_Message",
    "nr-rrc.dl.ccch": "DL_CCCH_Message",
    "nr-rrc.ul.ccch": "UL_CCCH_Message",
    "nr-rrc.dl.dcch": "DL_DCCH_Message",
    "nr-rrc.ul.dcch": "UL_DCCH_Message",
}


def pycrate_check(name: str, pdu: bytes) -> str:
    """'' when pycrate decodes the PDU and re-encodes it to the same octets, else why not."""
    try:
        if name in ("ngap", "f1ap", "e1ap"):
            o, enc = asn.top(name)
            asn.decode(o, pdu, enc)
            again = o.to_aper()
        elif name in RRC:
            o = asn.obj("rrc", "NR_RRC_Definitions", RRC[name])
            o.from_uper(pdu)
            again = o.to_uper()
        elif name == "nas-5gs":
            from pycrate_mobile.NAS5G import parse_NAS5G
            msg, err = parse_NAS5G(pdu)
            if err:
                return f"pycrate NAS5G error {err}"
            again = msg.to_bytes()
        else:
            return f"no pycrate decoder for {name}"
    except Exception as e:  # noqa: BLE001 - any decoder exception is the verdict
        return f"{type(e).__name__}: {str(e)[:120]}"
    return "" if again == pdu else "pycrate re-encodes it differently"


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    run = Path(sys.argv[1])
    frames = malformed = pyfail = rejudged = 0
    bad: list[str] = []
    peer = run / "peer"
    ours = tuple(c for c in CAPTURES if not (peer.is_dir() and c in PEER_HELD))
    for cap in ours:
        f = run / cap
        if not f.is_file():
            bad.append(f"{cap}: missing")
            continue
        data = f.read_bytes()
        records = pcap.read_pcapng_exported(data)
        if not records:
            bad.append(f"{cap}: no frames")
            continue
        frames += len(records)
        for i, p in enumerate(tshark.decode(data, prefs=["pdcp-nr.verify_integrity:FALSE"]), start=1):
            errs = tshark.errors(p)
            if errs:
                malformed += 1
                bad.append(f"{cap} frame {i}: tshark: {'; '.join(errs)[:160]}")
        for n, name, pdu, comment in records:
            why = pycrate_check(name, pdu)
            if why:
                pyfail += 1
                bad.append(f"{cap} frame {n} ({name}, {comment}): {why}")
    for cap in RAW_CAPTURES:
        f = run / cap
        if not f.is_file():
            bad.append(f"{cap}: missing")
            continue
        raw = f.read_bytes()
        packets = tshark.decode(raw)
        if not packets:
            bad.append(f"{cap}: no frames")
            continue
        frames += len(packets)
        # P2 Q12: an F1-U frame (an NR RAN container, nrup) carries a ciphered PDCP PDU,
        # which tshark's T-PDU heuristic may take for something else: at 1 in 65536 a
        # ciphertext has 0x86dd at offset 12 and reads as an Ethernet frame. Such a frame
        # is judged again with the T-PDU not dissected, on its GTP-U and NR-U headers.
        # P2 Q13: an Echo Request or Response tshark cannot read (a Recovery Time Stamp, IE
        # 231, from the Open5GS rig's UPF) is judged on TS 29.281 by ksimoracle.gtpu instead.
        plain = None
        frames_raw = None
        for i, p in enumerate(packets, start=1):
            errs = tshark.errors(p)
            f1u = any(lf.name == "gtp.ext_hdr" and "NR RAN container" in lf.show for lf in p.leaves)
            if errs and f1u:
                if plain is None:
                    plain = tshark.decode(raw, prefs=["gtp.dissect_tpdu_as:none"])
                errs = tshark.errors(plain[i - 1]) if i - 1 < len(plain) else errs
            elif errs:
                if frames_raw is None:
                    frames_raw = pcap.read_pcapng_packets(raw)
                g = gtpu.gtpu_of_ipv4(frames_raw[i - 1][1]) if i - 1 < len(frames_raw) else None
                if g is not None and gtpu.message_type(g) in gtpu.ALLOWED:
                    why = gtpu.path_message_problem(g)
                    errs = [f"TS 29.281: {why}"] if why else []
                    if not why:
                        rejudged += 1
            if errs:
                malformed += 1
                bad.append(f"{cap} frame {i}: tshark: {'; '.join(errs)[:160]}")
    print(f"PCAP_GTPU_ECHO_REJUDGED={rejudged}")
    sim_frames = 0
    f = run / SIM_CAPTURE
    if f.is_file():
        packets = tshark.decode(f.read_bytes())
        sim_frames = len(packets)
        frames += sim_frames
        for i, p in enumerate(packets, start=1):
            errs = tshark.errors(p)
            if errs:
                malformed += 1
                bad.append(f"{SIM_CAPTURE} frame {i}: tshark: {'; '.join(errs)[:160]}")
    print(f"PCAP_SIM_FRAMES={sim_frames}")
    if peer.is_dir():
        peer_frames = peer_malformed = 0
        for f in sorted(peer.glob("*.pcap")):
            packets = tshark.decode(f.read_bytes(), prefs=["pdcp-nr.verify_integrity:FALSE"])
            peer_frames += len(packets)
            for i, p in enumerate(packets, start=1):
                errs = tshark.errors(p)
                if errs:
                    peer_malformed += 1
                    print(f"PEER_PCAP_BAD {f.name} frame {i}: tshark: {'; '.join(errs)[:160]}")
        print(f"PEER_PCAP_FRAMES={peer_frames}\nPEER_PCAP_MALFORMED={peer_malformed}")
    for b in bad:
        print(f"PCAP_BAD {b}")
    ok = not bad and frames > 0
    print(f"PCAP_FRAMES={frames}\nPCAP_MALFORMED={malformed}\nPYCRATE_FAILED={pyfail}\n"
          f"PCAP_CHECK={'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
