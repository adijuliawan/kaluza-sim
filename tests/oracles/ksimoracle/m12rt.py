# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""The M12 check: GTP-U, the PDU Session Container (PSC), NR-U, APDUs and FCP.

    ours     ksim-codec decodes the octets and re-encodes them byte for byte;
    second   GTP-U and PSC: pycrate (TS29281_GTPU) reads them and re-encodes them
             byte for byte, with the same header, extension headers and IEs;
             APDU and FCP: pySim (out of process, see pysim_helper.py) reads
             the same command, parameters and response, or FCP data objects;
             NR-U: OCUDU's vectors are the second source (no pycrate reader);
    tshark   finds nothing wrong and its fields hold our values: gtp (and the
             PSC it dissects in an extension header), nrup in an NR RAN
             Container, gsm_sim in a GSMTAP SIM frame.

Generated values are written here from the specs (TS 29.281, 38.415, 38.425,
ETSI TS 102 221, TS 31.102), apart from GTP-U's min values, which are pycrate's
own defaults. OCUDU vectors whose own test expects its unpacker to refuse them
must be refused by ours too, unless they differ only after the last field
(padding or a Future Extension, which TS 38.415/38.425 5.5.1 let a receiver
take): LENIENT.
"""

from __future__ import annotations

import json
import os
import struct
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from . import pcap, tshark
from .codec import Codec

ROOT = Path(__file__).resolve().parents[3]
PYSIM_DIR = Path(os.environ.get("KSIM_PYSIM_DIR", "/home/amadeus/Development/ran/usim"))


@dataclass
class M12Result:
    status: str = "FAIL"
    ours: bool = False
    second: bool | None = None       # pycrate or pySim agrees (None: not consulted)
    tshark_clean: bool = False
    fields: int = 0                  # field values compared with tshark and the second reader
    notes: list[str] = field(default_factory=list)


# ---- pySim, out of process ----------------------------------------------------------------

class PySim:
    def __init__(self) -> None:
        py = PYSIM_DIR / ".venv-pysim" / "bin" / "python"
        env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME")}
        env["PYTHONPATH"] = str(PYSIM_DIR / "pysim-src")
        self.proc = subprocess.Popen([str(py), "-s", str(ROOT / "tests" / "oracles" / "pysim_helper.py")],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                     text=True, cwd=str(PYSIM_DIR), env=env)

    @staticmethod
    def available() -> bool:
        return (PYSIM_DIR / ".venv-pysim" / "bin" / "python").is_file() and (PYSIM_DIR / "pysim-src").is_dir()

    def ask(self, req: dict) -> dict:
        assert self.proc.stdin and self.proc.stdout
        self.proc.stdin.write(json.dumps(req) + "\n")
        self.proc.stdin.flush()
        return json.loads(self.proc.stdout.readline())

    def __enter__(self):
        return self

    def __exit__(self, *_):
        if self.proc.stdin:
            self.proc.stdin.close()
        self.proc.wait(timeout=30)


# ---- framing for tshark ----------------------------------------------------------------

def gsmtap_sim(payload: bytes) -> bytes:
    return struct.pack(">BBBBHbbIBBBB", 2, 4, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0) + payload


def gpdu_with(ext_type: int, frame: bytes, tpdu: bytes = b"") -> bytes:
    """A G-PDU carrying `frame` in one extension header (TS 29.281 5.2.1)."""
    assert (len(frame) + 2) % 4 == 0
    body = struct.pack(">HBB", 0, 0, ext_type) + bytes([(len(frame) + 2) // 4]) + frame + b"\x00" + tpdu
    return struct.pack(">BBHI", 0x34, 0xFF, len(body), 1) + body


def tpdu(cmd: bytes) -> bytes:
    """A command APDU as T=0 carries it (P3 is Lc, else Le, else '00'): what
    tshark and pySim read."""
    if len(cmd) <= 5:
        return cmd if len(cmd) == 5 else cmd + b"\x00"
    lc = cmd[4]
    return cmd[:5 + lc]


def _int(show: str) -> int:
    s = show.strip()
    if s in ("True", "Set"):
        return 1
    if s in ("False", "Not set"):
        return 0
    return int(s, 16) if s.lower().startswith("0x") else int(s.split()[0])


def _leaves(pkt, name: str) -> list:
    return [lf for lf in pkt.leaves if lf.name == name]


# ---- GTP-U ---------------------------------------------------------------------------------

def _pycrate_gtpu():
    import pycrate_mobile.TS29281_GTPU as G  # noqa: N812
    return G


REL17_IES = (230, 231)   # GTP-U Tunnel Status Information, Recovery Time Stamp: newer than both oracles


def check_gtpu(codec: Codec, data: bytes, generated: bool) -> M12Result:
    r = M12Result()
    a = codec._ask("dec", "gtpu", "-", data.hex())
    ours = None
    if not a.ok:
        r.notes.append(f"ours {a.stage}: {a.error[:160]}")
    else:
        r.ours = a.data == data
        ours = json.loads(a.jer)
        if not r.ours:
            r.notes.append(f"our re-encode differs: {a.hex[:60]}")
    lag: list[str] = []
    payload_at = len(data) - len(bytes.fromhex(ours["payload"])) if ours else 0
    rel17 = [ie for ie in (ours or {}).get("ies", []) if ie["type"] in REL17_IES]
    # pycrate: the header, the extension chain and the IEs as it decodes them
    if ours is not None and len(ours["ext"]) > 1:
        lag.append("pycrate not consulted: it misreads chained extension headers (KS-UP-T2)")
    elif ours is not None:
        try:
            G = _pycrate_gtpu()
            m, err = G.parse_GTPU(data)
            if err:
                raise ValueError(f"parse_GTPU error {err}")
            again = m.to_bytes()
            h = m["GTPUHdr"]
            got = {"type": h["Type"].get_val(), "teid": h["TEID"].get_val()}
            want = {"type": ours["type"], "teid": ours["teid"]}
            if ours["octet1"] & 0x02:
                got["sequence"], want["sequence"] = h["GTPUHdrOpt"]["SeqNum"].get_val(), ours["sequence"]
            if ours["octet1"] & 0x04:
                got["ext"] = [h["GTPUHdrOpt"]["NextExt"].get_val()] if len(h["GTPUHdrExtList"]._content) else [0]
                want["ext"] = [x["type"] for x in ours["ext"]] or [0]
            if "ies" in ours:
                got["ies"] = [e["Type"].get_val() for e in m._content[1:] if not e.get_trans()]
                want["ies"] = [ie["type"] for ie in ours["ies"]]
            if rel17:
                # pycrate keeps the first IE it does not know and stops after it: what it
                # read and wrote back must be ours up to there
                cut = next(i for i, ie in enumerate(ours["ies"]) if ie["type"] in REL17_IES)
                want["ies"] = want["ies"][:cut + 1]
                lag.append("pycrate 0.8.1 stops at a Rel-17 IE (230/231)")
                r.second = data.startswith(again) and got == want
            else:
                r.second = again == data and got == want
            r.fields += len(want)
            if not r.second:
                r.notes.append(f"pycrate reads {got}, ours {want}" + ("" if again == data else "; its re-encode differs"))
        except Exception as e:  # noqa: BLE001
            r.second = False
            r.notes.append(f"pycrate: {type(e).__name__}: {str(e)[:120]}")
    # tshark
    pkt = tshark.decode(pcap.raw_udp([(pcap.GTPU_PORT, data)]))[0]
    errs = tshark.errors(pkt)
    if ours is not None and ours["type"] == 253 and not _leaves(pkt, "gtp.message"):
        lag.append("tshark 4.6.4 does not dissect Tunnel Status (253)")
        errs, pkt = [], None
    if rel17 and errs and set(errs) <= {"Unknown extension header"}:
        lag.append("tshark 4.6.4 reads a Rel-17 IE (230/231) as an unknown extension header")
        errs = []
    r.tshark_clean = not errs
    for e in sorted(set(errs)):
        r.notes.append(("generated-content: " if generated else "tshark: ") + e)
    ts_ok = True
    if ours is not None and pkt is not None:
        checks = [("gtp.message", ours["type"]), ("gtp.teid", ours["teid"])]
        if ours["octet1"] & 0x02:
            checks.append(("gtp.seq_number", ours["sequence"]))
        for name, want in checks:
            lv = _leaves(pkt, name)
            if not lv or _int(lv[0].show) != want:
                ts_ok = False
                r.notes.append(f"tshark {name} {lv[0].show if lv else 'absent'}, ours {want}")
            r.fields += 1
        if ours["octet1"] & 0x04:
            # gtp.ext_hdr.next: the header's Next Extension Header Type, then each header's
            nexts = [_int(lf.show) for lf in _leaves(pkt, "gtp.ext_hdr.next")]
            want = [x["type"] for x in ours["ext"]] + [0]
            if nexts[: len(want)] != want and not errs:
                ts_ok = False
                r.notes.append(f"tshark next extension types {nexts}, ours {want}")
            r.fields += 1
        for x in ours["ext"]:
            if x["type"] in (0x84, 0x85):
                ok, n, why = frame_fields(pkt, "nru" if x["type"] == 0x84 else "psc", codec,
                                          bytes.fromhex(x["content"]))
                r.fields += n
                if not ok:
                    ts_ok = False
                    r.notes.append(why)
    r.notes += lag
    good = r.ours and ts_ok and r.second is not False
    if not good:
        r.status = "FAIL"
    elif errs:
        r.status = "GENERATED_CONTENT" if generated else "FAIL"
    else:
        r.status = "ORACLE_LAG" if lag else "PASS"
    return r


# ---- PSC and NR-U --------------------------------------------------------------------------

# Our field name -> tshark field (octet-aligned: compared by raw octets).
PSC_FIELDS = {
    "DL Sending Time Stamp": "gtp.ext_hdr.pdu_ses_cont.dl_send_time_stamp",
    "DL QFI Sequence Number": "gtp.ext_hdr.pdu_ses_cont.dl_qfi_sn",
    "DL MBS QFI Sequence Number": "gtp.ext_hdr.pdu_ses_cont.dl_mbs_qfi_sn",
    "DL Sending Time Stamp Repeated": "gtp.ext_hdr.pdu_ses_cont.dl_send_time_stamp_repeat",
    "DL Received Time Stamp": "gtp.ext_hdr.pdu_ses_cont.dl_recv_time_stamp",
    "UL Sending Time Stamp": "gtp.ext_hdr.pdu_ses_cont.ul_send_time_stamp",
    "DL Delay Result": "gtp.ext_hdr.pdu_ses_cont.dl_delay_result",
    "UL Delay Result": "gtp.ext_hdr.pdu_ses_cont.ul_delay_result",
    "UL QFI Sequence Number": "gtp.ext_hdr.pdu_ses_cont.ul_qfi_sn",
    "N3/N9 Delay Result": "gtp.ext_hdr.pdu_ses_cont.n3_n9_delay_result",
}
NRU_FIELDS = {
    "NR-U Sequence Number": "nrup.seq_num",
    "DL discard NR PDCP PDU SN": "nrup.dl_disc_nr_pdcp_pdu_sn",
    "DL report NR PDCP PDU SN": "nrup.dl_report_nr_pdcp_pdu_sn",
    "Desired buffer size for the data radio bearer": "nrup.desrd_buff_sz_data_radio_bearer",
    "Desired Data Rate": "nrup.desrd_data_rate",
    "Highest successfully delivered NR PDCP Sequence Number": "nrup.high_success_delivered_nr_pdcp_sn",
    "Highest transmitted NR PDCP Sequence Number": "nrup.high_tx_nr_pdcp_sn",
    "Cause Value": "nrup.cause_val",
    "Successfully delivered retransmitted NR PDCP Sequence Number": "nrup.high_success_delivered_retx_nr_pdcp_sn",
    "Retransmitted NR PDCP Sequence Number": "nrup.high_retx_nr_pdcp_sn",
}
# Block lists: the count field, then the fields of each block with their sizes.
NRU_BLOCKS = {
    "DL discard Number of blocks": ("nrup.dl_disc_num_blks",
                                    [("nrup.dl_disc_nr_pdcp_pdu_sn_start", 3), ("nrup.disc_blk_sz", 1)]),
    "Number of lost NR-U Sequence Number ranges reported": (
        "nrup.num_lost_nru_seq_num", [("nrup.start_num_lost_nru_seq_num", 3), ("nrup.end_num_lost_nru_seq_num", 3)]),
}
# (tshark field, flag octet, shift, mask) of the flag bits tshark shows.
PSC_FLAGS = {
    0: [("gtp.ext_hdr.pdu_ses_con.pdu_type", 0, 4, 15), ("gtp.ext_hdr.pdu_ses_con.qmp", 0, 3, 1),
        ("gtp.ext_hdr.pdu_ses_con.snp", 0, 2, 1), ("gtp.ext_hdr.pdu_ses_con.msnp", 0, 1, 1),
        ("gtp.ext_hdr.pdu_ses_cont.ppp", 1, 7, 1), ("gtp.ext_hdr.pdu_ses_cont.rqi", 1, 6, 1),
        ("gtp.ext_hdr.pdu_ses_con.qos_flow_id", 1, 0, 63), ("gtp.ext_hdr.pdu_ses_cont.ppi", 2, 5, 7)],
    1: [("gtp.ext_hdr.pdu_ses_con.pdu_type", 0, 4, 15), ("gtp.ext_hdr.pdu_ses_con.qmp", 0, 3, 1),
        ("gtp.ext_hdr.pdu_ses_con.dl_delay_ind", 0, 2, 1), ("gtp.ext_hdr.pdu_ses_con.ul_delay_ind", 0, 1, 1),
        ("gtp.ext_hdr.pdu_ses_con.snp", 0, 0, 1), ("gtp.ext_hdr.pdu_ses_con.n3_n9_delay_ind", 1, 7, 1),
        ("gtp.ext_hdr.pdu_ses_con.new_ie_flag", 1, 6, 1), ("gtp.ext_hdr.pdu_ses_con.qos_flow_id", 1, 0, 63)]
       + [(f"gtp.ext_hdr.pdu_ses_cont.new_ie_flag_{b}", 2, b, 1) for b in range(8)],
}
NRU_FLAGS = {
    0: [("nrup.pdu_type", 0, 4, 15), ("nrup.dl_disc_blks", 0, 2, 1), ("nrup.dl_flush", 0, 1, 1),
        ("nrup.report_polling", 0, 0, 1), ("nrup.request_out_of_seq_report", 1, 4, 1),
        ("nrup.report_delivered", 1, 3, 1), ("nrup.user_data_existence_flag", 1, 2, 1),
        ("nrup.ass_inf_rep_poll_flag", 1, 1, 1), ("nrup.retransmission_flag", 1, 0, 1)],
    1: [("nrup.pdu_type", 0, 4, 15), ("nrup.high_tx_nr_pdcp_sn_ind", 0, 3, 1),
        ("nrup.high_delivered_nr_pdcp_sn_ind", 0, 2, 1), ("nrup.final_frame_ind", 0, 1, 1),
        ("nrup.lost_pkt_rpt", 0, 0, 1), ("nrup.delivered_nr_pdcp_sn_range_ind", 1, 4, 1),
        ("nrup.data_rate_ind", 1, 3, 1), ("nrup.high_retx_nr_pdcp_sn_ind", 1, 2, 1),
        ("nrup.high_delivered_retx_nr_pdcp_sn_ind", 1, 1, 1), ("nrup.cause_rpt", 1, 0, 1)],
}


def frame_fields(pkt, proto: str, codec: Codec | None, frame: bytes, ours: dict | None = None) -> tuple[bool, int, str]:
    """Our reading of a PSC or NR-U frame against tshark's fields in `pkt`."""
    if ours is None:
        a = codec._ask("dec", proto, "-", frame.hex())
        if not a.ok:
            return False, 0, f"ours {a.stage}: {a.error[:120]}"
        ours = json.loads(a.jer)
    flags = ours["flags"]
    n = 0
    for name, octet, shift, mask in (PSC_FLAGS if proto == "psc" else NRU_FLAGS).get(ours["pdu_type"], []):
        if octet >= len(flags):
            continue
        lv = _leaves(pkt, name)
        if not lv:
            continue   # a flag tshark does not show (its version lags the release)
        if _int(lv[0].show) != (flags[octet] >> shift) & mask:
            return False, n, f"{proto}: tshark {name} {lv[0].show}, ours {(flags[octet] >> shift) & mask}"
        n += 1
    table = PSC_FIELDS if proto == "psc" else NRU_FIELDS
    for f in ours["fields"]:
        if f["name"] in table:
            lv = _leaves(pkt, table[f["name"]])
            if not lv:
                continue
            if lv[0].value.lower() != f["hex"]:
                return False, n, f"{proto}: tshark {table[f['name']]} {lv[0].value}, ours {f['hex']}"
            n += 1
        elif proto == "nru" and f["name"] in NRU_BLOCKS:
            count_field, parts = NRU_BLOCKS[f["name"]]
            octets = bytes.fromhex(f["hex"])
            lv = _leaves(pkt, count_field)
            if lv and _int(lv[0].show) != octets[0]:
                return False, n, f"nru: tshark {count_field} {lv[0].show}, ours {octets[0]}"
            pos, k = 1, 0
            while pos < len(octets):
                for tname, size in parts:
                    got = _leaves(pkt, tname)
                    if k < len(got) and got[k].value.lower() != octets[pos:pos + size].hex():
                        return False, n, f"nru: tshark {tname}[{k}] {got[k].value}, ours {octets[pos:pos + size].hex()}"
                    n += k < len(got)
                    pos += size
                k += 1
    return True, n, ""


def check_frame(codec: Codec, proto: str, data: bytes, generated: bool, refused_by_producer: bool) -> M12Result:
    r = M12Result()
    a = codec._ask("dec", proto, "-", data.hex())
    if refused_by_producer:
        if not a.ok:
            r.ours = True
            r.status = "NEGATIVE_AGREED"
            r.notes.append(f"refused, as its producer's test expects: {a.error[:100]}")
        else:
            ours = json.loads(a.jer)
            if len(data) % 4 != 2 or len(bytes.fromhex(ours["tail"])) > 3:
                r.ours = True
                r.status = "LENIENT"
                r.notes.append("accepted: it differs only after the last field (padding or a Future Extension, "
                               "which TS 38.415/38.425 5.5.1 let a receiver take); its producer refuses it")
            else:
                r.notes.append("accepted, though its producer's test expects refusal")
        return r
    if not a.ok:
        r.notes.append(f"ours {a.stage}: {a.error[:160]}")
        return r
    r.ours = a.data == data
    ours = json.loads(a.jer)
    if not r.ours:
        r.notes.append(f"our re-encode differs: {a.hex[:60]}")
    if (len(data) + 2) % 4 != 0:
        r.notes.append("not 4n-2 octets: it cannot ride in an extension header, so tshark is not consulted")
        r.status = "PASS" if r.ours else "FAIL"
        return r
    wrapped = gpdu_with(0x84 if proto == "nru" else 0x85, data)
    pkt = tshark.decode(pcap.raw_udp([(pcap.GTPU_PORT, wrapped)]))[0]
    errs = tshark.errors(pkt)
    r.tshark_clean = not errs
    for e in sorted(set(errs)):
        r.notes.append(("generated-content: " if generated else "tshark: ") + e)
    ok, n, why = frame_fields(pkt, proto, codec, data, ours)
    r.fields += n
    if not ok:
        r.notes.append(why)
    if proto == "psc":
        try:
            G = _pycrate_gtpu()
            m, err = G.parse_GTPU(wrapped)
            if err:
                raise ValueError(f"parse_GTPU error {err}")
            r.second = m.to_bytes() == wrapped
            cont = m["GTPUHdr"]["GTPUHdrExtList"][0]["PDUSessionContainer"]
            got_type = cont["Type"].get_val()
            r.fields += 1
            if not r.second or got_type != ours["pdu_type"]:
                r.second = False
                r.notes.append(f"pycrate reads PDU type {got_type} or re-encodes differently")
        except Exception as e:  # noqa: BLE001
            r.notes.append(f"pycrate: {type(e).__name__}: {str(e)[:120]}")
            r.second = None
    good = r.ours and ok and r.second is not False
    r.status = "FAIL" if not good else "PASS" if not errs else ("GENERATED_CONTENT" if generated else "FAIL")
    if good and r.status == "PASS" and proto == "psc" and r.second is None:
        r.status = "ORACLE_LAG"
    return r


# ---- APDU and FCP ------------------------------------------------------------------------

PYSIM_CLASSES = {
    "UiccSelect": "SELECT FILE", "UiccStatus": "STATUS", "ReadBinary": "READ BINARY",
    "UpdateBinary": "UPDATE BINARY", "ReadRecord": "READ RECORD", "UpdateRecord": "UPDATE RECORD",
    "SearchRecord": "SEARCH RECORD", "VerifyPin": "VERIFY PIN", "ChangePin": "CHANGE PIN",
    "DisablePin": "DISABLE PIN", "EnablePin": "ENABLE PIN", "UnblockPin": "UNBLOCK PIN",
    "UsimAuthenticateEven": "AUTHENTICATE", "UsimGetIdentity": "GET IDENTITY", "GetResponse": "GET RESPONSE",
    "ManageChannel": "MANAGE CHANNEL",
}
SELECT_P1 = {0x00: "df_ef_or_mf_by_file_id", 0x01: "child_df_of_current_df", 0x03: "parent_df_of_current_df",
             0x04: "df_name", 0x08: "path_from_mf", 0x09: "path_from_current_df"}


def _pysim_apdu_agrees(ours: dict, ps: dict) -> tuple[bool, int, str]:
    """pySim's reading of the command (cmd_to_dict, rsp_to_dict) against ours."""
    want = PYSIM_CLASSES.get(ps["class"])
    if want != ours["command"]:
        return False, 0, f"pySim reads {ps['class']}, ours {ours['command']!r}"
    c, rsp = ps["cmd"], ps.get("rsp") or {}
    checks: list[tuple[str, object, object]] = []
    name = ours["command"]
    if name == "SELECT FILE":
        checks.append(("p1", c.get("p1"), SELECT_P1.get(ours["p1"])))
        checks.append(("return", (c.get("p2") or {}).get("return"), {"fcp": "fcp", "none": "no_data"}.get(ours["return"])))
    elif name in ("READ BINARY", "UPDATE BINARY"):
        if "sfi" in ours:
            checks.append(("offset", c.get("offset"), ours["offset"]))
        else:
            # pySim computes ((P1 & 0x7F) << 8) & P2 where 11.1.3.2 means '|' (KS-UICC-T2):
            # its reading is checked against that formula, tshark's bin_offset against ours
            checks.append(("offset (pySim's formula)", c.get("offset"), ((ours["p1"] & 0x7F) << 8) & ours["p2"]))
        if "sfi" in ours:
            checks.append(("sfi", c.get("sfi"), ours["sfi"]))
    elif name in ("READ RECORD", "UPDATE RECORD"):
        checks.append(("record", c.get("record_number"), ours["record"]))
        checks.append(("file", c.get("file"), "sfi" if ours["sfi"] else "currently_selected_ef"))
        if ours["sfi"]:
            checks.append(("sfi", c.get("sfi"), ours["sfi"]))
    elif name in ("VERIFY PIN", "CHANGE PIN", "DISABLE PIN", "ENABLE PIN", "UNBLOCK PIN"):
        checks.append(("key", (c.get("p2") or {}).get("reference_data_nr"), ours["key_reference"] & 0x1F))
        checks.append(("scope", (c.get("p2") or {}).get("scope"),
                       "specific_df_adf" if ours["key_reference"] & 0x80 else "global_mf"))
    elif name == "AUTHENTICATE":
        p2 = c.get("p2") or {}
        checks.append(("context", p2.get("authentication_context"), {0: "gsm", 1: "umts"}.get(ours["context"])))
        checks.append(("scope", p2.get("scope"), "df_adf_specific" if ours["specific"] else "mf"))
        body = c.get("body") or {}
        checks.append(("rand", body.get("rand"), ours.get("rand")))
        if ours.get("autn"):
            checks.append(("autn", body.get("autn"), ours.get("autn")))
        rb = (rsp.get("body") or {}).get("body") if isinstance(rsp.get("body"), dict) else None
        if ours.get("auth") == "success" and rb is not None:
            checks.append(("res", rb.get("res"), ours.get("res")))
            checks.append(("ck_len", len(rb.get("ck") or "") // 2, ours.get("ck_len")))
            checks.append(("ik_len", len(rb.get("ik") or "") // 2, ours.get("ik_len")))
        elif ours.get("auth") == "sync_failure" and rb is not None:
            checks.append(("auts", rb.get("auts"), ours.get("auts")))
    elif name == "MANAGE CHANNEL":
        checks.append(("operation", c.get("p1"), {"open": "open_channel", "close": "close_channel"}.get(ours["operation"])))
    elif name == "GET IDENTITY":
        checks.append(("context", (c.get("p2") or {}).get("identity_context"), {1: "suci", 2: "suci_5g_nswo"}.get(ours["identity_context"])))
    if "p3" in c:   # T=0's P3: Lc, else Le (256 as '00'), else 0
        p3 = len(ours["data"]) // 2 if ours.get("data") else (ours.get("le", 0) % 256 if "le" in ours else 0)
        if "data_len" in ours:
            p3 = ours["data_len"]
        checks.append(("p3", c.get("p3"), p3))
    sw = rsp.get("sw")
    if sw is not None:
        checks.append(("sw", sw, ours.get("sw")))
    if isinstance(rsp.get("body"), str) and "rsp" in ours:
        checks.append(("response data", rsp["body"], ours["rsp"]))
    for what, got, want in checks:
        if got != want:
            return False, len(checks), f"pySim {what} {got!r}, ours {want!r}"
    return True, len(checks), ""


def _tshark_apdu_agrees(pkt, ours: dict) -> tuple[bool, int, str]:
    checks = [("gsm_sim.apdu.ins", ours["ins"]), ("gsm_sim.apdu.p1", ours["p1"]), ("gsm_sim.apdu.p2", ours["p2"])]
    if "sw" in ours:
        checks.append(("gsm_sim.apdu.sw", int(ours["sw"], 16)))
    if ours["command"] == "SELECT FILE" and ours["p1"] == 0x00 and len(ours["data"]) == 4:
        checks.append(("gsm_sim.file_id", int(ours["data"], 16)))
    if ours["command"] in ("READ RECORD", "UPDATE RECORD"):
        checks += [("gsm_sim.record_nr", ours["record"]), ("gsm_sim.record_file", ours["sfi"]),
                   ("gsm_sim.record_mode", ours["mode"])]
    if ours["command"] == "AUTHENTICATE":
        checks += [("gsm_sim.auth_context", ours["context"]), ("gsm_sim.auth_reference", ours["specific"])]
    if "le" in ours and ours.get("case") == 2 and ours["le"] != 256:
        # (tshark 4.6.4 reads a P3 of '00' and the next octet as an extended Le: KS-UICC-T2)
        checks.append(("gsm_sim.apdu.le", ours["le"]))
    if ours.get("data") and ours["command"] not in ("SELECT FILE",):
        checks.append(("gsm_sim.apdu.lc", len(ours["data"]) // 2))
    if ours["command"] in ("READ BINARY", "UPDATE BINARY") and "sfi" not in ours:
        checks.append(("gsm_sim.bin_offset", ours["offset"]))
    n = 0
    for name, want in checks:
        lv = _leaves(pkt, name)
        if not lv:
            continue
        if _int(lv[0].show) != want:
            return False, n, f"tshark {name} {lv[0].show}, ours {want}"
        n += 1
    for name, key in (("gsm_sim.auth_rand", "rand"), ("gsm_sim.auth_autn", "autn"), ("gsm_sim.auth_res", "res"),
                      ("gsm_sim.auth_auts", "auts")):
        lv = _leaves(pkt, name)
        if lv and ours.get(key):
            if lv[0].value.lower() != ours[key]:
                return False, n, f"tshark {name} differs from ours"
            n += 1
    return True, n, ""


def check_apdu(codec: Codec, pysim: PySim | None, cmd: bytes, rsp: bytes) -> M12Result:
    r = M12Result()
    a = codec._ask("dec", "apdu", "-", cmd.hex() + "/" + rsp.hex())
    if not a.ok:
        r.notes.append(f"ours {a.stage}: {a.error[:160]}")
        return r
    r.ours = a.hex == cmd.hex() + "/" + rsp.hex()
    if not r.ours:
        r.notes.append("our re-encode differs")
    ours = json.loads(a.jer)
    t = tpdu(cmd)
    if pysim is not None:
        ps = pysim.ask({"kind": "apdu", "cmd": t.hex(), "rsp": rsp.hex()})
        if not ps.get("ok"):
            r.second = False
            r.notes.append(f"pySim: {ps.get('error', '')[:160]}")
        else:
            r.second, n, why = _pysim_apdu_agrees(ours, ps)
            r.fields += n
            if not r.second:
                r.notes.append(why)
    pkt = tshark.decode(pcap.raw_udp([(pcap.GSMTAP_PORT, gsmtap_sim(t + rsp))]))[0]
    errs = tshark.errors(pkt)
    r.tshark_clean = not errs
    for e in sorted(set(errs)):
        r.notes.append("tshark: " + e)
    ts_ok, n, why = _tshark_apdu_agrees(pkt, ours)
    r.fields += n
    if not ts_ok:
        r.notes.append(why)
    r.status = "PASS" if r.ours and ts_ok and not errs and r.second is not False else "FAIL"
    return r


LIFE_CYCLE = {0x00: "no_information", 0x01: "creation", 0x03: "initialization", 0x05: "operational_activated",
              0x07: "operational_activated", 0x04: "operational_deactivated", 0x06: "operational_deactivated"}
FCP_KEYS = {"file_descriptor": 0x82, "file_identifier": 0x83, "df_name": 0x84, "proprietary_information": 0xA5,
            "life_cycle_status_integer": 0x8A, "security_attrib_referenced": 0x8B, "security_attrib_compact": 0x8C,
            "security_attrib_expanded": 0xAB, "pin_status_template_do": 0xC6, "file_size": 0x80,
            "total_file_size": 0x81, "short_file_identifier": 0x88}
STRUCTURE = {"none": "no_info_given", "transparent": "transparent", "linear_fixed": "linear_fixed",
             "cyclic": "cyclic", "ber_tlv": "ber_tlv"}


def _pysim_fcp_agrees(ours: dict, ps: dict) -> tuple[bool, int, str]:
    items = ps["fcp"]["fcp_template"]
    keys = [next(iter(d)) for d in items]
    got: dict = {}
    for d in items:
        got.update(d)
    checks = [("tags", [FCP_KEYS.get(k, -1) for k in keys], ours["tags"])]
    fd = got.get("file_descriptor", {})
    fdb = fd.get("file_descriptor_byte", {})
    checks.append(("file_type", fdb.get("file_type"), ours.get("file_type")))
    if ours.get("file_type") != "df":
        checks.append(("structure", fdb.get("structure"), STRUCTURE.get(ours.get("structure"))))
    checks.append(("shareable", fdb.get("shareable"), ours.get("shareable")))
    if "record_length" in ours:
        checks.append(("record_len", fd.get("record_len"), ours["record_length"]))
        checks.append(("num_of_rec", fd.get("num_of_rec"), ours["records"]))
    if "file_id" in ours:
        checks.append(("file_id", got.get("file_identifier"), f"{ours['file_id']:04x}"))
    if "df_name" in ours:
        checks.append(("df_name", got.get("df_name"), ours["df_name"]))
    if "file_size" in ours:
        checks.append(("file_size", got.get("file_size"), ours["file_size"]))
    if "total_file_size" in ours:
        checks.append(("total_file_size", got.get("total_file_size"), ours["total_file_size"]))
    if "life_cycle" in ours and ours["life_cycle"] in LIFE_CYCLE:
        checks.append(("life_cycle", got.get("life_cycle_status_integer"), LIFE_CYCLE[ours["life_cycle"]]))
    if "pin_key_references" in ours:
        refs = [x["key_reference"] for x in got.get("pin_status_template_do", []) if "key_reference" in x]
        checks.append(("pin_key_references", refs, ours["pin_key_references"]))
    for what, g, w in checks:
        if g != w:
            return False, len(checks), f"pySim {what} {g!r}, ours {w!r}"
    return True, len(checks), ""


def check_fcp(codec: Codec, pysim: PySim | None, data: bytes) -> M12Result:
    r = M12Result()
    a = codec._ask("dec", "fcp", "-", data.hex())
    if not a.ok:
        r.notes.append(f"ours {a.stage}: {a.error[:160]}")
        return r
    r.ours = a.data == data
    ours = json.loads(a.jer)
    if pysim is not None:
        ps = pysim.ask({"kind": "fcp", "hex": data.hex()})
        if not ps.get("ok"):
            r.second = False
            r.notes.append(f"pySim: {ps.get('error', '')[:160]}")
        else:
            r.second, n, why = _pysim_fcp_agrees(ours, ps)
            r.fields += n
            if not r.second:
                r.notes.append(why)
    # tshark: the FCP as the response to a SELECT returning it
    cmd = bytes.fromhex("00a4000402") + struct.pack(">H", ours.get("file_id", 0x3F00))
    pkt = tshark.decode(pcap.raw_udp([(pcap.GSMTAP_PORT, gsmtap_sim(cmd + data + b"\x90\x00"))]))[0]
    errs = tshark.errors(pkt)
    r.tshark_clean = not errs
    for e in sorted(set(errs)):
        r.notes.append("tshark: " + e)
    r.status = "PASS" if r.ours and not errs and r.second is not False else "FAIL"
    return r


# ---- generated values ------------------------------------------------------------------

def _gtpu(octet1: int, mtype: int, teid: int, opt: bytes | None, ext: list[tuple[int, bytes]], payload: bytes) -> bytes:
    """A GTP-U PDU written from TS 29.281 5.1 and 5.2.1."""
    body = b""
    if opt is not None:
        nxt = ext[0][0] if ext else 0
        body += opt[:3] + bytes([nxt])
        for i, (_, content) in enumerate(ext):
            assert (len(content) + 2) % 4 == 0
            body += bytes([(len(content) + 2) // 4]) + content + bytes([ext[i + 1][0] if i + 1 < len(ext) else 0])
    body += payload
    return struct.pack(">BBHI", octet1, mtype, len(body), teid) + body


def _ie_tlv(t: int, v: bytes) -> bytes:
    return bytes([t]) + struct.pack(">H", len(v)) + v


FRAME_TYPES = {"psc": {"DL PDU SESSION INFORMATION": 0, "UL PDU SESSION INFORMATION": 1},
               "nru": {"DL USER DATA": 0, "DL DATA DELIVERY STATUS": 1}}
RTS = _ie_tlv(231, bytes.fromhex("ead0b100"))                 # 8.8: seconds since 1900
PRIV = _ie_tlv(255, bytes.fromhex("0001aabb"))                # 8.6: extension identifier 1
PSC_DL_SMALL = bytes([0x00, 0x09])                            # 38.415: DL, QFI 9
PSC_UL_SMALL = bytes([0x10, 0x09])


def _pad(frame: bytes) -> bytes:
    return frame + bytes((4 - (len(frame) + 2) % 4) % 4)


def gen_frame(proto: str, pdu_type: int, mode: str) -> bytes:
    """PSC (TS 38.415 5.5.2) and NR-U (TS 38.425 5.5.2) frames, every optional
    field on (max) or none (min)."""
    if mode == "min":
        base = {("psc", 0): b"\x00\x09", ("psc", 1): b"\x10\x09", ("nru", 0): b"\x00\x00\x00\x00\x2a",
                ("nru", 1): b"\x10\x00\x00\x01\x00\x00"}[(proto, pdu_type)]
        return _pad(base)
    if (proto, pdu_type) == ("psc", 0):
        f = bytes([0x0E, 0xC9, 0xA3])                          # QMP SNP MSNP; PPP RQI QFI 9; PPI 5, BSSI, TTNBI
        f += bytes.fromhex("e8d4a51000000001") + bytes.fromhex("000102") + bytes.fromhex("00000003")
        f += bytes.fromhex("000400") + bytes.fromhex("0005")
        return _pad(f)
    if (proto, pdu_type) == ("psc", 1):
        f = bytes([0x1F, 0xC9, 0x1F])                          # QMP, delays, SNP; N3/N9, new IE flag, QFI 9; flags 0-4
        f += bytes.fromhex("e8d4a51000000001") + bytes.fromhex("e8d4a51000000002") + bytes.fromhex("e8d4a51000000003")
        f += bytes.fromhex("00000011") + bytes.fromhex("00000012") + bytes.fromhex("000013") + bytes.fromhex("00000014")
        f += bytes([0x01]) + bytes.fromhex("2616") + bytes.fromhex("0bb8") + bytes.fromhex("000186a0") + bytes.fromhex("00030d40")
        return _pad(f)
    if (proto, pdu_type) == ("nru", 0):
        f = bytes([0x07, 0xFF]) + bytes.fromhex("00002a")      # all flags; NR-U SN 42
        f += bytes.fromhex("000010")                            # DL discard NR PDCP PDU SN
        f += bytes([2]) + bytes.fromhex("00002005") + bytes.fromhex("00003003")   # two discard blocks
        f += bytes.fromhex("000011")                            # DL report NR PDCP PDU SN
        f += bytes.fromhex("000400") + bytes.fromhex("0005")    # BSSize, TTNB
        f += bytes([0x07])                                      # new IE flags 0-2
        f += bytes.fromhex("000012")                            # DL retransmission NR PDCP PDU SN
        f += bytes([1]) + bytes.fromhex("00004002")             # one retransmission block
        f += bytes([0x01])                                      # DL Remaining Time based Polling Indicator
        return _pad(f)
    f = bytes([0x1F, 0x7F]) + bytes.fromhex("00010000")        # every indicator; desired buffer size
    f += bytes.fromhex("000f4240")                              # desired data rate
    f += bytes([2]) + bytes.fromhex("000005000007") + bytes.fromhex("000009000009")   # lost NR-U SN ranges
    f += bytes.fromhex("000020") + bytes.fromhex("000021") + bytes([0x01])   # highest delivered, transmitted; cause
    f += bytes.fromhex("000022") + bytes.fromhex("000023")     # delivered retransmitted, retransmitted
    f += bytes([1]) + bytes.fromhex("000030000031")            # delivered out of sequence range
    f += bytes.fromhex("00002b") + bytes.fromhex("00000064")   # polling frame SN, feedback delay
    return _pad(f)


def gen_gtpu(name: str, mode: str) -> bytes:
    if mode == "min":
        G = _pycrate_gtpu()
        cls = {"Echo Request": "GTPUEchoReq", "Echo Response": "GTPUEchoResp", "Error Indication": "GTPUErrorInd",
               "Supported Extension Headers Notification": "GTPUSuppExtHdrNotif", "Tunnel Status": "GTPUTunnelStatus",
               "End Marker": "GTPUEndMarker", "G-PDU": "GPDU"}[name]
        return getattr(G, cls)().to_bytes()
    seq = struct.pack(">HB", 0x1234, 0)
    if name == "Echo Request":
        return _gtpu(0x32, 1, 0, seq, [], RTS + PRIV)
    if name == "Echo Response":
        return _gtpu(0x32, 2, 0, seq, [], bytes([14, 0]) + RTS + PRIV)
    if name == "Error Indication":
        ies = bytes([16]) + bytes.fromhex("11223344") + _ie_tlv(133, bytes([10, 0, 0, 1])) + RTS + PRIV
        return _gtpu(0x36, 26, 0, seq, [(0x40, struct.pack(">H", 2152))], ies)
    if name == "Supported Extension Headers Notification":
        return _gtpu(0x32, 31, 0, seq, [], bytes([141, 3, 0x84, 0x85, 0xC0]))
    if name == "Tunnel Status":
        return _gtpu(0x30, 253, 0x0A0B0C0D, None, [], _ie_tlv(230, bytes([0x01])) + PRIV)
    if name == "End Marker":
        return _gtpu(0x34, 254, 0x0A0B0C0D, struct.pack(">HB", 0, 0), [(0x85, PSC_DL_SMALL)], PRIV)
    ip = bytes.fromhex("4500001c0001000040110000") + bytes([10, 45, 0, 2, 10, 45, 0, 1]) + bytes.fromhex("0035d3c80008")
    return _gtpu(0x37, 255, 0x0A0B0C0D, struct.pack(">HB", 0x1234, 0x56),
                 [(0x85, gen_frame("psc", 0, "max")), (0x03, bytes.fromhex("000102000000"))], ip)


SFI7_READ = 0x87


def gen_apdus() -> list[tuple[str, str, bytes, bytes]]:
    """(v1 command, label, command APDU, response APDU), written from TS 102 221
    clause 11 and TS 31.102 clause 7. PINs, keys and identities are synthetic
    (the SUCI is the null scheme of a test-range IMSI)."""
    mf = gen_fcps()["MF"]
    ef = gen_fcps()["EF transparent"]
    adf = gen_fcps()["ADF USIM"]
    rnd, autn = bytes(range(0x10, 0x20)), bytes(range(0x20, 0x30))
    ok = b"\x90\x00"
    return [
        ("SELECT FILE", "MF by file id, FCP", bytes.fromhex("00a40004023f0000"), mf + ok),
        ("SELECT FILE", "EF by path from MF, FCP", bytes.fromhex("00a40804047fff6f0700"), ef + ok),
        ("SELECT FILE", "ADF by DF name, FCP", bytes.fromhex("00a4040410a0000000871002ff86ffff89ffffffff00"), adf + ok),
        ("SELECT FILE", "MF, no data", bytes.fromhex("00a4000c023f00"), ok),
        ("STATUS", "FCP of the current application", bytes.fromhex("80f2000000"), adf + ok),
        ("STATUS", "no data", bytes.fromhex("80f2010c"), ok),
        ("READ BINARY", "offset 0", bytes.fromhex("00b0000009"), bytes(range(9)) + ok),
        ("READ BINARY", "SFI 7", bytes([0x00, 0xB0, SFI7_READ, 0x02, 0x04]), bytes(range(4)) + ok),
        ("UPDATE BINARY", "offset 258", bytes.fromhex("00d6010203aabbcc"), ok),
        ("READ RECORD", "absolute record 1", bytes.fromhex("00b201041a"), bytes(26) + ok),
        ("READ RECORD", "next record, SFI 7", bytes.fromhex("00b2003a1a"), bytes(26) + ok),
        ("UPDATE RECORD", "absolute record 2", bytes.fromhex("00dc020405" "0102030405"), ok),
        ("SEARCH RECORD", "simple forward search", bytes.fromhex("00a2010403aabbcc00"), bytes([1]) + ok),
        ("VERIFY PIN", "PIN1", bytes.fromhex("0020000108" + "31323334ffffffff"), ok),
        ("VERIFY PIN", "status of PIN1", bytes.fromhex("00200001"), bytes.fromhex("63c3")),
        ("CHANGE PIN", "PIN1", bytes.fromhex("0024000110" + "31323334ffffffff" + "35363738ffffffff"), ok),
        ("DISABLE PIN", "PIN1", bytes.fromhex("0026000108" + "31323334ffffffff"), ok),
        ("ENABLE PIN", "PIN1", bytes.fromhex("0028000108" + "31323334ffffffff"), ok),
        ("UNBLOCK PIN", "PIN1 with PUK1", bytes.fromhex("002c000110" + "3132333435363738" + "31323334ffffffff"), ok),
        ("AUTHENTICATE", "5G context, success", bytes.fromhex("0088008122") + bytes([16]) + rnd + bytes([16]) + autn + b"\x00",
         bytes.fromhex("db08") + bytes(range(0x40, 0x48)) + bytes([16]) + bytes(range(0x50, 0x60)) + bytes([16])
         + bytes(range(0x60, 0x70)) + ok),
        ("AUTHENTICATE", "5G context, synchronisation failure",
         bytes.fromhex("0088008122") + bytes([16]) + rnd + bytes([16]) + autn + b"\x00",
         bytes.fromhex("dc0e") + bytes(range(0x70, 0x7E)) + ok),
        ("GET IDENTITY", "SUCI context", bytes.fromhex("8078000100"),
         bytes.fromhex("a10e0100f110f0ff00000003000000") + ok),
        ("GET RESPONSE", "26 octets", bytes.fromhex("00c000001a"), bytes(26) + ok),
        ("MANAGE CHANNEL", "open", bytes.fromhex("0070000001"), bytes([1]) + ok),
        ("MANAGE CHANNEL", "close channel 1", bytes.fromhex("00708001"), ok),
    ]


def gen_fcps() -> dict[str, bytes]:
    """FCP templates written from TS 102 221 11.1.1.3 and 11.1.1.4."""
    def tlv(tag: int, v: bytes) -> bytes:
        assert len(v) < 0x80
        return bytes([tag, len(v)]) + v

    def fcp(*objs: bytes) -> bytes:
        return tlv(0x62, b"".join(objs))

    pin = tlv(0xC6, tlv(0x90, b"\x60") + tlv(0x83, b"\x01") + tlv(0x83, b"\x81") + tlv(0x83, b"\x0a"))
    arr = tlv(0x8B, bytes.fromhex("2f0601"))
    return {
        "MF": fcp(tlv(0x82, b"\x78\x21"), tlv(0x83, b"\x3f\x00"), tlv(0xA5, tlv(0x80, b"\x71") + tlv(0x87, b"\x01")),
                  tlv(0x8A, b"\x05"), arr, pin, tlv(0x81, b"\x00\x40\x00")),
        "ADF USIM": fcp(tlv(0x82, b"\x78\x21"), tlv(0x83, b"\x7f\xff"),
                        tlv(0x84, bytes.fromhex("a0000000871002ff86ffff89ffffffff")), tlv(0x8A, b"\x05"), arr, pin),
        "DF": fcp(tlv(0x82, b"\x78\x21"), tlv(0x83, b"\x7f\x10"), tlv(0x8A, b"\x05"), arr, pin),
        "EF transparent": fcp(tlv(0x82, b"\x41\x21"), tlv(0x83, b"\x6f\x07"), tlv(0x8A, b"\x05"), arr,
                              tlv(0x80, b"\x00\x09"), tlv(0x88, b"\x38")),
        "EF linear fixed": fcp(tlv(0x82, b"\x42\x21\x00\x1a\x04"), tlv(0x83, b"\x6f\x40"), tlv(0x8A, b"\x05"), arr,
                               tlv(0x80, b"\x00\x68"), tlv(0x88, b"")),
        "EF cyclic": fcp(tlv(0x82, b"\x46\x21\x00\x0d\x05"), tlv(0x83, b"\x6f\x31"), tlv(0x8A, b"\x05"), arr,
                         tlv(0x80, b"\x00\x41")),
        "EF BER-TLV": fcp(tlv(0x82, b"\x79\x21"), tlv(0x83, b"\x6f\xa1"),
                          tlv(0xA5, tlv(0x83, b"\x00\x00\x10\x00") + tlv(0x84, b"\x80")), tlv(0x8A, b"\x05"), arr,
                          tlv(0x80, b"\x00\x20")),
    }


def selftest(codec: Codec, pysim: PySim | None) -> list[tuple[str, bool]]:
    """Must-fail cases: each mutation has to be caught. (name, caught)."""
    out = []
    em = bytearray(gen_gtpu("Echo Request", "max"))
    em[3] += 1                                   # the Length one octet too long
    out.append(("gtpu: a Length one octet too long", check_gtpu(codec, bytes(em), True).status == "FAIL"))
    gp = bytearray(gen_gtpu("G-PDU", "max"))
    gp[12] = 0                                   # the first extension header's length 0
    out.append(("gtpu: an extension header of length 0", check_gtpu(codec, bytes(gp), True).status == "FAIL"))
    good = check_gtpu(codec, gen_gtpu("G-PDU", "max"), True)
    out.append(("gtpu: G-PDU fields compared at all (header, extension chain, PSC)", good.fields >= 10))
    for proto, t in (("psc", 0), ("psc", 1), ("nru", 0), ("nru", 1)):
        frame = gen_frame(proto, t, "max")
        ours = json.loads(codec._ask("dec", proto, "-", frame.hex()).jer)
        pkt = tshark.decode(pcap.raw_udp([(pcap.GTPU_PORT, gpdu_with(0x84 if proto == "nru" else 0x85, frame))]))[0]
        ok, n, _ = frame_fields(pkt, proto, None, frame, ours)
        out.append((f"{proto} type {t}: fields compared with tshark at all", ok and n >= 5))
        bad = json.loads(json.dumps(ours))
        bad["fields"][0]["hex"] = ("%02x" % (int(bad["fields"][0]["hex"][:2], 16) ^ 1)) + bad["fields"][0]["hex"][2:]
        out.append((f"{proto} type {t}: a field value differing from tshark's", not frame_fields(pkt, proto, None, frame, bad)[0]))
    out.append(("nru: a whole 4n-2 frame its producer refuses, accepted", check_frame(
        codec, "nru", gen_frame("nru", 0, "min"), False, True).status == "FAIL"))
    apdus = {label: (c, r) for _, label, c, r in gen_apdus()}
    c, r = apdus["absolute record 1"]
    ours = json.loads(codec._ask("dec", "apdu", "-", c.hex() + "/" + r.hex()).jer)
    pkt = tshark.decode(pcap.raw_udp([(pcap.GSMTAP_PORT, gsmtap_sim(tpdu(c) + r))]))[0]
    out.append(("apdu: tshark fields compared at all", _tshark_apdu_agrees(pkt, ours)[1] >= 5))
    out.append(("apdu: a record number differing from tshark's",
                not _tshark_apdu_agrees(pkt, {**ours, "record": ours["record"] + 1})[0]))
    if pysim is not None:
        ps = pysim.ask({"kind": "apdu", "cmd": tpdu(c).hex(), "rsp": r.hex()})
        out.append(("apdu: a record number differing from pySim's",
                    not _pysim_apdu_agrees({**ours, "record": ours["record"] + 1}, ps)[0]))
        c, r = apdus["5G context, success"]
        ours = json.loads(codec._ask("dec", "apdu", "-", c.hex() + "/" + r.hex()).jer)
        ps = pysim.ask({"kind": "apdu", "cmd": tpdu(c).hex(), "rsp": r.hex()})
        out.append(("apdu: AUTHENTICATE compared with pySim at all", _pysim_apdu_agrees(ours, ps)[1] >= 6))
        out.append(("apdu: a RES differing from pySim's", not _pysim_apdu_agrees({**ours, "res": "00" + ours["res"][2:]}, ps)[0]))
        f = gen_fcps()["EF linear fixed"]
        ours = json.loads(codec._ask("dec", "fcp", "-", f.hex()).jer)
        ps = pysim.ask({"kind": "fcp", "hex": f.hex()})
        out.append(("fcp: a record count differing from pySim's", not _pysim_fcp_agrees({**ours, "records": 5}, ps)[0]))
        out.append(("fcp: fields compared with pySim at all", _pysim_fcp_agrees(ours, ps)[1] >= 8))
    return out
