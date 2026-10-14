# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""pycrate as an ASN.1 oracle, compiled from OUR extracted Rel-19 modules.

pycrate's bundled 3GPP modules are older releases, so it compiles
spec/asn1/<proto>/*.asn itself. The compiled module is cached by the sha256 of
the inputs and the pycrate version, in ~/.cache/kaluza-sim/pycrate-asn/.

The extraction is shared with asn1c, so a spec-extraction error would be
shared too. tshark, which carries Wireshark's own ASN.1, is the independent
check for that.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.util
import os
import subprocess
import sys
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CACHE = Path(os.environ.get("KSIM_PYCRATE_CACHE", Path.home() / ".cache" / "kaluza-sim" / "pycrate-asn"))

# Top-level PDU per protocol, with its encoding.
PDU = {
    "ngap": ("NGAP_PDU_Descriptions", "NGAP_PDU", "aper"),
    "f1ap": ("F1AP_PDU_Descriptions", "F1AP_PDU", "aper"),
    "e1ap": ("E1AP_PDU_Descriptions", "E1AP_PDU", "aper"),
    "xnap": ("XnAP_PDU_Descriptions", "XnAP_PDU", "aper"),
}


def stamp(proto: str) -> str:
    h = hashlib.sha256(importlib.metadata.version("pycrate").encode())
    for f in sorted((ROOT / "spec" / "asn1" / proto).glob("*.asn")):
        h.update(f.name.encode())
        h.update(f.read_bytes())
    return h.hexdigest()[:16]


@lru_cache(maxsize=None)
def module(proto: str):
    """The compiled pycrate module for a protocol (compiling once per stamp)."""
    CACHE.mkdir(parents=True, exist_ok=True)
    out = CACHE / f"{proto}_{stamp(proto)}.py"
    if not out.is_file():
        compiler = Path(sys.executable).parent / "pycrate_asn1compile.py"
        base = CACHE / f"{proto}_{stamp(proto)}_tmp"           # the compiler appends .py
        r = subprocess.run([sys.executable, "-I", str(compiler), "-i", f"{ROOT / 'spec' / 'asn1' / proto}/",
                            "-o", str(base)], capture_output=True, text=True)
        produced = base.with_suffix(".py")
        if r.returncode != 0 or not produced.is_file():
            raise RuntimeError(f"pycrate compile of {proto} failed: {r.stderr[-600:]}")
        produced.rename(out)
    spec = importlib.util.spec_from_file_location(f"ksim_pycrate_{proto}", out)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def obj(proto: str, module_name: str, type_name: str):
    """A pycrate ASN.1 object by module and type name, e.g. ('rrc', 'NR_RRC_Definitions', 'UL_CCCH_Message')."""
    return getattr(getattr(module(proto), module_name), type_name)


def top(proto: str):
    m, t, enc = PDU[proto]
    return obj(proto, m, t), enc


def decode(o, data: bytes, enc: str):
    if enc == "aper":
        o.from_aper(data)
    else:
        o.from_uper(data)
    return o.get_val()


def encode(o, value, enc: str) -> bytes:
    o.set_val(value)
    return o.to_aper() if enc == "aper" else o.to_uper()


def roundtrip(o, data: bytes, enc: str) -> tuple[bool, str]:
    """Decode then re-encode: (identical, error)."""
    try:
        decode(o, data, enc)
        again = o.to_aper() if enc == "aper" else o.to_uper()
    except Exception as e:  # noqa: BLE001 - any decoder complaint is the verdict
        return False, f"{type(e).__name__}: {e}"[:300]
    return again == data, "" if again == data else f"re-encoded {again.hex()} != {data.hex()}"
