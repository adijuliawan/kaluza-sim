# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""pySim as an out-of-process oracle for APDUs and FCP templates (plan M12).

Run by ksimoracle/m12rt.py with pySim's own interpreter and PYTHONPATH (pySim is
GPL and is used like tshark: a separate program whose output we read; nothing
of it is copied). One JSON request per line on stdin, one answer per line:

    {"kind": "apdu", "cmd": "<C-TPDU hex>", "rsp": "<data and SW hex>"}
        -> {"ok": true, "class": "<pySim command class>", "cmd": {...}, "rsp": {...}}
    {"kind": "fcp", "hex": "<62 L ...>"} -> {"ok": true, "fcp": {...}}

Bytes in the answers are hex strings.
"""

from __future__ import annotations

import json
import sys


def plain(v):
    if isinstance(v, (bytes, bytearray)):
        return v.hex()
    if isinstance(v, dict):
        return {str(k): plain(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [plain(x) for x in v]
    if isinstance(v, (str, int, float, bool)) or v is None:
        return v
    return str(v)


def main() -> int:
    from pySim.apdu import Apdu
    from pySim.apdu.ts_102_221 import ApduCommands as UiccCommands
    from pySim.apdu.ts_31_102 import ApduCommands as UsimCommands
    from pySim.ts_102_221 import FcpTemplate

    commands = UiccCommands + UsimCommands
    for line in sys.stdin:
        req = json.loads(line)
        try:
            if req["kind"] == "apdu":
                cmd = commands.parse_cmd_apdu(Apdu(bytes.fromhex(req["cmd"]), bytes.fromhex(req["rsp"])))
                out = {"ok": True, "class": type(cmd).__name__, "cmd": plain(cmd.cmd_to_dict()),
                       "rsp": plain(cmd.rsp_to_dict())}
            else:
                f = FcpTemplate()
                f.from_tlv(bytes.fromhex(req["hex"]))
                out = {"ok": True, "fcp": plain(f.to_dict())}
        except Exception as e:  # noqa: BLE001 - every failure is an answer
            out = {"ok": False, "error": f"{type(e).__name__}: {e}"[:300]}
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
