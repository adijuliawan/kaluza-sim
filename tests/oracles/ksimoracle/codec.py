# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Our C++ codecs, driven through `ksim-codec batch` (plan M10).

One long-lived process; one request line and one answer line per call. This is
the only place the harness touches our C++: everything else in ksimoracle is
independent of it.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


@dataclass
class Answer:
    ok: bool
    hex: str = ""        # re-encoded (dec) or encoded (enc) octets
    jer: str = ""        # minified JER
    stage: str = ""      # where it failed
    error: str = ""

    @property
    def data(self) -> bytes:
        return bytes.fromhex(self.hex)


def default_binary() -> Path:
    env = os.environ.get("KSIM_CODEC")
    if env:
        return Path(env)
    return ROOT / "build" / "dev" / "apps" / "ksim-codec" / "ksim-codec"


class Codec:
    def __init__(self, binary: Path | None = None):
        self.binary = binary or default_binary()
        if not self.binary.is_file():
            raise FileNotFoundError(f"{self.binary}: build the ksim-codec target (cmake --build build/dev)")
        self.crashes = 0
        self._start()

    def _start(self) -> None:
        self.p = subprocess.Popen([str(self.binary), "batch"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  text=True, bufsize=1)

    def _ask(self, op: str, proto: str, type_name: str, payload: str) -> Answer:
        if "\n" in payload or "\t" in payload:
            raise ValueError("payload must be one line without tabs")
        assert self.p.stdin and self.p.stdout
        self.p.stdin.write(f"{op}\t{proto}\t{type_name}\t{payload}\n")
        self.p.stdin.flush()
        line = self.p.stdout.readline().rstrip("\n")
        if not line:                         # it crashed: record it, start a fresh one
            rc = self.p.wait(timeout=30)
            self.crashes += 1
            self._start()
            return Answer(False, stage="crash", error=f"ksim-codec exited with {rc} on {op} {type_name}")
        f = line.split("\t", 2)
        if f[0] == "OK":
            return Answer(True, hex=f[1], jer=f[2] if len(f) > 2 else "")
        return Answer(False, stage=f[1] if len(f) > 1 else "", error=f[2] if len(f) > 2 else "")

    def dec(self, proto: str, type_name: str, data: bytes) -> Answer:
        return self._ask("dec", proto, type_name, data.hex())

    def enc(self, proto: str, type_name: str, jer: str) -> Answer:
        return self._ask("enc", proto, type_name, jer)

    def close(self) -> None:
        if self.p.stdin:
            self.p.stdin.close()
        self.p.wait(timeout=30)

    def __enter__(self) -> "Codec":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
