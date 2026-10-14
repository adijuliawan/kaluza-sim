#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Guard (plan M15): the compliance registers under docs/compliance are what
tools/registers.py generates from the requirements, the typed rows,
docs/compliance/built.tsv and the committed spec data, byte for byte.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "registers.py"


def main() -> int:
    arg = "--self-test" if "--self-test" in sys.argv[1:] else "--check"
    return subprocess.run([sys.executable, "-I", str(TOOL), arg]).returncode


if __name__ == "__main__":
    sys.exit(main())
