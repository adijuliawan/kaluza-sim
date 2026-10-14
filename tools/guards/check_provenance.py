#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Guard (plan M14, ADRs 0004 and 0005): no hand-written file of ours shares
code with a tree we must not copy from (tools/provenance.py scan). A missing or
stale fingerprint database fails; the must-fail self-test runs the scan on a
synthetic tree, so no third-party text is ever part of the fixtures.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "provenance.py"


def main() -> int:
    command = "self-test" if "--self-test" in sys.argv[1:] else "scan"
    return subprocess.run([sys.executable, "-I", str(TOOL), command]).returncode


if __name__ == "__main__":
    sys.exit(main())
