#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# CI hook (P1 N14; verification.md, the card row): pySim-shell reads every EF
# of our soft card over pcscd's vpcd reader 1, pySim-trace and tshark decode
# its GSMTAP-SIM, and a pySim fsdump imports back into a valid image
# (tests/oracles/pysim_shell.py). Full mode only; SKIP without pcscd, vpcd or
# the pySim venv (KSIM_PYSIM_DIR).
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[[ "${1:-quick}" == full ]] || { echo "PYSIM=SKIP (full mode only)"; exit 77; }
command -v tshark >/dev/null || { echo "PYSIM=SKIP (no tshark)"; exit 77; }
# A pcscd that came up without vpcd's readers is waited out (P2 Q7); the oracle
# then SKIPs as before if the reader is still missing.
"$ROOT/tools/vpcd_ready.sh" "Virtual PCD 00 01" || true
exec python3 -I "$ROOT/tests/oracles/pysim_shell.py" --keep "$ROOT/build/pysim/last"
