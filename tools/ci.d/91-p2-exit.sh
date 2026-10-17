#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# CI hook (P2 Q16): the parts of P2's exit CI can see (tools/p2_exit.py --stub-only): every
# stub row of split mode and of C3 accounted for, the E1 rows of C4 and C5, the 100-UE rows,
# the PC/SC path, every mutant killed, the captures and the canary clean, no NULL AS run.
# Runs after hook 90, on what hooks 57, 58, 65 and 68 left. Full mode only.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[[ "${1:-quick}" == full ]] || { echo "P2_EXIT_STUB=SKIP (full mode only)"; exit 77; }
exec "$ROOT/tools/p2_exit.sh" --stub-only
