#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# CI hook (P3 R0): the parts of P3's exit CI can see (tools/p3_exit.py --stub-only): the stub's
# ksim-p3 rows due by the milestone reached, in aio and split and in C6-C8, every mutant
# killed, the captures and the canary clean, no NULL AS run. Runs after hook 91. Full mode only.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[[ "${1:-quick}" == full ]] || { echo "P3_EXIT_STUB=SKIP (full mode only)"; exit 77; }
exec "$ROOT/tools/p3_exit.sh" --stub-only
