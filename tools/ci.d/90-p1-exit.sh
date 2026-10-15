#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# CI hook (P1 N16): the parts of P1's exit CI can see (tools/p1_exit.py
# --stub-only): every stub row accounted for, every mutant killed, every EF
# read by pySim, the component run's captures and canary clean. Runs last, on
# what hooks 55, 65 and 68 left. Full mode only.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[[ "${1:-quick}" == full ]] || { echo "P1_EXIT_STUB=SKIP (full mode only)"; exit 77; }
exec "$ROOT/tools/p1_exit.sh" --stub-only
