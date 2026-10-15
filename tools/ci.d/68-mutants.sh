#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# CI hook (P1 N16): every mutant of tests/mutants.tsv against the gate that
# scores its row, on the stub (tools/mutants.sh): MUTANTS_KILLED=n/n. Full mode
# only (about eight minutes).
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[[ "${1:-quick}" == full ]] || { echo "MUTANTS=SKIP (full mode only)"; exit 77; }
exec "$ROOT/tools/mutants.sh"
