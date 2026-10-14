#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# CI hook (plan M14): the fuzz smoke. Every libFuzzer target of the fuzz
# preset runs 60 s from its seeds (tools/fuzz.sh); any crash, sanitizer
# report or leak fails, and fuzz_mustfail has to crash. Full mode only.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MODE="${1:-quick}"
JOBS="${2:-8}"
[[ "$MODE" == full ]] || { echo "FUZZ=SKIP (full mode only)"; exit 77; }
"$ROOT/tools/fuzz.sh" 60 "$JOBS"
