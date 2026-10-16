#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# CI hook (P2 Q8): ksim-bench from the release build against its regression bounds
# (tests/bench/bounds.tsv). Its numbers go to build/bench/last.txt.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="$ROOT/build/release/apps/ksim-bench/ksim-bench"
[[ -x "$BIN" ]] || { echo "BENCH=SKIP (no release build of ksim-bench)"; exit 77; }
mkdir -p "$ROOT/build/bench"
"$BIN" --ms 300 --check "$ROOT/tests/bench/bounds.tsv" | tee "$ROOT/build/bench/last.txt" | grep -E '^BENCH(=|\.pdcp)'
rc=${PIPESTATUS[0]}
exit "$rc"
