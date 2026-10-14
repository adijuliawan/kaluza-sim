#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# CI hook (plan M14): clang-tidy (.clang-tidy, tests/.clang-tidy) on every
# hand-written translation unit of src, apps and tests, with the clang
# compile commands of the fuzz preset; no finding may remain. Its must-fail
# fixture (tools/clang_tidy/mustfail.cpp, a use after move) must be reported.
# Full mode only (the fuzz preset is built there).
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MODE="${1:-quick}"
JOBS="${2:-8}"
[[ "$MODE" == full ]] || { echo "CLANG_TIDY=SKIP (full mode only)"; exit 77; }
DB="$ROOT/build/fuzz/compile_commands.json"
[[ -f "$DB" ]] || { echo "CLANG_TIDY=SKIP (no $DB)"; exit 77; }
fixture=$(clang-tidy --quiet --config-file="$ROOT/.clang-tidy" "$ROOT/tools/clang_tidy/mustfail.cpp" -- -std=c++20 2>&1)
if grep -q "bugprone-use-after-move" <<< "$fixture"; then
    echo "CLANG_TIDY_MUSTFAIL=CAUGHT"
else
    echo "CLANG_TIDY_MUSTFAIL=MISSED (the fixture's use after move was not reported)"; exit 1
fi
mapfile -t files < <(python3 - "$DB" "$ROOT" <<'PY'
import json, sys
db, root = sys.argv[1], sys.argv[2].rstrip("/") + "/"
keep = ("src/", "apps/", "tests/unit/", "tests/fuzz/", "tests/canary/", "tests/corestub/", "tests/procedure/")
for f in sorted({e["file"] for e in json.load(open(db))}):
    if f.startswith(root) and f.endswith(".cpp") and f[len(root):].startswith(keep):
        print(f)
PY
)
out="$ROOT/build/clang-tidy.log"
run-clang-tidy -quiet -p "$ROOT/build/fuzz" -j "$JOBS" "${files[@]}" > "$out" 2>&1
findings=$(grep -cE "(warning|error): .*\[[a-z]" "$out" || true)
if (( findings > 0 )); then
    grep -E "(warning|error): .*\[[a-z]" "$out" | sed "s|$ROOT/||" | sort -u | head -n 40
    echo "CLANG_TIDY=FAIL files=${#files[@]} findings=$findings log=build/clang-tidy.log"; exit 1
fi
echo "CLANG_TIDY=PASS files=${#files[@]} findings=0"
