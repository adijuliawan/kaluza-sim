#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# Run every fuzz target of the fuzz preset (plan M14) for SECONDS each, in
# parallel, from seed corpora (tools/fuzz_seeds.py), and fail on any crash,
# sanitizer report, leak or timeout. fuzz_mustfail must crash: a harness that
# finds nothing there is broken. The CI smoke runs 60 s; the milestone run 600 s.
#
#   tools/fuzz.sh [SECONDS] [JOBS]
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SECONDS_EACH="${1:-60}"
JOBS="${2:-8}"
BIN="$ROOT/build/fuzz/tests/fuzz"
WORK="$ROOT/build/fuzz-run"
[[ -x "$BIN/fuzz_codecs" ]] || { echo "FUZZ=SKIP (no fuzz preset build: cmake --build --preset fuzz)"; exit 77; }
rm -rf "$WORK"
mkdir -p "$WORK/seeds" "$WORK/corpus" "$WORK/artifacts" "$WORK/logs"
"$ROOT/.venv/bin/python" -I "$ROOT/tools/fuzz_seeds.py" "$WORK/seeds" | tail -n 1 || exit 1
targets=()
for t in "$BIN"/fuzz_*; do
    [[ -x "$t" && "$(basename "$t")" != fuzz_mustfail ]] && targets+=("$(basename "$t")")
done
run_one() {  # run_one TARGET SECONDS
    local t="$1" s="$2"
    mkdir -p "$WORK/corpus/$t"
    "$BIN/$t" -max_total_time="$s" -rss_limit_mb=2048 -timeout=10 -print_final_stats=1 -print_funcs=0 \
        -artifact_prefix="$WORK/artifacts/$t-" "$WORK/corpus/$t" "$WORK/seeds/$t" > "$WORK/logs/$t.log" 2>&1
}
export -f run_one
export BIN WORK
printf '%s\n' "${targets[@]}" | xargs -P "$JOBS" -I{} bash -c 'run_one "$1" "$2" || echo "FUZZ_CRASH $1"' _ {} "$SECONDS_EACH" \
    > "$WORK/crashes.txt"
fail=0
for t in "${targets[@]}"; do
    execs=$(grep -oE "stat::number_of_executed_units: *[0-9]+" "$WORK/logs/$t.log" | grep -oE "[0-9]+$" || echo 0)
    cov=$(grep -oE "cov: [0-9]+" "$WORK/logs/$t.log" | tail -n 1 | grep -oE "[0-9]+" || echo 0)
    if grep -q "FUZZ_CRASH $t$" "$WORK/crashes.txt"; then
        echo "FUZZ_TARGET $t=CRASH execs=$execs cov=$cov log=build/fuzz-run/logs/$t.log"
        grep -m 3 -E "ERROR: |SUMMARY: |deadly signal" "$WORK/logs/$t.log" | sed 's/^/  /'
        fail=1
    else
        echo "FUZZ_TARGET $t=CLEAN execs=$execs cov=$cov"
    fi
done
# the must-fail target: its seed starts with "KSIM", so it has to crash at once
if run_one fuzz_mustfail 10; then
    echo "FUZZ_MUSTFAIL=MISSED (fuzz_mustfail did not crash: the harness is broken)"
    fail=1
else
    echo "FUZZ_MUSTFAIL=CAUGHT"
fi
echo "FUZZ=$([[ $fail == 0 ]] && echo PASS || echo FAIL) seconds=$SECONDS_EACH targets=${#targets[@]}"
exit $fail
