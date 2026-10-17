#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The gate-level mutant run (P1 N16; verification.md): for each mutant of
# tests/mutants.tsv, ksim from the mutants preset with KSIM_MUTANT set runs the
# gate that scores the mutant's row against the stub (from the dev preset, so
# the network side stays right). The mutant is killed when its row FAILs.
# Other rows that fail with it are listed, not counted against it.
#
#   tools/mutants.sh            all mutants
#   tools/mutants.sh <name>...  some
# Prints MUTANT=<name> KILLED|SURVIVED row=<id> gate=<script> also_failed=<n>,
# then MUTANTS_KILLED=<k>/<n>; exit 0 when every one is killed. The summary
# goes to build/mutants-run/last/summary.txt for tools/p1_exit.py.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
M="$ROOT/build/mutants/apps"
D="$ROOT/build/dev/apps"
for x in "$M/ksim/ksim" "$D/ksim-ctl/ksim-ctl" "$D/ksim-corestub/ksim-corestub" "$D/ksim-sim/ksim-sim"; do
    [[ -x "$x" ]] || { echo "MUTANTS=SKIP (no $x; build the mutants and dev presets)"; exit 77; }
done
OUT="$ROOT/build/mutants-run/last"
rm -rf "$OUT"; mkdir -p "$OUT"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin"
ln -s "$M/ksim/ksim" "$T/bin/ksim"
ln -s "$D/ksim-ctl/ksim-ctl" "$T/bin/ksim-ctl"
ln -s "$D/ksim-corestub/ksim-corestub" "$T/bin/ksim-corestub"
BLOCK=001010000300001/12
"$D/ksim-sim/ksim-sim" range init --master "$T/keys/master.key" --kek "$T/keys/kek.key" >/dev/null || exit 1
"$D/ksim-sim/ksim-sim" range derive --block "$BLOCK" --master "$T/keys/master.key" --kek "$T/keys/kek.key" \
    --out "$T/cards" >/dev/null || exit 1

want=("$@")
killed=0; total=0
while IFS=$'\t' read -r name row _; do
    [[ -z "$name" || "$name" == name || "$name" == \#* ]] && continue
    if [[ ${#want[@]} -gt 0 && ! " ${want[*]} " == *" $name "* ]]; then continue; fi
    if [[ "$row" == - ]]; then
        # A mutant only a procedure test kills runs in the mutants preset's ctest, not here.
        echo "MUTANT=$name PROCEDURE row=- (tests/procedure, the mutants preset)" | tee -a "$OUT/summary.txt"
        continue
    fi
    total=$((total + 1))
    gate=$(grep -l "row $row " "$ROOT"/gates/verification/ksim-p[123]-*.sh | head -n 1)
    if [[ -z "$gate" ]]; then
        echo "MUTANT=$name SURVIVED row=$row gate=none (no gate scores the row)" | tee -a "$OUT/summary.txt"
        continue
    fi
    # A gate that needs a reader or a peer runs its mutants in its own hook (P2 Q1: 57-pcsc).
    if elsewhere=$(sed -n 's/^# mutants: run by //p' "$gate") && [[ -n "$elsewhere" ]]; then
        total=$((total - 1))
        echo "MUTANT=$name ELSEWHERE row=$row gate=$(basename "$gate") by=$elsewhere" | tee -a "$OUT/summary.txt"
        continue
    fi
    # A gate may name the topology it needs (P2 Q3: '# topology: topologies/split-stub.yaml').
    topo=$(sed -n 's/^# topology: //p' "$gate" | head -n 1)
    KSIM_TOPOLOGY_FILE="${topo:+$ROOT/$topo}" KSIM_MUTANT="$name" KSIM_BIN="$T/bin" KSIM_RUNS="$T/runs-$name" KSIM_MASTER="$T/keys/master.key" \
        KSIM_KEK="$T/keys/kek.key" KSIM_SEALED="$T/cards" \
        KSIM_PHASE="$(case "$gate" in *ksim-p3-*) echo p3 ;; *ksim-p2-*) echo p2 ;; *) echo p1 ;; esac)" \
        sh "$ROOT/gates/run.sh" stub "$gate" > "$OUT/$name.out" 2>&1
    run=$(sed -n 's/^RUN_DIR=//p' "$OUT/$name.out")
    res=$(awk -F'\t' -v r="$row" '$1 == r {print $2}' "$run/rows.tsv" 2>/dev/null | head -n 1)
    also=$(awk -F'\t' -v r="$row" '$1 != r && $2 == "FAIL"' "$run/rows.tsv" 2>/dev/null | wc -l)
    if [[ "$res" == FAIL ]]; then
        killed=$((killed + 1)); verdict=KILLED
    else
        verdict=SURVIVED
    fi
    echo "MUTANT=$name $verdict row=$row result=${res:-none} gate=$(basename "$gate") also_failed=$also" | tee -a "$OUT/summary.txt"
    [[ -n "$run" && -d "$run" ]] && cp "$run/rows.tsv" "$OUT/$name.rows.tsv" 2>/dev/null
done < "$ROOT/tests/mutants.tsv"
echo "MUTANTS_KILLED=$killed/$total" | tee -a "$OUT/summary.txt"
[[ $killed -eq $total && $total -gt 0 ]]
