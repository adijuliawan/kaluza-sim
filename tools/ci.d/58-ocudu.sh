#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# CI hook (P2 Q4, Q5; ADR 0012): the OCUDU interop combinations on this host, against
# ksim-corestub, all on 127.0.0.x, with tools/ocudu-peer.sh's build of the pin
# (gates/run.sh starts the peers from each topology and stops them):
#   1. C3, our UE farm and DU with OCUDU's CU-CP and CU-UP: gates/verification/ksim-p2-ocudu.sh
#      on topologies/ocudu-c3-stub.yaml;
#   2. C4, OCUDU's CU-UP with our CU-CP, and C5, OCUDU's CU-CP with our CU-UP: the E1 gate and
#      the P1 session and data-plane gates (topologies/ocudu-c4-stub.yaml, ocudu-c5-stub.yaml);
#   3. tools/pcap_check.py on our captures (the peer's reported apart) and the canary over
#      each run, the peer's files included;
#   4. with the mutants preset built: no_ddds fails ksim-p2.ocudu-ddds;
#   5. no OCUDU process of ours is left.
# Full mode only. SKIP without the peer build, the binaries, tshark or the oracle venv,
# and while a gnb or odu process (a B220 cell) runs on the host: the dev PC's rule.
# The summary goes to build/ocudu/last/summary.txt for tools/p2_exit.py.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[[ "${1:-quick}" == full ]] || { echo "OCUDU=SKIP (full mode only)"; exit 77; }
D="$ROOT/build/dev/apps"
M="$ROOT/build/mutants/apps"
PY="$ROOT/.venv/bin/python"
for x in "$D/ksim/ksim" "$D/ksim-ctl/ksim-ctl" "$D/ksim-corestub/ksim-corestub" "$D/ksim-sim/ksim-sim"; do
    [[ -x "$x" ]] || { echo "OCUDU=SKIP (no $x; build the dev preset)"; exit 77; }
done
PIN=$(sed -n 's/^PIN=//p' "$ROOT/tools/ocudu-peer.sh")
[[ -f "$HOME/kaluza-sim-peers/ocudu-$PIN/PIN" ]] || { echo "OCUDU=SKIP (no peer build; tools/ocudu-peer.sh build)"; exit 77; }
command -v tshark >/dev/null || { echo "OCUDU=SKIP (no tshark)"; exit 77; }
[[ -x "$PY" ]] || { echo "OCUDU=SKIP (no oracle venv)"; exit 77; }
if pgrep -x gnb >/dev/null || pgrep -x odu >/dev/null; then
    echo "OCUDU=SKIP (a gnb or odu process runs: a B220 cell)"; exit 77
fi
V="$ROOT/gates/verification"
BLOCK=001010000300001/12
OUT="$ROOT/build/ocudu/last"
rm -rf "$OUT"; mkdir -p "$OUT"
T="$(mktemp -d)"
trap '"$ROOT/tools/ocudu-peer.sh" stop >/dev/null 2>&1; rm -rf "$T"' EXIT
"$D/ksim-sim/ksim-sim" range init --master "$T/keys/master.key" --kek "$T/keys/kek.key" >/dev/null || exit 1
"$D/ksim-sim/ksim-sim" range derive --block "$BLOCK" --master "$T/keys/master.key" --kek "$T/keys/kek.key" \
    --out "$T/cards" >/dev/null || exit 1

gate() {   # $1 = label, $2 = topology, $3 = the gates (space-separated), then env assignments for the run
    local label="$1" topo="$2" gates="$3"; shift 3
    # shellcheck disable=SC2086
    env KSIM_PHASE=p2 KSIM_TOPOLOGY_FILE="$ROOT/topologies/$topo" KSIM_RUNS="$T/runs-$label" \
        KSIM_MASTER="$T/keys/master.key" KSIM_KEK="$T/keys/kek.key" KSIM_SEALED="$T/cards" "$@" \
        sh "$ROOT/gates/run.sh" stub $gates > "$OUT/$label.out" 2>&1   # the caller's settings last: they win
    local rc=$?
    local run; run=$(sed -n 's/^RUN_DIR=//p' "$OUT/$label.out")
    [[ -n "$run" && -f "$run/rows.tsv" ]] && cp "$run/rows.tsv" "$OUT/$label.rows.tsv"
    echo "$run" > "$OUT/$label.run"
    return $rc
}
row_of() { awk -F'\t' -v r="$2" '$1 == r {print $2}' "$OUT/$1.rows.tsv" 2>/dev/null | head -n 1; }

checks() {   # $1 = label: the oracles and the canary over that run
    local run; run=$(cat "$OUT/$1.run")
    [[ -n "$run" && -d "$run/peer" ]] || { echo "OCUDU: $1 has no run directory with the peer's files"; return 1; }
    "$PY" -I "$ROOT/tools/pcap_check.py" "$run" > "$OUT/$1.pcap.out" || { cat "$OUT/$1.pcap.out"; return 1; }
    "$PY" -I "$ROOT/tools/secret_canary.py" --run-dir "$run" --master "$T/keys/master.key" --block "$BLOCK" \
        > "$OUT/$1.canary.out" || { cat "$OUT/$1.canary.out"; return 1; }
    mkdir -p "$OUT/$1"
    cp -r "$run/peer" "$OUT/$1/peer" 2>/dev/null
    cp "$run"/*.pcapng "$run/rows.tsv" "$OUT/$1/" 2>/dev/null
}

rc=0
echo "-- 1. C3: our DU and UEs, OCUDU's CU-CP and CU-UP, the stub"
gate c3 ocudu-c3-stub.yaml "$V/ksim-p2-ocudu.sh" || rc=1
cat "$OUT/c3.out"
echo "-- 2. C4 and C5: E1 with OCUDU on either side"
gate c4 ocudu-c4-stub.yaml "$V/ksim-p2-e1.sh $V/ksim-p1-session.sh $V/ksim-p1-dataplane.sh" || rc=1
cat "$OUT/c4.out"
gate c5 ocudu-c5-stub.yaml "$V/ksim-p2-e1.sh $V/ksim-p1-session.sh $V/ksim-p1-dataplane.sh" || rc=1
cat "$OUT/c5.out"
echo "-- 2b. C3 with 100 UEs (P2 Q7)"
"$D/ksim-sim/ksim-sim" range derive --block 001010000300000/100 --master "$T/keys/master.key" --kek "$T/keys/kek.key" \
    --out "$T/cards100" >/dev/null || rc=1
gate c3-100 ocudu-c3-stub-100.yaml "$V/ksim-p2-scale.sh" KSIM_SEALED="$T/cards100" STUB_BLOCK=001010000300000/100 || rc=1
cat "$OUT/c3-100.out"

echo "-- 3. captures and the canary"
for label in c3 c4 c5 c3-100; do
    checks "$label" || rc=1
    grep -E '^(PCAP_MALFORMED|PYCRATE_FAILED|PEER_PCAP_MALFORMED|PCAP_CHECK)=' "$OUT/$label.pcap.out" | sed "s/^/$label: /"
    grep -E '^CANARY_RUN=' "$OUT/$label.canary.out" | sed "s/^/$label: /"
done
chmod -R go-rwx "$OUT"

echo "-- 4. the mutants"
killed=0; total=0
if [[ -x "$M/ksim/ksim" ]]; then
    mkdir -p "$T/mbin"
    ln -s "$M/ksim/ksim" "$T/mbin/ksim"; ln -s "$D/ksim-ctl/ksim-ctl" "$T/mbin/ksim-ctl"
    ln -s "$D/ksim-corestub/ksim-corestub" "$T/mbin/ksim-corestub"
    total=$((total + 1))
    gate m-ddds ocudu-c3-stub.yaml "$V/ksim-p2-ocudu.sh" KSIM_BIN="$T/mbin" KSIM_MUTANT=no_ddds
    r=$(row_of m-ddds ksim-p2.ocudu-ddds)
    [[ "$r" == FAIL ]] && killed=$((killed + 1))
    echo "MUTANT=no_ddds $([[ "$r" == FAIL ]] && echo KILLED || echo SURVIVED) row=ksim-p2.ocudu-ddds result=${r:-none}" \
        | tee -a "$OUT/summary.txt"
else
    echo "MUTANTS=SKIP (no mutants preset)" | tee -a "$OUT/summary.txt"
fi

echo "-- 5. nothing left"
"$ROOT/tools/ocudu-peer.sh" stop | tee "$OUT/stop.out"
grep -qx 'OCUDU_LEFT=0' "$OUT/stop.out" || rc=1

fails=$(awk -F'\t' '$2 == "FAIL"' "$OUT/c3.rows.tsv" 2>/dev/null | wc -l)
passes=$(awk -F'\t' '$2 == "PASS"' "$OUT/c3.rows.tsv" 2>/dev/null | wc -l)
[[ "$fails" -eq 0 && "$passes" -ge 9 ]] || rc=1
e1_fail=$(cat "$OUT/c4.rows.tsv" "$OUT/c5.rows.tsv" 2>/dev/null | awk -F'\t' '$2 == "FAIL"' | wc -l)
e1_pass=$(cat "$OUT/c4.rows.tsv" "$OUT/c5.rows.tsv" 2>/dev/null | awk -F'\t' '$2 == "PASS"' | wc -l)
e1_allowed=$(cat "$OUT/c4.rows.tsv" "$OUT/c5.rows.tsv" 2>/dev/null | awk -F'\t' '$2 == "ALLOWED"' | wc -l)
[[ "$e1_fail" -eq 0 && "$e1_pass" -ge 4 ]] || rc=1
[[ "$killed" -eq "$total" ]] || rc=1
{
    echo "OCUDU_PIN=$PIN"
    sed 's/^/OCUDU_/' "$HOME/kaluza-sim-peers/ocudu-$PIN/PIN" | sed -n 's/^OCUDU_\(ocucp\|ocuup\)=[^ ]* sha256=/OCUDU_\U\1\E_SHA256=/p'
    echo "OCUDU_C3_PASS=$passes"
    echo "OCUDU_C3_FAIL=$fails"
    echo "OCUDU_C4_C5_PASS=$e1_pass"
    echo "OCUDU_C4_C5_ALLOWED=$e1_allowed"
    echo "OCUDU_C4_C5_FAIL=$e1_fail"
    grep -q $'^ksim-p2.ocudu-100\tPASS' "$OUT/c3-100.rows.tsv" 2>/dev/null && echo "OCUDU_C3_100=PASS" || echo "OCUDU_C3_100=FAIL"
    for label in c3 c4 c5 c3-100; do
        grep -E '^(PCAP_MALFORMED|PYCRATE_FAILED|PEER_PCAP_MALFORMED)=' "$OUT/$label.pcap.out" | sed "s/^/${label^^}_/"
        grep -E '^CANARY_RUN=' "$OUT/$label.canary.out" | sed "s/^/${label^^}_/"
    done
    echo "OCUDU_MUTANTS_KILLED=$killed/$total"
} | tee -a "$OUT/summary.txt"
echo "OCUDU=$([[ $rc -eq 0 ]] && echo PASS || echo FAIL) OUT=build/ocudu/last"
exit "$rc"
