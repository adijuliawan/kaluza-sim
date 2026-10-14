#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# Build the OCUDU vector producer outside both trees and write its output to
# tests/vectors/sources/ocudu-produced.tsv (plan M10). Refuses while the lab
# cell (gnb/odu) runs, like tools/ci.sh.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OCUDU_SRC="${OCUDU_SRC:-/home/amadeus/Development/ran/ocudu}"
B="${HOME}/.cache/kaluza-sim/ocudu-vectors"
if pgrep -x gnb >/dev/null || pgrep -x odu >/dev/null; then
    echo "OCUDU_VECTORS=REFUSED (the lab cell is running)"; exit 1
fi
rev="$(git -C "$OCUDU_SRC" rev-parse HEAD)"
cmake -S "$ROOT/tools/ocudu_vectors" -B "$B" -G Ninja -DOCUDU_SRC="$OCUDU_SRC" >/dev/null
nice -n 10 cmake --build "$B" -j "$(nproc)" >/dev/null
out="$ROOT/tests/vectors/sources/ocudu-produced.tsv"
mkdir -p "$(dirname "$out")"
{
    echo "# OCUDU ${rev} test message builders packed by OCUDU's ASN.1 encoder (tools/ocudu_vectors). Do not edit."
    printf 'protocol\tbuilder\thex\n'
    "$B/ocudu-vectors" | grep -P "^(f1ap|e1ap|ngap|xnap|rrc)\t"
} > "$out"
echo "OCUDU_VECTORS=PASS rev=${rev:0:10} pdus=$(($(wc -l < "$out") - 2)) out=${out#$ROOT/}"
