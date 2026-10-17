#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# OCUDU's own decoder over our RRC builders (P3 R1; ADR 0014 point 4): every RRCReconfiguration,
# HandoverPreparationInformation and HandoverCommand sample msg_builders_dump prints goes
# through tools/ocudu_vectors/unpack.sh (the pinned tree), with the masterCellGroup inside
# each. Every line must be UNPACK=OK REPACK=SAME: OCUDU's CU-CP treats a container it cannot
# unpack as fatal (report_fatal_error). Prints OCUDU_RRC=PASS|FAIL count=N.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DUMP="${DUMP:-$ROOT/build/dev/tests/unit/asn1/msg_builders_dump}"
[[ -x "$DUMP" ]] || { echo "OCUDU_RRC=SKIP (no $DUMP)"; exit 77; }
out=$("$DUMP" 2>/dev/null | awk -F'\t' '$1 == "rrc" {split($2, a, ".");
        if (a[1] == "RRCReconfiguration" || a[1] == "HandoverPreparationInformation" || a[1] == "HandoverCommand")
            print a[1] "\t" $3}' | "$ROOT/tools/ocudu_vectors/unpack.sh") || { echo "OCUDU_RRC=FAIL (unpack.sh)"; exit 1; }
printf '%s\n' "$out"
n=$(printf '%s\n' "$out" | grep -c .)
bad=$(printf '%s\n' "$out" | grep -vc $'\tUNPACK=OK\tREPACK=SAME\t')
[[ "$n" -gt 0 && "$bad" -eq 0 ]] && { echo "OCUDU_RRC=PASS count=$n"; exit 0; }
echo "OCUDU_RRC=FAIL count=$n bad=$bad"; exit 1
