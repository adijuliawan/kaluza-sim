#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# P0's exit check (plan M16, roadmap P0 exit): refresh the oracle reports of
# every v1 type (M10 roundtrip, M11 l3roundtrip, M12 m12roundtrip), then
# evaluate them with the KATs, the construct table and every must-fail case
# (tools/p0_exit.py). Needs the dev and fuzz builds and the oracle venv.
#
#   tools/p0_exit.sh [--reuse]   (--reuse: keep build/oracle's reports)
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY=("$ROOT/.venv/bin/python" -I)
export KSIM_CODEC="${KSIM_CODEC:-$ROOT/build/dev/apps/ksim-codec/ksim-codec}"
if [[ "${1:-}" != --reuse ]]; then
    for c in roundtrip l3roundtrip m12roundtrip; do
        "${PY[@]}" "$ROOT/tests/oracles/oracle.py" "$c" --show 5 2>&1 | grep -E "_TOTAL|^FAILURE" || true
    done
fi
"${PY[@]}" "$ROOT/tools/p0_exit.py"
