#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# CI hook (P1 N15; architecture section 6): every persona's capability
# containers decode in pycrate (our Rel-19 RRC) and tshark, and, where the
# kaluza-ue captures are on this machine (KSIM_PERSONA_CAPTURES), extracting
# again from the named capture gives the same octets. The C++ side (the
# persona loads, its NR capability decodes in asn1c, the UE sends it byte for
# byte) is in tests/unit/node and tests/procedure persona_test.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PY="$ROOT/.venv/bin/python"
[[ -x "$PY" ]] || { echo "PERSONAS=SKIP (no oracle venv)"; exit 77; }
command -v tshark >/dev/null || { echo "PERSONAS=SKIP (no tshark)"; exit 77; }
CAPS="${KSIM_PERSONA_CAPTURES:-/home/amadeus/Development/ran/kaluza-ue/captures}"
extra=()
if [[ -d "$CAPS" ]]; then
    extra=(--captures "$CAPS")
else
    echo "PERSONA_CAPTURES=absent (decode checks only)"
fi
"$PY" -I "$ROOT/tools/persona_extract.py" --check "$ROOT"/personas/*.yaml "${extra[@]}" 2>&1 | grep -v '^CryptoMobile'
exit "${PIPESTATUS[0]}"
