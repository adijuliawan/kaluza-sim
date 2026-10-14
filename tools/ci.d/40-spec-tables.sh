#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# CI hook (plans M7, M11): the extracted NAS/SMS tables and KATs equal a fresh
# extraction from the pinned documents, the second readings of the NAS tables
# have no unclassified difference, spec/v1-pdus.tsv is current, and
# spec/nas/24501/ie_types.tsv (tools/nasgen.py) is current with no problem.
# Exit 77 (SKIP) on a fresh clone without the fetched documents.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
python3 -m unittest discover -s "$ROOT/tests/spec_tools" -p 'test_*.py' -q 2>&1 | tail -n 3 || exit 1
# The NAS IE types (plan M11) agree with the committed message tables.
python3 -I "$ROOT/tools/nasgen.py" --check || exit 1
if ! compgen -G "$ROOT/spec/3gpp/24/24501-*.zip" >/dev/null; then
    echo "SPEC_TABLES=SKIP (no fetched documents; run spec/tools/fetch.py)"; exit 77
fi
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
python3 "$ROOT/spec/tools/docx_tables.py" all --out "$W/nas" >/dev/null || exit 1
python3 "$ROOT/spec/tools/kat_extract.py" --out "$W/kat" >/dev/null || exit 1
for d in 24501 24008 24011 23038; do
    for f in "$W/nas/$d"/*.tsv; do
        cmp -s "$f" "$ROOT/spec/nas/$d/$(basename "$f")" || { echo "SPEC_TABLES=DRIFT $d/$(basename "$f")"; exit 1; }
    done
done
for f in "$W/kat"/*.tsv; do
    cmp -s "$f" "$ROOT/spec/kat/$(basename "$f")" || { echo "SPEC_TABLES=DRIFT kat/$(basename "$f")"; exit 1; }
done
"$ROOT/.venv/bin/python" -I "$ROOT/spec/tools/nas_second_reading.py" 2>/dev/null | tail -n 1 | grep -q "unclassified=0" ||
    { echo "SPEC_TABLES=FAIL second reading has unclassified differences"; exit 1; }
python3 "$ROOT/spec/tools/v1_pdus.py" --check || exit 1
echo "SPEC_TABLES=PASS (tables, KATs and v1-pdus match the pinned documents)"
