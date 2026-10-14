#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# CI hook (plan M5): the docx trap tests pass; the committed spec/asn1/ equals a
# fresh extraction from the pinned documents (no drift, no hand edits); the
# construct inventory is current. The drift check is skipped (77) on a fresh
# clone without the fetched documents.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
python3 -m unittest discover -s "$ROOT/tests/spec_tools" -q 2>&1 | tail -n 3 || exit 1
python3 "$ROOT/spec/tools/asn1_constructs.py" --check || exit 1
if ! compgen -G "$ROOT/spec/3gpp/38/38331-*.zip" >/dev/null; then
    echo "ASN1_DRIFT=SKIP (no fetched documents; run spec/tools/fetch.py)"; exit 77
fi
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
python3 "$ROOT/spec/tools/docx_asn1.py" all --out "$W" >/dev/null || exit 1
for p in rrc ngap f1ap e1ap xnap; do
    diff -r -q "$W/$p" "$ROOT/spec/asn1/$p" || { echo "ASN1_DRIFT=FAIL proto=$p"; exit 1; }
done
echo "ASN1_DRIFT=PASS (committed spec/asn1 equals a fresh extraction)"
