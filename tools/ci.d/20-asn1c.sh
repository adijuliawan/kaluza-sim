#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# CI hook (plan M4): the vendored asn1c runtime matches its manifest, the
# installed compiler is the pinned binary, and the smoke test passes.
# Exit 77 (SKIP) when the pinned compiler is not installed.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ASN1C="${KSIM_ASN1C:-$HOME/.local/opt/asn1c-18e56503/bin/asn1c}"

( cd "$ROOT/third_party/asn1c/runtime" && sha256sum --quiet -c "$ROOT/third_party/asn1c/MANIFEST.sha256" ) ||
    { echo "ASN1C_RUNTIME=FAIL (vendored files differ from MANIFEST.sha256)"; exit 1; }
extra=$(comm -13 <(awk '{print $2}' "$ROOT/third_party/asn1c/MANIFEST.sha256" | LC_ALL=C sort) \
                 <(ls "$ROOT/third_party/asn1c/runtime" | LC_ALL=C sort))
[[ -z "$extra" ]] || { echo "ASN1C_RUNTIME=FAIL (files not in the manifest: $extra)"; exit 1; }
echo "ASN1C_RUNTIME=PASS files=$(wc -l < "$ROOT/third_party/asn1c/MANIFEST.sha256")"

[[ -x "$ASN1C" ]] || { echo "ASN1C=SKIP (not installed; run tools/build-asn1c.sh)"; exit 77; }
want=$(awk -F'\t' '$1=="asn1c"{print $3}' "$ROOT/third_party/PINS.tsv" | sed -n 's/.*binary-sha256:\([0-9a-f]*\).*/\1/p')
have=$(sha256sum "$ASN1C" | cut -c1-64)
[[ "$want" == "$have" ]] || { echo "ASN1C=FAIL installed binary $have is not the pinned $want"; exit 1; }
echo "ASN1C=PASS sha256=$have"
"$ROOT/tests/asn1c-smoke/run.sh"
