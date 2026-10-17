#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# P3 R0 spike 2 (ADR 0013 point 13): the RRC builder route for a handover CellGroupConfig.
# tests/vectors/rrc/cellgroup-ho-spike.json (our DU's SRB1 bearer plus spCellConfig with
# reconfigurationWithSync: spCellConfigCommon, newUE-Identity, t304, contention-free RA on an
# SSB) goes through our JER route (ksim-codec encode, asn1c's UPER with strict constraints),
# then OCUDU's decoder from the pinned tree (tools/ocudu_vectors/unpack.sh) and pycrate read it.
# OCUDU's CU-CP calls report_fatal_error on a target DU's CellGroupConfig it cannot unpack and
# reads t304 from it unchecked. Prints SPIKE_CG=PASS|FAIL.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
C="$ROOT/build/dev/apps/ksim-codec/ksim-codec"
jer=$(python3 -c 'import json,sys;print(json.dumps(json.load(open(sys.argv[1]))))' "$ROOT/tests/vectors/rrc/cellgroup-ho-spike.json")
hex=$("$C" encode rrc CellGroupConfig "$jer") || { echo "SPIKE_CG=FAIL (our encoder refused it)"; exit 1; }
echo "OURS hex=$hex"
oc=$(printf 'CellGroupConfig\t%s\n' "$hex" | "$ROOT/tools/ocudu_vectors/unpack.sh")
echo "OCUDU $oc"
py=$("$ROOT/.venv/bin/python" -I -c '
import sys
from pycrate_asn1dir import RRCNR
c = RRCNR.NR_RRC_Definitions.CellGroupConfig
h = sys.argv[1]
c.from_uper(bytes.fromhex(h))
r = c.get_val()["spCellConfig"]["reconfigurationWithSync"]
print("PYCRATE=OK" if c.to_uper().hex() == h else "PYCRATE=DIFF", "t304=" + r["t304"], "newUE=%d" % r["newUE-Identity"])
' "$hex" 2>&1)
echo "$py"
case "$oc" in *"UNPACK=OK"*"REPACK=SAME"*"recfg_with_sync=1 t304_ms=1000"*"cfra=1"*) ok_oc=1 ;; *) ok_oc=0 ;; esac
case "$py" in PYCRATE=OK*t304=ms1000*) ok_py=1 ;; *) ok_py=0 ;; esac
[[ $ok_oc == 1 && $ok_py == 1 ]] && echo "SPIKE_CG=PASS" || { echo "SPIKE_CG=FAIL"; exit 1; }
