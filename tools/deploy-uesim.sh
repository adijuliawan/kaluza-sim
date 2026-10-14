#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# Deploy and run the release-lab ksim-selftest on kaluza-uesim (VM 105), plan
# M16 and lab.md. Only in a window agreed with the kaluza-core sessions and the
# user: it refuses to run without --window-agreed. It copies one binary to
# ~/ksim-p0/ as the normal user, records the host (CPU flags, kernel) and the
# binary's shared libraries (a missing one fails), runs the self-test, and
# removes ~/ksim-p0/ again. No sudo, no netns, nothing on ens19 or the lab
# addresses; ssh and scp are the only network use.
#
#   tools/deploy-uesim.sh --window-agreed [--host kaluza-uesim]
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST=kaluza-uesim
AGREED=0
while (( $# )); do
    case "$1" in
        --window-agreed) AGREED=1 ;;
        --host) HOST="$2"; shift ;;
        *) echo "usage: $0 --window-agreed [--host HOST]" >&2; exit 2 ;;
    esac
    shift
done
(( AGREED )) || { echo "DEPLOY=REFUSED (no --window-agreed: clear the window with kaluza-core first, lab.md)"; exit 2; }
BIN="$ROOT/build/release-lab/apps/ksim-selftest/ksim-selftest"
[[ -x "$BIN" ]] || { echo "DEPLOY=FAIL (no $BIN; cmake --build --preset release-lab --target ksim-selftest)"; exit 1; }
OUT="$ROOT/build/uesim-selftest.txt"
DIR=ksim-p0
ssh -o BatchMode=yes "$HOST" "test ! -e ~/$DIR && mkdir ~/$DIR"
trap 'ssh -o BatchMode=yes "$HOST" "rm -rf ~/$DIR" || true' EXIT
scp -q "$BIN" "$HOST:$DIR/ksim-selftest"
{
    echo "UESIM_HOST=$(ssh -o BatchMode=yes "$HOST" hostname)"
    echo "UESIM_KERNEL=$(ssh -o BatchMode=yes "$HOST" uname -r)"
    echo "UESIM_CPUS=$(ssh -o BatchMode=yes "$HOST" nproc)"
    echo "UESIM_CPU=$(ssh -o BatchMode=yes "$HOST" "grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//'")"
    echo "UESIM_FLAGS=$(ssh -o BatchMode=yes "$HOST" "grep -m1 '^flags' /proc/cpuinfo | tr ' ' '\n' | grep -xE 'aes|vaes|pclmulqdq|vpclmulqdq|avx2|sha_ni|avx512f' | sort | tr '\n' ' '")"
    echo "UESIM_LOAD=$(ssh -o BatchMode=yes "$HOST" "cut -d' ' -f1-3 /proc/loadavg")"
    ldd_out=$(ssh -o BatchMode=yes "$HOST" "ldd ~/$DIR/ksim-selftest")
    echo "$ldd_out" | sed 's/^\s*/LDD /'
    if grep -q "not found" <<< "$ldd_out"; then
        echo "LDD=FAIL"
    else
        echo "LDD=PASS libraries=$(grep -c '=>' <<< "$ldd_out")"
    fi
    ssh -o BatchMode=yes "$HOST" "~/$DIR/ksim-selftest --bench-ms 500" || true
} | tee "$OUT"
if grep -q "^SELFTEST=PASS" "$OUT" && grep -q "^LDD=PASS" "$OUT"; then
    echo "DEPLOY=PASS report=build/uesim-selftest.txt"
else
    echo "DEPLOY=FAIL report=build/uesim-selftest.txt"
    exit 1
fi
