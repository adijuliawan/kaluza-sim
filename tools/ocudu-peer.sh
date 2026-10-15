#!/bin/sh
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# OCUDU as kaluza-sim's interop peer (P2 Q4; ADR 0012).
#
#   tools/ocudu-peer.sh build [--jobs N]
#       exports the pinned commit of the lab's tree (git archive, read-only on
#       ~/Development/ran/ocudu-fork) into ~/kaluza-sim-peers/ocudu-<pin>/src and
#       builds only ocucp and ocuup there, Release, -march=x86-64-v3 (the lab VM's
#       Zen 3 runs them; never native), no radio, no tests, no plugins. Writes
#       ~/kaluza-sim-peers/ocudu-<pin>/PIN (commit and the binaries' sha256).
#   tools/ocudu-peer.sh run --cucp|--cuup [--run-dir D] [--amf A:P] [--lab]
#       writes the role's config from topologies/peers/ocudu/<role>.yml.in into
#       D (default runs/ocudu-<UTC>) and starts it there in the background,
#       printing PID= and CONFIG=. Our dev-PC guard applies to the peer: an AMF
#       in 172.30.0.0/16 is refused unless this runs on kaluza-uesim with --lab,
#       and nothing starts while a gnb or odu process (a B220 cell) runs.
#   tools/ocudu-peer.sh stop [--lab]
#       stops every ocucp and ocuup started from our build (matched by their full
#       path, so no other OCUDU on the host is touched), then checks none is left;
#       with --lab also tears down their namespaces.
#
# P2 Q7: in a release (tools/deploy-uesim.sh --peers) the binaries are the
# release's peers/ocudu-<pin>/, else tools/ocudu-peer.sh build's. With --lab on
# kaluza-uesim (LW2, ADR 0012 point 4) each role runs in a namespace of ours made
# through ksim-ctl netd: ksim-ocucp with 172.30.30.36/24 on ens19 (N2) and the
# ksim-mid leg 10.250.0.1/24 (F1-C, E1); ksim-ocuup with 172.30.30.37/24 (N3)
# and 10.250.0.3/24 (E1, F1-U); started by netd's exec as the asking user, from
# the lab templates (<role>-lab.yml.in).
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PIN=d9d2263f4d
FORK="$HOME/Development/ran/ocudu-fork"
BASE="$HOME/kaluza-sim-peers/ocudu-$PIN"
REL_PEERS="$ROOT/peers/ocudu-$PIN"   # a release's copy (kaluza-uesim)
KSIM_CTL="${KSIM_CTL:-$ROOT/bin/ksim-ctl}"
[ -x "$KSIM_CTL" ] || KSIM_CTL="$ROOT/build/dev/apps/ksim-ctl/ksim-ctl"
# lab: netns, N2/N3 address on ens19, ksim-mid leg (LW2)
lab_ns() { [ "$1" = cucp ] && echo ksim-ocucp || echo ksim-ocuup; }
lab_addr() { [ "$1" = cucp ] && echo 172.30.30.36/24 || echo 172.30.30.37/24; }
lab_mid() { [ "$1" = cucp ] && echo 10.250.0.1/24 || echo 10.250.0.3/24; }
cmd="${1:?usage: tools/ocudu-peer.sh build|run|stop}"; shift

case "$cmd" in
build)
    jobs=12
    [ "${1:-}" = --jobs ] && jobs="$2"
    [ -d "$FORK/.git" ] || { echo "no OCUDU tree at $FORK" >&2; exit 2; }
    git -C "$FORK" cat-file -e "$PIN^{commit}" 2>/dev/null || { echo "the fork has no commit $PIN" >&2; exit 2; }
    if [ ! -f "$BASE/src/CMakeLists.txt" ]; then
        mkdir -p "$BASE/src"
        git -C "$FORK" archive --format=tar "$PIN" | tar -x -C "$BASE/src"
    fi
    cmake -S "$BASE/src" -B "$BASE/build" -G Ninja -DCMAKE_BUILD_TYPE=Release -DMARCH=x86-64-v3 \
        -DENABLE_UHD=OFF -DENABLE_ZEROMQ=OFF -DENABLE_SIDEKIQ=OFF -DENABLE_DIFI=OFF -DENABLE_MKL=OFF \
        -DENABLE_FFTZ=OFF -DENABLE_ARMPL=OFF -DENABLE_PLUGINS=OFF -DBUILD_TESTING=OFF -DENABLE_WERROR=OFF \
        -DENABLE_BACKWARD=OFF -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ >"$BASE/configure.log" 2>&1 ||
        { tail -20 "$BASE/configure.log" >&2; exit 1; }
    nice -n 10 cmake --build "$BASE/build" -j "$jobs" --target ocucp ocuup >"$BASE/build.log" 2>&1 ||
        { tail -30 "$BASE/build.log" >&2; exit 1; }
    cucp=$(find "$BASE/build" -type f -name ocucp -perm -u+x | head -n 1)
    cuup=$(find "$BASE/build" -type f -name ocuup -perm -u+x | head -n 1)
    [ -n "$cucp" ] && [ -n "$cuup" ] || { echo "the build made no ocucp/ocuup" >&2; exit 1; }
    {
        echo "commit=$PIN"
        echo "ocucp=$cucp sha256=$(sha256sum "$cucp" | cut -d' ' -f1)"
        echo "ocuup=$cuup sha256=$(sha256sum "$cuup" | cut -d' ' -f1)"
    } > "$BASE/PIN"
    cat "$BASE/PIN"
    ;;
run)
    role=""; run_dir=""; amf=""; lab=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --cucp) role=cucp ;;
            --cuup) role=cuup ;;
            --run-dir) run_dir="$2"; shift ;;
            --amf) amf="$2"; shift ;;
            --lab) lab=1 ;;
            *) echo "unknown option $1" >&2; exit 2 ;;
        esac
        shift
    done
    [ -n "$role" ] || { echo "run --cucp or --cuup" >&2; exit 2; }
    if [ -f "$REL_PEERS/PIN" ]; then
        pin_file="$REL_PEERS/PIN"
        bin="$REL_PEERS/oc${role#cu}"
        [ "$role" = cucp ] && bin="$REL_PEERS/ocucp"
        [ "$role" = cuup ] && bin="$REL_PEERS/ocuup"
    else
        [ -f "$BASE/PIN" ] || { echo "no peer build (tools/ocudu-peer.sh build)" >&2; exit 2; }
        pin_file="$BASE/PIN"
        [ "$role" = cucp ] && bin=$(sed -n 's/^ocucp=\([^ ]*\) .*/\1/p' "$BASE/PIN")
        [ "$role" = cuup ] && bin=$(sed -n 's/^ocuup=\([^ ]*\) .*/\1/p' "$BASE/PIN")
    fi
    [ -x "$bin" ] || { echo "no $role binary ($pin_file)" >&2; exit 2; }
    : "${run_dir:=$ROOT/runs/ocudu-$(date -u +%Y%m%dT%H%M%SZ)}"
    # The peer's NGAP and E1AP captures are not redacted: K_gNB and the UP keys are
    # in them, so everything it writes is the owner's only, as our run files are.
    umask 077
    mkdir -p "$run_dir"
    cp "$pin_file" "$run_dir/PIN"   # the pin and the binaries' sha256, with the run's evidence (ADR 0012 point 1)
    : "${amf:=127.0.0.1:39412}"
    amf_addr=${amf%:*}; amf_port=${amf##*:}
    case "$amf_addr" in
        172.30.*)
            if [ "$lab" != 1 ] || [ "$(hostname)" != kaluza-uesim ]; then
                echo "refused: an AMF in 172.30.0.0/16 needs --lab on kaluza-uesim (the dev-PC guard)" >&2; exit 7
            fi ;;
    esac
    # The dev PC's rule (lab.md): never while a B220 cell runs, as ksim and ci.sh refuse.
    if pgrep -x gnb >/dev/null 2>&1 || pgrep -x odu >/dev/null 2>&1; then
        echo "refused: a gnb or odu process runs on this host (a B220 cell)" >&2; exit 7
    fi
    tmpl="$ROOT/topologies/peers/ocudu/$role.yml.in"
    [ "$lab" = 1 ] && tmpl="$ROOT/topologies/peers/ocudu/$role-lab.yml.in"
    cfg="$run_dir/ocudu-$role.yml"
    sed -e "s|@AMF_ADDR@|$amf_addr|g" -e "s|@AMF_PORT@|$amf_port|g" -e "s|@RUN_DIR@|$run_dir|g" "$tmpl" > "$cfg"
    if [ "$lab" = 1 ]; then
        # LW2: the role's own namespace with its ens19 address and ksim-mid leg, then netd's exec.
        ns=$(lab_ns "$role")
        "$KSIM_CTL" netd teardown "$ns" >/dev/null 2>&1 || true   # one a run that died left
        "$KSIM_CTL" netd setup-node "$ns" --parent ens19 --addr "$(lab_addr "$role")" >/dev/null || exit 1
        "$KSIM_CTL" netd veth "$ns" "$(lab_mid "$role")" >/dev/null || { "$KSIM_CTL" netd teardown "$ns" >/dev/null 2>&1; exit 1; }
        "$KSIM_CTL" netd exec "$ns" --log "$run_dir/ocudu-$role.out" -- "$bin" -c "$cfg" | sed -n 's/^PID=/PID=/p'
        echo "NETNS=$ns"
    else
        "$bin" -c "$cfg" > "$run_dir/ocudu-$role.out" 2>&1 &
        echo "PID=$!"
    fi
    echo "CONFIG=$cfg"
    ;;
stop)
    # Only ours: the path of our build (or the release's copy), anchored (never a bare
    # pkill -f on a name). The CU-UP first: one whose CU-CP went first retries E1 Setup
    # while stopping, fails it fatally and never writes its captures.
    for prefix in "$BASE/build/apps" "$REL_PEERS"; do
        for role in cu_up cu_cp; do
            pat="^$prefix/$role/"
            [ "$prefix" = "$REL_PEERS" ] && { [ "$role" = cu_up ] && pat="^$prefix/ocuup" || pat="^$prefix/ocucp"; }
            pkill -f "$pat" 2>/dev/null || true
            i=0
            while pgrep -f "$pat" >/dev/null 2>&1; do
                i=$((i + 1)); [ "$i" -gt 50 ] && break
                sleep 0.1
            done
        done
    done
    pkill -9 -f "^$BASE/build/" 2>/dev/null || true
    pkill -9 -f "^$REL_PEERS/" 2>/dev/null || true
    sleep 0.1
    if [ "${1:-}" = --lab ]; then
        for r in cuup cucp; do "$KSIM_CTL" netd teardown "$(lab_ns "$r")" >/dev/null 2>&1 || true; done
    fi
    if pgrep -f "^$BASE/build/" >/dev/null 2>&1 || pgrep -f "^$REL_PEERS/" >/dev/null 2>&1; then
        echo "OCUDU_LEFT=1"; exit 1
    fi
    echo "OCUDU_LEFT=0"
    ;;
*) echo "usage: tools/ocudu-peer.sh build|run|stop" >&2; exit 2 ;;
esac
