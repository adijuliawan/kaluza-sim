#!/bin/sh
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The performance run's measurements (P2 Q12; requirements.md §3.5), run by gates/run.sh
# inside one ksim run like a gate (tools/perf/perf.sh starts it). The UEs are in namespaces
# of their own (netd ues: true) and the stub's UPF forwards to its DN namespace
# (ksim-corestub --dn-netd), where iperf3 servers run on 10.60.0.1. Each number goes to
# $RUN/perf.tsv as "case<TAB>metric<TAB>value<TAB>unit"; tools/perf/perf_report.py scores them.
#
#   PERF_CASE=one-ue    one UE: TCP DL and UL, ping latency, CPU and RSS per process;
#                       then the same session again with NIA2 on the DRB (TCP DL)
#   PERF_CASE=many      PERF_UES UEs (100) registered 10 at a time, one session each, then
#                       TCP DL on all of them at once, one iperf3 server port each
#   PERF_LABEL          the case's name in perf.tsv (nea2, nea1, ...)
#   PERF_SECS           each iperf3 test's length (10 s)
#
# Not a row gate: no rows are scored, so it ends with summary only for the run's bookkeeping.

set -u
. "$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)/gates/lib/ksim.sh"

: "${PERF_CASE:=one-ue}"
: "${PERF_LABEL:=$PERF_CASE}"
: "${PERF_SECS:=10}"
: "${PERF_UES:=100}"
DN_NS=${DN_NS:-ksim-dn-stub}
OUT="$RUN/perf.tsv"
stub() { "$KSIM_CTL" --socket "$STUB_CTL" stub "$@"; }
put() { printf '%s\t%s\t%s\t%s\n' "$PERF_LABEL" "$1" "$2" "$3" >> "$OUT"; echo "  $PERF_LABEL $1 = $2 $3"; }
py() { if [ -x "$KSIM_ROOT/.venv/bin/python" ]; then "$KSIM_ROOT/.venv/bin/python" -I "$@"; else python3 -I "$@"; fi; }
num() { _v=$(cat); echo "${_v:-0}"; }

# iperf3 servers in the DN namespace, one port each (iperf3 serves one test at a time);
# their PIDs kept, so only they are stopped at the end.
servers() {
    _i=0
    while [ "$_i" -lt "$1" ]; do
        "$KSIM_CTL" netd exec "$DN_NS" --log "$RUN/iperf3-s-$_i.log" -- iperf3 -s -p $((5201 + _i)) \
            | sed -n 's/^PID=//p' >> "$RUN/iperf3-s.pids"
        _i=$((_i + 1))
    done
    [ "$(wc -l < "$RUN/iperf3-s.pids")" -ge "$1" ] || abort "iperf3 did not start in $DN_NS"
    sleep 1
}
# iperf UE PORT ARGS...: one iperf3 client in UE's namespace; prints its JSON report.
iperf() {
    _u=$1; _p=$2; shift 2
    ctl --json --timeout $((PERF_SECS + 20))s ue "$_u" exec -- iperf3 -c 10.60.0.1 -p "$_p" -t "$PERF_SECS" -J "$@"
}
mbits() { py -c 'import json,sys
d=json.load(sys.stdin)
out=json.loads(d[0]["STDOUT"] if isinstance(d,list) else d["STDOUT"])
print("%.1f" % (out["end"]["sum_received"]["bits_per_second"]/1e6))' 2>/dev/null || echo 0; }
# The CPU seconds (user+system) of the processes named, and their RSS in MiB.
cpu_s() { for _n in "$@"; do pgrep -x "$_n"; done | while read -r _pid; do
    awk '{print $14 + $15}' "/proc/$_pid/stat" 2>/dev/null; done | awk -v hz="$(getconf CLK_TCK)" '{s += $1} END {printf "%.2f", s / hz}'; }
rss_mib() { for _n in "$@"; do pgrep -x "$_n"; done | while read -r _pid; do
    awk '/^VmRSS:/ {print $2}' "/proc/$_pid/status" 2>/dev/null; done | awk '{s += $1} END {printf "%.0f", s / 1024}'; }
ROLES="ksim ksim-du ksim-cucp ksim-cuup ksim-ue"

if [ "$PERF_CASE" = one-ue ]; then
    u=1
    ctl ue "$u" power on --wait 30s >/dev/null || abort "UE $u did not register"
    psi=$(ctl ue "$u" ps-establish ipv4 --dnn internet $SLICE --wait 15s | kv PSI)
    [ -n "$psi" ] || abort "UE $u got no session"
    servers 1
    c0=$(cpu_s $ROLES); s0=$(cpu_s ksim-corestub)
    dl=$(iperf "$u" 5201 -R | mbits)
    c1=$(cpu_s $ROLES); s1=$(cpu_s ksim-corestub)
    put tcp_dl "$dl" Mbit/s
    put cpu_ksim_dl "$(awk -v a="$c0" -v b="$c1" -v t="$PERF_SECS" 'BEGIN {printf "%.0f", 100 * (b - a) / t}')" "% of a core"
    put cpu_stub_dl "$(awk -v a="$s0" -v b="$s1" -v t="$PERF_SECS" 'BEGIN {printf "%.0f", 100 * (b - a) / t}')" "% of a core"
    ul=$(iperf "$u" 5201 | mbits)
    put tcp_ul "$ul" Mbit/s
    # Latency: ping RTT with the link delay at 0, both directions (one way is at most half);
    # 200 ms apart, the shortest interval ping gives a user.
    ctl --timeout 60s ue "$u" exec -- ping -c 100 -i 0.2 -s 56 10.60.0.1 | sed -n 's/.*time=\([0-9.]*\) ms.*/\1/p' \
        | grep -E '^[0-9.]+$' | sort -n > "$RUN/rtt.txt"
    ctl metrics > "$RUN/metrics.txt" 2>/dev/null   # the per-hop latency histograms after the pings
    n=$(wc -l < "$RUN/rtt.txt")
    put rtt_median "$(awk -v n="$n" 'NR == int((n + 1) / 2) {print}' "$RUN/rtt.txt")" ms
    put rtt_p99 "$(awk -v n="$n" 'NR == int(n * 0.99 + 0.999) {print}' "$RUN/rtt.txt")" ms
    put rss "$(rss_mib $ROLES)" MiB
    put rss_stub "$(rss_mib ksim-corestub)" MiB
    put cuup_dropped "$(ctl cuup "$(ctl info | kv GNB)-cuup" bearers | kv DROPPED | num)" packets
    # The same with NIA2 on the DRB: the SMF asks for UP integrity.
    ctl ue "$u" ps-release "$psi" --wait 15s >/dev/null
    stub up-policy --integrity required --confidentiality required >/dev/null || abort "the stub took no up-policy"
    psi=$(ctl ue "$u" ps-establish ipv4 --dnn internet $SLICE --wait 15s | kv PSI)
    [ -n "$psi" ] || abort "UE $u got no session with integrity"
    put tcp_dl_nia "$(iperf "$u" 5201 -R | mbits)" Mbit/s
    stub up-policy --integrity not-needed --confidentiality required >/dev/null
    ctl ue "$u" ps-release "$psi" --wait 15s >/dev/null
    ctl ue "$u" power off --switch-off --wait 10s >/dev/null
fi

if [ "$PERF_CASE" = many ]; then
    t0=$(date +%s.%N)
    ctl --parallel 10 ue "1-$PERF_UES" power on --wait 60s >/dev/null || abort "not every UE registered"
    ctl --parallel 10 ue "1-$PERF_UES" ps-establish ipv4 --dnn internet $SLICE --wait 30s > "$RUN/sessions.txt" \
        || abort "not every UE got a session"
    t1=$(date +%s.%N)
    put attach_and_session "$(awk -v a="$t0" -v b="$t1" 'BEGIN {printf "%.1f", b - a}')" s
    put rss_registered "$(rss_mib $ROLES)" MiB
    servers "$PERF_UES"
    b0=$("$KSIM_CTL" --socket "$STUB_CTL" stub | kv UPF_DL_BYTES)
    # The clients start through netd straight into each UE's namespace, their reports to a
    # file each: 100 runs of PERF_SECS through the API's blocking exec would queue behind its
    # worker threads and end in timeouts with their traffic still flowing.
    i=1
    while [ "$i" -le "$PERF_UES" ]; do
        ns=$(ctl ue "$i" ifaces | kv NETNS)
        [ -n "$ns" ] || abort "UE $i has no namespace"
        "$KSIM_CTL" netd exec "$ns" --log "$RUN/iperf-$i.json" -- iperf3 -c 10.60.0.1 -p $((5200 + i)) -t "$PERF_SECS" -R -J \
            | sed -n 's/^PID=//p' >> "$RUN/iperf-c.pids"
        i=$((i + 1))
    done
    t=0
    while [ "$t" -lt $((PERF_SECS + 30)) ]; do
        running=0
        while read -r pid; do kill -0 "$pid" 2>/dev/null && running=$((running + 1)); done < "$RUN/iperf-c.pids"
        [ "$running" -eq 0 ] && break
        sleep 1; t=$((t + 1))
    done
    put clients_still_running "$running" UEs
    b1=$("$KSIM_CTL" --socket "$STUB_CTL" stub | kv UPF_DL_BYTES)
    # The UPF's own count over the test, an upper bound on the clients' (it holds retransmissions).
    put upf_dl_rate "$(awk -v a="${b0:-0}" -v b="${b1:-0}" -v t="$PERF_SECS" 'BEGIN {printf "%.1f", (b - a) * 8 / t / 1e6}')" Mbit/s
    # Each client's own count; the run's sum is what the UEs received together.
    py - "$RUN" "$PERF_UES" > "$RUN/aggregate.txt" <<'PYEOF2'
import json, sys
run, n = sys.argv[1], int(sys.argv[2])
total, ok, starts, ends = 0.0, 0, [], []
for i in range(1, n + 1):
    try:
        o = json.load(open(f"{run}/iperf-{i}.json"))
        s = o["end"]["sum_received"]
        total += s["bytes"] * 8 / s["seconds"] / 1e6
        ok += 1
    except Exception:
        pass
print(f"{total:.1f} {ok}")
PYEOF2
    put tcp_dl_aggregate "$(cut -d' ' -f1 "$RUN/aggregate.txt")" Mbit/s
    put ues_with_traffic "$(cut -d' ' -f2 "$RUN/aggregate.txt")" UEs
    put rss_loaded "$(rss_mib $ROLES)" MiB
    i=1
    while [ "$i" -le "$PERF_UES" ]; do
        release_all "$i" >/dev/null 2>&1 &
        [ $((i % 10)) -eq 0 ] && wait
        i=$((i + 1))
    done
    wait
    ctl --parallel 10 ue "1-$PERF_UES" power off --switch-off --wait 10s >/dev/null 2>&1
fi
# netd exec prints its helper's PID, the leader of the command's process group: the group
# is stopped, the helper and iperf3 together (KS-PLAT-D18).
for f in "$RUN/iperf3-s.pids" "$RUN/iperf-c.pids"; do
    [ -f "$f" ] || continue
    while read -r pid; do kill -TERM "-$pid" 2>/dev/null; done < "$f"   # dash: no "--"
done
echo "PERF_TSV=$OUT"
