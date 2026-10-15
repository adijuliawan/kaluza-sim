#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# Waits until pcscd lists vpcd's reader (P2 Q7; the CI hooks 55 and 57):
#
#   tools/vpcd_ready.sh ["Virtual PCD 00 01"]
#
# pcscd runs socket-activated with --auto-exit. One that starts while the one
# before still holds vpcd's port comes up without the virtual readers ("Address
# already in use" in its journal), and stays that way while any client talks to
# it, so polling it does not help. This looks once; when the reader is missing,
# it leaves pcscd alone past its 60 s idle exit and looks again, three times at
# most. Prints VPCD_READY=1 (exit 0) or VPCD_READY=0 (exit 1). Without
# pcsc_scan it cannot look, and says VPCD_READY=unknown (exit 0).
set -uo pipefail
reader="${1:-Virtual PCD 00 01}"
command -v pcsc_scan >/dev/null || { echo "VPCD_READY=unknown (no pcsc_scan)"; exit 0; }
for attempt in 1 2 3; do
    if timeout 10 pcsc_scan -r 2>/dev/null | grep -qF "$reader"; then
        echo "VPCD_READY=1"
        exit 0
    fi
    [[ $attempt -lt 3 ]] && sleep 70
done
echo "VPCD_READY=0 (pcscd lists no '$reader')"
exit 1
