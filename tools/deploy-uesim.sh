#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# Deploy v2 to kaluza-uesim (VM 105; P1 N9, lab.md 5). Only in a window agreed
# with the kaluza-core session and the user: it refuses without --window-agreed.
#
#   tools/deploy-uesim.sh --window-agreed [--host kaluza-uesim] [--secrets] [--selftest]
#
# A release is ~/ksim/releases/<commit>/ (bin: ksim, ksim-ctl, ksim-sim,
# ksim-netd, ksim-selftest from the release-lab preset; topologies, cards,
# gates, tools/systemd), ~/ksim/current points at it, and the newest three
# releases are kept. Every binary's shared libraries must resolve on the VM
# (LDD=PASS). --secrets streams the sealed card files and the KEK into
# ~/.kaluza-sim on the VM (umask 077, over ssh stdin); the range master and the
# provisioning credentials never leave the dev PC. --selftest runs
# ksim-selftest from the release (the P0 M16 check). The script uses no sudo:
# installing ksim-netd as root is the user's step, and the commands for it are
# printed at the end.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST=kaluza-uesim
AGREED=0
SECRETS=0
SELFTEST=0
while (( $# )); do
    case "$1" in
        --window-agreed) AGREED=1 ;;
        --host) HOST="$2"; shift ;;
        --secrets) SECRETS=1 ;;
        --selftest) SELFTEST=1 ;;
        *) echo "usage: $0 --window-agreed [--host HOST] [--secrets] [--selftest]" >&2; exit 2 ;;
    esac
    shift
done
(( AGREED )) || { echo "DEPLOY=REFUSED (no --window-agreed: clear the window with kaluza-core first, lab.md)"; exit 2; }

B="$ROOT/build/release-lab/apps"
BINS=(ksim ksim-ctl ksim-sim ksim-netd ksim-selftest)
for b in "${BINS[@]}"; do
    [[ -x "$B/$b/$b" ]] || { echo "DEPLOY=FAIL (no $B/$b/$b; cmake --build --preset release-lab)"; exit 1; }
done
REL="$(git -C "$ROOT" describe --always --dirty --abbrev=12)"
rig() { ssh -o BatchMode=yes "$HOST" "$@"; }

# Stage the release locally, then send it as one tar stream.
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/$REL/bin" "$STAGE/$REL/tools"
for b in "${BINS[@]}"; do cp "$B/$b/$b" "$STAGE/$REL/bin/"; done
cp -r "$ROOT/topologies" "$ROOT/cards" "$ROOT/gates" "$STAGE/$REL/"
cp -r "$ROOT/tools/systemd" "$STAGE/$REL/tools/"
rig "mkdir -p ~/ksim/releases && test ! -e ~/ksim/releases/$REL" || { echo "DEPLOY=FAIL (release $REL is on the VM already)"; exit 1; }
tar -C "$STAGE" -cf - "$REL" | rig "tar -C ~/ksim/releases -xf -"
rig "ln -sfn releases/$REL ~/ksim/current && cd ~/ksim/releases && ls -1t | tail -n +4 | xargs -r rm -rf"
echo "RELEASE=$REL"

ldd_bad=0
for b in "${BINS[@]}"; do
    out=$(rig "ldd ~/ksim/current/bin/$b")
    if grep -q "not found" <<< "$out"; then
        echo "LDD $b: $(grep 'not found' <<< "$out" | tr '\n' ' ')"
        ldd_bad=1
    fi
done
(( ldd_bad )) && { echo "LDD=FAIL"; exit 1; }
echo "LDD=PASS binaries=${#BINS[@]}"

if (( SECRETS )); then
    # The sealed cards and the KEK only; nothing else of ~/.kaluza-sim is sent.
    [[ -d "$HOME/.kaluza-sim/cards" && -f "$HOME/.kaluza-sim/secrets/kek.key" ]] ||
        { echo "SECRETS=FAIL (ksim-sim range init and derive first)"; exit 1; }
    tar -C "$HOME" -cf - .kaluza-sim/cards .kaluza-sim/secrets/kek.key |
        rig "umask 077 && mkdir -p ~/.kaluza-sim && tar -C ~ -xf - && chmod 700 ~/.kaluza-sim ~/.kaluza-sim/cards ~/.kaluza-sim/secrets"
    echo "SECRETS=SENT cards=$(ls "$HOME/.kaluza-sim/cards" | wc -l) kek=1 master=0"
fi

if (( SELFTEST )); then
    rig "~/ksim/current/bin/ksim-selftest --bench-ms 500" | tee "$ROOT/build/uesim-selftest.txt" | grep -E "^SELFTEST="
fi

uid=$(rig "id -u")
cat <<EOF

ksim-netd is installed by the user, once per release that changes it (root on the VM):
  sudo install -o root -g root -m 0755 ~/ksim/current/bin/ksim-netd /usr/local/sbin/ksim-netd
  sudo install -o root -g root -m 0644 ~/ksim/current/tools/systemd/ksim-netd.service /etc/systemd/system/
  sudo sed -i 's/^Environment=KSIM_UID=.*/Environment=KSIM_UID=$uid/' /etc/systemd/system/ksim-netd.service
  sudo systemctl daemon-reload && sudo systemctl enable --now ksim-netd
EOF
echo "DEPLOY=PASS release=$REL"
