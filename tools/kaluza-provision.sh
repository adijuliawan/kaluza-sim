#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# The kaluza-core subscriber import (P1 N9/N11, W0; ADR 0008), from the dev PC
# only, as the kaluza-core session described the endpoints on 2026-10-15:
#
#   token  https://kaluza-keycloak.kaluza.svc.cluster.local:8443/realms/kaluza/protocol/openid-connect/token
#          at the Keycloak service's ClusterIP; client_credentials for
#          kaluza-sim-key-entry; root.pem; the client certificate sent too
#   UDR    https://udr.5gc.mnc001.mcc001.3gppnetwork.org:7779/provisioning/v1/subscribers/imsi-<IMSI>
#          at the pod IP of a Running, Ready UDR pod not being deleted, read
#          again on every run; mTLS with tls-chain.pem and tls.key
#
#   tools/kaluza-provision.sh --resolve-only
#   tools/kaluza-provision.sh --window-agreed provision --block 001010000300000/100 [--replace]
#   tools/kaluza-provision.sh --window-agreed deprovision --block 001010000300000/100
#
# kubectl is only read (get svc, get pod). The credentials stay in
# ~/.config/kaluza-sim/provisioning (KSIM_PROV_DIR), read by ksim-sim at run
# time and never by this script; the client secret's file name is
# KSIM_PROV_SECRET_FILE (default client-secret). The range master is
# ~/.kaluza-sim/secrets/range-master.key (KSIM_MASTER). ksim-sim prints UE_ID,
# STATUS, PROFILE and K_FPR only.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SIM="${KSIM_SIM:-$ROOT/build/dev/apps/ksim-sim/ksim-sim}"
NS=kaluza
TOKEN_HOST=kaluza-keycloak.kaluza.svc.cluster.local
UDR_HOST=udr.5gc.mnc001.mcc001.3gppnetwork.org

keycloak_ip() { kubectl -n "$NS" get svc kaluza-keycloak -o jsonpath='{.spec.clusterIP}'; }
udr_ip() {
    kubectl -n "$NS" get pod -l app.kubernetes.io/name=kaluza-udr --field-selector=status.phase=Running -o json |
        python3 -I -c '
import json, sys
for p in json.load(sys.stdin)["items"]:
    if p["metadata"].get("deletionTimestamp"):
        continue
    ready = any(c["type"] == "Ready" and c["status"] == "True" for c in p["status"].get("conditions", []))
    if ready and p["status"].get("podIP"):
        print(p["status"]["podIP"])
        break
'
}

window=0
if [[ "${1:-}" == --window-agreed ]]; then window=1; shift; fi
kc="$(keycloak_ip)"; udr="$(udr_ip)"
[[ -n "$kc" && -n "$udr" ]] || { echo "KALUZA_PROVISION=FAIL (no Keycloak ClusterIP or no Ready UDR pod)" >&2; exit 1; }
echo "KEYCLOAK=$kc UDR=$udr"
if [[ "${1:-}" == --resolve-only ]]; then exit 0; fi
[[ $window -eq 1 ]] || { echo "refused: --window-agreed (a window agreed with the kaluza-core session)" >&2; exit 2; }
cmd="${1:?provision|deprovision}"; shift
case "$cmd" in provision|deprovision) ;; *) echo "provision|deprovision" >&2; exit 2 ;; esac
extra=()
[[ "$cmd" == provision ]] && extra+=(--master "${KSIM_MASTER:-$HOME/.kaluza-sim/secrets/range-master.key}")
exec "$SIM" range "$cmd" --target kaluza \
    --token-url "https://$TOKEN_HOST:8443/realms/kaluza/protocol/openid-connect/token" --token-mtls \
    --udr-url "https://$UDR_HOST:7779" \
    --resolve "$TOKEN_HOST=$kc" --resolve "$UDR_HOST=$udr" \
    --cred-dir "${KSIM_PROV_DIR:-$HOME/.config/kaluza-sim/provisioning}" \
    --secret-file "${KSIM_PROV_SECRET_FILE:-client-secret}" \
    "${extra[@]}" "$@"
