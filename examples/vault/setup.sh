#!/usr/bin/env bash
# Configure Vault for jwks-bridge: KV v2 path, read-only policy, Kubernetes auth
# role, and a first active key. Needs VAULT_ADDR and an admin VAULT_TOKEN.
set -euo pipefail
cd "$(dirname "$0")"

NAMESPACE="${BRIDGE_NAMESPACE:-jwks}"          # namespace of the bridge pods
SERVICE_ACCOUNT="${BRIDGE_SERVICE_ACCOUNT:-jwks-bridge}"
KUBERNETES_HOST="${KUBERNETES_HOST:-https://kubernetes.default.svc:443}"

vault secrets list | grep -q '^secret/' || vault secrets enable -path=secret kv-v2
vault policy write jwks-bridge policy.hcl

vault auth list | grep -q '^kubernetes/' || vault auth enable kubernetes
vault write auth/kubernetes/config kubernetes_host="$KUBERNETES_HOST"
vault write auth/kubernetes/role/jwks-bridge \
  bound_service_account_names="$SERVICE_ACCOUNT" \
  bound_service_account_namespaces="$NAMESPACE" \
  policies=jwks-bridge ttl=1h

if ! vault kv get secret/jwks-bridge/default >/dev/null 2>&1; then
  jwks-bridge keygen --alg RS256 --status active | jq -c '[.]' \
    | vault kv put secret/jwks-bridge/default keys=-
fi
