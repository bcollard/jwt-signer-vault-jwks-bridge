#!/usr/bin/env bash
# End-to-end test: Vault, jwks-bridge and Kong Gateway Enterprise in hybrid mode
# (one control plane, two data planes) on a Kubernetes cluster.
#
# Usage: test/e2e/run.sh [all|up|configure|test|down]   (default: all)
#   configure  apply the Kong configuration only (used by demo.sh)
#
# Environment:
#   KONG_LICENSE_DATA   Kong Enterprise license JSON (required; jwt-signer is an Enterprise plugin)
#   E2E_KUBE_CONTEXT    use this existing cluster context instead of creating a kind cluster
#   E2E_CLUSTER         kind cluster name (default: jwks-bridge-e2e)
#   E2E_IMAGE           bridge image tag to build and load (default: jwks-bridge:e2e)
#   E2E_LOAD_IMAGE      command that loads $E2E_IMAGE into the cluster
#                       (default: kind load docker-image $E2E_IMAGE --name $E2E_CLUSTER)
#   E2E_KEEP            set to 1 to keep the cluster after "all"
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$ROOT/test/e2e"
WORK="$HERE/.work"
CLUSTER="${E2E_CLUSTER:-jwks-bridge-e2e}"
IMAGE="${E2E_IMAGE:-jwks-bridge:e2e}"
CTX="${E2E_KUBE_CONTEXT:-kind-$CLUSTER}"
KONG_CHART_VERSION="3.4.1"
BASIC_USER="kong"
BASIC_PASSWORD="e2e-password"

k() { kubectl --context "$CTX" "$@"; }
log() { printf '\n==> %s\n' "$*"; }

create_cluster() {
  if [[ -n "${E2E_KUBE_CONTEXT:-}" ]]; then
    log "Using existing context $CTX"
    return
  fi
  if ! kind get clusters | grep -qx "$CLUSTER"; then
    log "Creating kind cluster $CLUSTER"
    kind create cluster --name "$CLUSTER" --config "$HERE/kind.yaml" --wait 120s
  fi
}

load_image() {
  log "Building $IMAGE"
  docker build -t "$IMAGE" "$ROOT"
  log "Loading $IMAGE into the cluster"
  if [[ -n "${E2E_LOAD_IMAGE:-}" ]]; then
    eval "$E2E_LOAD_IMAGE"
  else
    kind load docker-image "$IMAGE" --name "$CLUSTER"
  fi
}

gen_certs() {
  log "Generating certificates in $WORK"
  mkdir -p "$WORK"
  cd "$WORK"
  # Kong hybrid mode shared cluster certificate.
  openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -days 30 \
    -keyout cluster.key -out cluster.crt -subj "/CN=kong_clustering" 2>/dev/null
  # CA and server certificate for the bridge private listener.
  openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 30 \
    -keyout ca.key -out ca.crt -subj "/CN=jwks-bridge e2e CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
  openssl req -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout bridge.key -out bridge.csr -subj "/CN=jwks-bridge.jwks.svc" 2>/dev/null
  printf 'subjectAltName=DNS:jwks-bridge.jwks.svc,DNS:jwks-bridge.jwks.svc.cluster.local\nextendedKeyUsage=serverAuth\n' > bridge.ext
  openssl x509 -req -in bridge.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 30 \
    -extfile bridge.ext -out bridge.crt 2>/dev/null
  cd - >/dev/null
}

deploy_vault() {
  log "Deploying Vault (dev mode)"
  k apply -f "$HERE/manifests/vault.yaml"
  k -n vault rollout status deploy/vault --timeout=180s

  log "Configuring Vault Kubernetes auth and seeding key k1"
  k -n vault exec -i deploy/vault -- sh -ec '
    vault auth list | grep -q "^kubernetes/" || vault auth enable kubernetes
    vault write auth/kubernetes/config kubernetes_host=https://kubernetes.default.svc:443
    vault policy write jwks-bridge - <<POLICY
path "secret/data/jwks-bridge/*" { capabilities = ["read"] }
path "secret/metadata/jwks-bridge/*" { capabilities = ["read"] }
POLICY
    vault write auth/kubernetes/role/jwks-bridge \
      bound_service_account_names=jwks-bridge bound_service_account_namespaces=jwks \
      policies=jwks-bridge ttl=1h'
  (cd "$ROOT" && go run ./cmd/jwks-bridge keygen --alg RS256 --kid k1 --status active) \
    | jq -c '[.]' \
    | k -n vault exec -i deploy/vault -- vault kv put secret/jwks-bridge/default keys=-
}

deploy_bridge() {
  log "Deploying jwks-bridge"
  k create namespace jwks --dry-run=client -o yaml | k apply -f -
  k -n jwks create secret tls jwks-bridge-tls --cert="$WORK/bridge.crt" --key="$WORK/bridge.key" \
    --dry-run=client -o yaml | k apply -f -
  k -n jwks create secret generic jwks-bridge-basic-auth \
    --from-literal=username="$BASIC_USER" --from-literal=password="$BASIC_PASSWORD" \
    --dry-run=client -o yaml | k apply -f -
  helm --kube-context "$CTX" upgrade --install jwks-bridge "$ROOT/deploy/helm/jwks-bridge" \
    -n jwks -f "$HERE/values/jwks-bridge.yaml" --wait --timeout 3m
}

deploy_kong() {
  log "Deploying Kong hybrid (1 control plane, 2 data planes)"
  : "${KONG_LICENSE_DATA:?KONG_LICENSE_DATA must hold a Kong Enterprise license}"
  k create namespace kong --dry-run=client -o yaml | k apply -f -
  k -n kong create secret generic kong-enterprise-license --from-literal=license="$KONG_LICENSE_DATA" \
    --dry-run=client -o yaml | k apply -f -
  k -n kong create secret tls kong-cluster-cert --cert="$WORK/cluster.crt" --key="$WORK/cluster.key" \
    --dry-run=client -o yaml | k apply -f -
  k -n kong create secret generic jwks-bridge-ca --from-file=ca.crt="$WORK/ca.crt" \
    --dry-run=client -o yaml | k apply -f -
  k apply -f "$HERE/manifests/postgres.yaml" -f "$HERE/manifests/httpbin.yaml"
  k -n kong rollout status deploy/postgres --timeout=180s
  k -n backend rollout status deploy/httpbin --timeout=180s

  helm repo add kong https://charts.konghq.com >/dev/null 2>&1 || true
  helm repo update kong >/dev/null
  helm --kube-context "$CTX" upgrade --install kong-cp kong/kong --version "$KONG_CHART_VERSION" \
    -n kong -f "$HERE/values/kong-cp.yaml" --wait --timeout 6m
  helm --kube-context "$CTX" upgrade --install kong-dp kong/kong --version "$KONG_CHART_VERSION" \
    -n kong -f "$HERE/values/kong-dp.yaml" --wait --timeout 6m
}

PF_PIDS=()
port_forward() { # name target local remote
  k -n "$1" port-forward "$2" "$3:$4" >/dev/null 2>&1 &
  PF_PIDS+=($!)
}
stop_port_forwards() {
  for p in "${PF_PIDS[@]:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null || true; done
}

wait_http() { # url [expected code]
  for _ in $(seq 1 60); do
    code=$(curl -s -o /dev/null -w '%{http_code}' "$1" || true)
    [[ "$code" == "${2:-200}" ]] && return 0
    sleep 2
  done
  echo "timeout waiting for $1 (last code $code)" >&2
  return 1
}

configure_kong() {
  log "Configuring Kong through the control plane Admin API"
  local admin="http://127.0.0.1:18001"
  wait_http "$admin/status"
  put() { curl -sf -X PUT "$admin/$1" -H 'Content-Type: application/json' -d "$2" >/dev/null; }

  put services/jwks-bridge-public '{"url":"http://jwks-bridge.jwks.svc:8080"}'
  put services/jwks-bridge-public/routes/jwks \
    '{"paths":["/.well-known/jwks.json"],"strip_path":false,"methods":["GET"],"protocols":["http","https"]}'
  put services/jwks-bridge-public/plugins/00000000-0000-4000-8000-000000000001 \
    '{"name":"proxy-cache","config":{"strategy":"memory","response_code":[200],"content_type":["application/jwk-set+json"],"cache_ttl":5}}'

  put services/echo '{"url":"http://httpbin.backend.svc:8080/headers"}'
  put services/echo/routes/echo '{"paths":["/echo"],"protocols":["http","https"]}'
  put services/echo/plugins/00000000-0000-4000-8000-000000000002 "$(cat <<JSON
{"name":"jwt-signer","config":{
  "access_token_issuer":"https://kong.e2e.test",
  "access_token_signing":true,
  "access_token_signing_algorithm":"RS256",
  "access_token_upstream_header":"Authorization:Bearer",
  "verify_access_token_signature":false,
  "channel_token_optional":true,
  "access_token_keyset":"https://jwks-bridge.jwks.svc:8443/keyset?name=default",
  "access_token_keyset_rotate_period":20,
  "access_token_endpoints_ssl_verify":true,
  "access_token_keyset_client_username":"$BASIC_USER",
  "access_token_keyset_client_password":"$BASIC_PASSWORD"
}}
JSON
)"
}

up() {
  create_cluster
  load_image
  gen_certs
  deploy_vault
  deploy_bridge
  deploy_kong
}

run_tests() {
  trap stop_port_forwards EXIT
  local dps dp1 dp2
  dps=$(k -n kong get pods -l app.kubernetes.io/instance=kong-dp -o jsonpath='{.items[*].metadata.name}')
  dp1=${dps%% *}
  dp2=${dps##* }
  port_forward kong svc/kong-cp-kong-admin 18001 8001
  port_forward kong "pod/$dp1" 18101 8000
  port_forward kong "pod/$dp2" 18102 8000
  port_forward vault svc/vault 18200 8200
  port_forward jwks svc/jwks-bridge-admin 18090 9090
  configure_kong

  log "Waiting for both data planes to serve the routes"
  wait_http "http://127.0.0.1:18101/.well-known/jwks.json"
  wait_http "http://127.0.0.1:18102/.well-known/jwks.json"

  log "Running Go e2e tests"
  cd "$ROOT"
  E2E_DP_URLS="http://127.0.0.1:18101,http://127.0.0.1:18102" \
  E2E_VAULT_ADDR="http://127.0.0.1:18200" E2E_VAULT_TOKEN=root \
  E2E_BRIDGE_ADMIN_URL="http://127.0.0.1:18090" \
  E2E_ROTATE_PERIOD=20s E2E_MIN_STAGE=10s \
    go test -tags e2e -count=1 -v -timeout 20m ./test/e2e/...
}

down() {
  if [[ -n "${E2E_KUBE_CONTEXT:-}" ]]; then
    log "Removing test namespaces from $CTX"
    helm --kube-context "$CTX" uninstall kong-dp kong-cp -n kong 2>/dev/null || true
    k delete namespace kong jwks vault backend --ignore-not-found --wait=false
    k delete clusterrolebinding vault-auth-delegator --ignore-not-found
  else
    log "Deleting kind cluster $CLUSTER"
    kind delete cluster --name "$CLUSTER"
  fi
}

case "${1:-all}" in
  up) up ;;
  configure)
    trap stop_port_forwards EXIT
    port_forward kong svc/kong-cp-kong-admin 18001 8001
    configure_kong
    ;;
  test) run_tests ;;
  down) down ;;
  all)
    up
    status=0
    (run_tests) || status=$?
    if [[ "${E2E_KEEP:-0}" != "1" ]]; then down; fi
    exit $status
    ;;
  *) echo "usage: $0 [all|up|configure|test|down]" >&2; exit 2 ;;
esac
