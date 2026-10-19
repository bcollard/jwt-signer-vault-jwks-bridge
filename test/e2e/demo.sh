#!/usr/bin/env bash
# Guided demo on the e2e environment: two Kong data planes sign upstream
# tokens with one key held in Vault, then a staged rotation under load.
#
# Prerequisite: test/e2e/run.sh up
# Usage:        test/e2e/demo.sh              pause before each step
#               DEMO_AUTO=1 test/e2e/demo.sh  run without pauses
# Environment:  E2E_KUBE_CONTEXT, E2E_CLUSTER  same meaning as for run.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$ROOT/test/e2e"
WORK="$HERE/.work"
CTX="${E2E_KUBE_CONTEXT:-kind-${E2E_CLUSTER:-jwks-bridge-e2e}}"
ROTATE_PERIOD=20 # access_token_keyset_rotate_period, set by run.sh
MIN_STAGE=10     # config.minStageDuration in values/jwks-bridge.yaml
DP1=http://127.0.0.1:18101
DP2=http://127.0.0.1:18102
BRIDGE_HOST=jwks-bridge.jwks.svc
ROTATE=examples/vault/rotate.sh
CA=test/e2e/.work/ca.crt

export VAULT_ADDR=http://127.0.0.1:18200 VAULT_TOKEN=root
export PATH="$WORK/bin:$PATH"

k() { kubectl --context "$CTX" "$@"; }
bold() { printf '\033[1m%s\033[0m\n' "$*"; }
step() {
  printf '\n\033[1;34m== %s\033[0m\n' "$1"
  shift
  for line in "$@"; do printf '   %s\n' "$line"; done
  [[ "${DEMO_AUTO:-0}" == "1" ]] || read -r -p $'\033[2m   press Enter\033[0m ' _
}
run() { # command string, printed then evaluated
  printf '\033[2m$ %s\033[0m\n' "$*"
  eval "$*"
}
countdown() { # seconds reason
  for ((s = $1; s > 0; s--)); do printf '\r   %s: %2ss ' "$2" "$s"; sleep 1; done
  printf '\r\033[K'
}

PF_PIDS=()
LOAD_PID=""
cleanup() {
  [[ -n "$LOAD_PID" ]] && kill "$LOAD_PID" 2>/dev/null || true
  for p in "${PF_PIDS[@]:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null || true; done
}
trap cleanup EXIT
port_forward() { # namespace target local remote
  # kubectl itself, not the k function: $! must be the process to kill
  kubectl --context "$CTX" -n "$1" port-forward "$2" "$3:$4" >/dev/null 2>&1 &
  PF_PIDS+=($!)
}

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
b64url_decode() {
  local s
  s=$(tr -- '-_' '+/' <<<"$1")
  while (($(printf %s "$s" | wc -c) % 4)); do s="$s="; done
  printf %s "$s" | openssl base64 -d -A
}

# The inbound token the client sends. verify_access_token_signature is off in
# the demo, so any well-formed RS256 JWT works.
inbound_token() {
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$WORK/client.key" 2>/dev/null
  local now header payload sig
  now=$(date +%s)
  header=$(printf '{"alg":"RS256","typ":"JWT"}' | b64url)
  payload=$(printf '{"sub":"demo-client","iss":"https://idp.demo.test","iat":%d,"exp":%d}' "$now" $((now + 3600)) | b64url)
  sig=$(printf '%s.%s' "$header" "$payload" | openssl dgst -sha256 -sign "$WORK/client.key" -binary | b64url)
  printf '%s.%s.%s' "$header" "$payload" "$sig"
}

# Calls /echo on a data plane and prints the token the upstream received.
upstream_token() {
  curl -sf "$1/echo" -H "Authorization: Bearer $INBOUND" \
    | jq -r '.headers.Authorization[0] // empty' | sed 's/^Bearer //'
}
upstream_kid() { b64url_decode "$(upstream_token "$1" | cut -d. -f1)" | jq -r .kid; }
public_kids() { curl -sf "$DP1/.well-known/jwks.json" | jq -c '[.keys[].kid]'; }
active_kid() { vault kv get -field=keys secret/jwks-bridge/default | jq -r '.[] | select(.status == "active") | .kid'; }

show_signers() {
  printf '   DP1 signs with kid=%s\n' "$(upstream_kid "$DP1")"
  printf '   DP2 signs with kid=%s\n' "$(upstream_kid "$DP2")"
  printf '   public JWKS kids: %s\n' "$(public_kids)"
}

# ---------------------------------------------------------------------------

cd "$ROOT" # commands are printed with paths relative to the repository
bold "jwks-bridge demo on context $CTX"
mkdir -p "$WORK/bin"
go build -o "$WORK/bin/jwks-bridge" ./cmd/jwks-bridge

port_forward vault svc/vault 18200 8200
port_forward jwks svc/jwks-bridge 18080 8080
port_forward jwks svc/jwks-bridge 18443 8443
port_forward jwks svc/jwks-bridge-admin 18090 9090
dps=$(k -n kong get pods -l app.kubernetes.io/instance=kong-dp -o jsonpath='{.items[*].metadata.name}')
port_forward kong "pod/${dps%% *}" 18101 8000
port_forward kong "pod/${dps##* }" 18102 8000
E2E_KUBE_CONTEXT="$CTX" "$HERE/run.sh" configure >/dev/null
for url in "$VAULT_ADDR/v1/sys/health" "$DP1/.well-known/jwks.json" "$DP2/.well-known/jwks.json" http://127.0.0.1:18090/readyz; do
  for i in $(seq 1 60); do curl -sf -o /dev/null "$url" && break; sleep 1; done
  ((i < 60)) || { echo "no answer from $url; is the port already in use?" >&2; exit 1; }
done
INBOUND=$(inbound_token)

step "The setup" \
  "Vault holds the keyset. Two jwks-bridge replicas read it." \
  "One Kong control plane and two data planes (DP1, DP2) with no database." \
  "jwt-signer on route /echo re-signs every request with the key from the bridge."
run "k get deploy -A | awk 'NR == 1 || \$1 ~ /^(vault|jwks|kong|backend)\$/' | sed 's/^/   /'"

step "The keyset in Vault" \
  "One document at secret/jwks-bridge/default. Each key has a kid and a status."
run "$ROTATE show"

step "Kong reads the private keyset" \
  "The bridge private listener needs TLS plus mTLS or Basic auth." \
  "Without credentials:"
run "curl -s -o /dev/null -w '   HTTP %{http_code}\n' --cacert $CA --resolve $BRIDGE_HOST:18443:127.0.0.1 'https://$BRIDGE_HOST:18443/keyset?name=default'"
echo "   With Kong's credentials (private members present):"
run "curl -s --cacert $CA --resolve $BRIDGE_HOST:18443:127.0.0.1 -u kong:e2e-password 'https://$BRIDGE_HOST:18443/keyset?name=default' | jq -c '.keys[] | {kid, alg, private_key_present: has(\"d\")}'"

step "Backends read the public JWKS" \
  "Same keys, public members only. Kong serves it on /.well-known/jwks.json."
run "curl -s $DP1/.well-known/jwks.json | jq -c '.keys[] | {kid, alg, private_key_present: has(\"d\")}'"

step "Both data planes sign with the same key" \
  "A request through each data plane. httpbin echoes the token Kong sent upstream."
run "upstream_token $DP1 | cut -d. -f1-2 | tr . '\n' | while read -r p; do b64url_decode \"\$p\" | jq -c .; done"
show_signers

OLD=$(active_kid)
LOG="$WORK/demo-load.log"
: >"$LOG"
step "Rotation under load" \
  "A client now calls both data planes every 200 ms and records the signing kid." \
  "Current active key: $OLD"
(
  while true; do
    for dp in "$DP1" "$DP2"; do
      kid=$(upstream_kid "$dp" 2>/dev/null || true)
      printf '%s %s\n' "${dp##*:}" "${kid:-FAIL}" >>"$LOG"
    done
    sleep 0.2
  done
) &
LOAD_PID=$!

step "Stage a new key" \
  "A staged key is published in the public JWKS so backends can cache it." \
  "Kong does not sign with it yet."
NEW=$($ROTATE stage | awk '{print $2}')
echo "   staged $NEW"
run "$ROTATE show"
countdown 5 "waiting for the bridge refresh"
show_signers

step "Promote it" \
  "The bridge keeps signing with $OLD until $NEW has been staged ${MIN_STAGE}s (min_stage_duration)." \
  "Each data plane picks the new key on its own ${ROTATE_PERIOD}s reload timer."
run "$ROTATE promote $NEW"
run "$ROTATE show"
countdown $((MIN_STAGE + ROTATE_PERIOD + 5)) "waiting for both data planes to reload"
show_signers

step "Remove the retired key" \
  "In production, wait for the longest token lifetime first. $OLD stayed in the public JWKS until now."
run "$ROTATE remove $OLD"
countdown 5 "waiting for the bridge refresh"
show_signers
kill "$LOAD_PID" 2>/dev/null || true
LOAD_PID=""

step "What the client saw" \
  "Requests per data plane and signing kid, in the order they occurred."
total=$(wc -l <"$LOG" | tr -d ' ')
fails=$(grep -c ' FAIL$' "$LOG" || true)
awk '{dp = ($1 == "18101") ? "DP1" : "DP2"; n[dp" "$2]++} END {for (key in n) printf "   %s  %d requests\n", key, n[key]}' "$LOG" | sort
printf '   total %s requests, %s failed\n' "$total" "$fails"

step "Prometheus metrics" "Admin listener, port 9090."
run "curl -s http://127.0.0.1:18090/metrics | grep -E '^jwksbridge_(keys|refresh_total|snapshot_age_seconds|source_errors_total|build_info)' | sed 's/^/   /'"

step "W3C trace context" \
  "A request with a traceparent header. The bridge continues the trace and logs its id."
TRACE_ID=$(openssl rand -hex 16)
run "curl -s -o /dev/null -w '   HTTP %{http_code}\n' -H 'traceparent: 00-$TRACE_ID-$(openssl rand -hex 8)-01' http://127.0.0.1:18080/jwks.json"
sleep 1
run "k -n jwks logs -l app.kubernetes.io/name=jwks-bridge --since=1m --prefix | grep $TRACE_ID | sed 's/^/   /'"

bold $'\nDemo complete.'
