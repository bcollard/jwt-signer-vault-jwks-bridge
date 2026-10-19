#!/usr/bin/env bash
# Run jwks-bridge locally with the file source and a freshly generated key.
# Private listener in plain HTTP with Basic auth: local development only.
set -euo pipefail
cd "$(dirname "$0")"
BIN="${BIN:-../../bin/jwks-bridge}"
command -v jwks-bridge >/dev/null && [[ ! -x "$BIN" ]] && BIN=jwks-bridge

mkdir -p keys
if [[ ! -f keys/default.json ]]; then
  "$BIN" keygen --alg RS256 --kid local-k1 --status active --doc > keys/default.json
fi
printf 'local-password' > keys/basic-password

export JWKSB_SOURCE=file
export JWKSB_FILE_DIR="$PWD/keys"
export JWKSB_KEYSETS=default=default.json
export JWKSB_PRIVATE_INSECURE_PLAINTEXT=true
export JWKSB_BASIC_USER=kong
export JWKSB_BASIC_PASSWORD_FILE="$PWD/keys/basic-password"
export JWKSB_REFRESH_INTERVAL=5s
export JWKSB_MIN_STAGE_DURATION=10s
export JWKSB_LOG_FORMAT=text

cat <<MSG
Public JWKS:  curl -s localhost:8080/.well-known/jwks.json | jq
Keyset:       curl -s -u kong:local-password localhost:8443/keyset | jq
Metrics:      curl -s localhost:9090/metrics | grep jwksbridge_
Edit keys/default.json to stage, promote or retire keys; changes load within 5 s.
MSG
exec "$BIN" serve
