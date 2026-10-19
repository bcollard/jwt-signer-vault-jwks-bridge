#!/usr/bin/env bash
# Staged key rotation for one keyset stored in Vault KV v2.
#
#   rotate.sh stage   [alg]   add a new staged key (public JWKS only)
#   rotate.sh promote <kid>   make <kid> active and retire the current active key
#   rotate.sh remove  <kid>   delete a retired key
#   rotate.sh show            print kid, status and timestamps
#
# Respect the waits between steps; see the rotation guide.
set -euo pipefail
PATH_KV="${KEYSET_PATH:-secret/jwks-bridge/default}"

read_keys() { vault kv get -field=keys "$PATH_KV"; }
# Compute the new value fully before writing, so a failed jq never writes an empty value.
update() { local v; v=$(read_keys | jq -ce "$@") && vault kv put "$PATH_KV" keys="$v" >/dev/null; }

case "${1:-show}" in
  stage)
    new=$(jwks-bridge keygen --alg "${2:-RS256}" --status staged)
    update --argjson n "$new" '. + [$n]'
    echo "staged $(jq -r .kid <<<"$new")"
    ;;
  promote)
    kid="${2:?kid}"
    now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    update --arg kid "$kid" --arg now "$now" '
      (map(select(.kid == $kid))[0].jwk.alg) as $alg
      | map(if .kid == $kid then .status = "active" | .promoted_at = $now
            elif .status == "active" and .jwk.alg == $alg then .status = "retired"
            else . end)'
    echo "promoted $kid"
    ;;
  remove)
    kid="${2:?kid}"
    update --arg kid "$kid" '
      if any(.[]; .kid == $kid and .status == "active") then error("refusing to remove the active key")
      else map(select(.kid != $kid)) end'
    echo "removed $kid"
    ;;
  show)
    read_keys | jq -r '.[] | [.kid, .status, (.jwk.alg), (.staged_at // "-"), (.promoted_at // "-")] | @tsv' \
      | column -t
    ;;
  *) sed -n '2,10p' "$0"; exit 2 ;;
esac
