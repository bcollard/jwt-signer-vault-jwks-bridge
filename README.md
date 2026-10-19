# jwks-bridge

[![CI](https://github.com/bcollard/jwt-signer-vault-jwks-bridge/actions/workflows/ci.yml/badge.svg)](https://github.com/bcollard/jwt-signer-vault-jwks-bridge/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-bcollard.github.io-3a46c4)](https://bcollard.github.io/jwt-signer-vault-jwks-bridge/)

Serve signing keys stored in HashiCorp Vault to the Kong Gateway Enterprise `jwt-signer` plugin, and publish the public JWKS through Kong for backend applications.

In hybrid mode (and Konnect) data planes have no database, so the plugin's default `kong` keyset is a different key pair on every data plane, and there is no public JWKS endpoint. `jwks-bridge` gives every data plane the same Vault-managed key through the `access_token_keyset` URL.

| Document | Consumer | Endpoint |
|---|---|---|
| Keyset, with private members | Kong data planes (`access_token_keyset`) | `https://jwks-bridge:8443/keyset?name=default` (mTLS or Basic auth) |
| Public JWKS | Backends, through a Kong Route | `http://jwks-bridge:8080/.well-known/jwks.json` |
| Metrics | Prometheus | `http://jwks-bridge:9090/metrics` |

Documentation: https://bcollard.github.io/jwt-signer-vault-jwks-bridge/

## Features

- Vault KV v2 source with Kubernetes, AppRole or token auth; file source for local use.
- In-memory snapshots with stale-if-error: Vault outages do not stop signing.
- Staged key rotation (`staged` → `active` → `retired` → removed) with a staging guard.
- Strict validation of every Vault write; a bad document never replaces a good one.
- Prometheus metrics and OpenTelemetry tracing with W3C `traceparent` propagation.
- Helm chart, distroless non-root image, `keygen` and `validate` commands.

## Install

```sh
brew tap bcollard/jwks-bridge
brew install --cask jwks-bridge
```

Container image: `ghcr.io/bcollard/jwks-bridge`. Helm chart: `oci://ghcr.io/bcollard/charts/jwks-bridge`.

## Quick start

```sh
mkdir -p keys
jwks-bridge keygen --alg RS256 --kid k1 --status active --doc > keys/default.json
printf 'local-password' > keys/password

jwks-bridge serve --source file --file-dir ./keys --keysets default=default.json \
  --private-insecure-plaintext --basic-user kong --basic-password-file ./keys/password

curl -s localhost:8080/.well-known/jwks.json
curl -s -u kong:local-password localhost:8443/keyset
```

`--private-insecure-plaintext` is for local development only. In production the private listener requires TLS.

## Kong configuration

```yaml
plugins:
  - name: jwt-signer
    config:
      access_token_signing: true
      access_token_signing_algorithm: RS256
      access_token_keyset: https://jwks-bridge.jwks.svc:8443/keyset?name=default
      access_token_keyset_rotate_period: 300
      access_token_endpoints_ssl_verify: true
      access_token_keyset_client_username: "{vault://env/jwks-bridge-user}"
      access_token_keyset_client_password: "{vault://env/jwks-bridge-pass}"
```

Full decK file: [`examples/kong/kong.yaml`](examples/kong/kong.yaml).

## Examples

| Path | Content |
|---|---|
| [`examples/local`](examples/local) | Run the bridge locally with a generated key |
| [`examples/vault`](examples/vault) | Vault policy, Kubernetes auth setup, rotation script |
| [`examples/kubernetes`](examples/kubernetes) | Production Helm values, cert-manager Certificate |
| [`examples/kong`](examples/kong) | decK configuration, Kong data plane chart values |

## Development

```sh
make test        # unit tests with -race
make lint        # go vet + golangci-lint
make helm-lint
make e2e         # kind + Vault + jwks-bridge + Kong hybrid (1 CP, 2 DPs); needs KONG_LICENSE_DATA
python3 scripts/site.py   # regenerate shared parts of the docs site and validate links
```

The end-to-end test runs a full key rotation under traffic through two data planes and fails on any verification error. To run it on an existing cluster, set `E2E_KUBE_CONTEXT` and `E2E_LOAD_IMAGE`; see [`test/e2e/run.sh`](test/e2e/run.sh). After `run.sh up`, [`test/e2e/demo.sh`](test/e2e/demo.sh) walks through the same flow step by step for a live demo.

Design notes: [`DESIGN.md`](DESIGN.md).

## License

MIT
