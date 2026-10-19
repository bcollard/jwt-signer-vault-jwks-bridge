# Read-only access to the jwks-bridge keysets. Nothing else.
path "secret/data/jwks-bridge/*" {
  capabilities = ["read"]
}
path "secret/metadata/jwks-bridge/*" {
  capabilities = ["read"]
}
