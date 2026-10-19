// Package keyset parses, validates and renders the keyset documents stored in
// the secret store.
//
// A stored document looks like:
//
//	{"keys": [{"kid": "k1", "status": "active", "staged_at": "...", "promoted_at": "...", "jwk": {...}}]}
//
// From it the package renders two JWK Sets: the private keyset fetched by Kong
// data planes, and the public JWKS fetched by backend applications.
package keyset

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Status is the lifecycle state of a key.
type Status string

const (
	StatusStaged  Status = "staged"
	StatusActive  Status = "active"
	StatusRetired Status = "retired"
)

// Entry is one key in the stored document.
type Entry struct {
	Kid        string          `json:"kid"`
	Status     Status          `json:"status"`
	StagedAt   *time.Time      `json:"staged_at,omitempty"`
	PromotedAt *time.Time      `json:"promoted_at,omitempty"`
	JWK        json.RawMessage `json:"jwk"`
}

// Document is the stored keyset.
type Document struct {
	Keys []Entry `json:"keys"`
}

// Parse decodes a stored document. It does not validate it; see Resolve.
func Parse(raw []byte) (*Document, error) {
	var doc Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("decode keyset: %w", err)
	}
	if doc.Keys == nil {
		return nil, errors.New("decode keyset: missing \"keys\" array")
	}
	return &doc, nil
}

// SupportedAlgorithms lists the asymmetric algorithms accepted by the
// jwt-signer plugin's access_token_signing_algorithm field.
var SupportedAlgorithms = []string{
	"RS256", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA",
}

func algSupported(alg string) bool {
	for _, a := range SupportedAlgorithms {
		if a == alg {
			return true
		}
	}
	return false
}

// privateMembers are the JWK members removed when deriving a public key.
var privateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
