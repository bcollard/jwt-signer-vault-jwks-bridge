// Package keygen generates signing key pairs as keyset entries.
package keygen

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/bcollard/jwt-signer-vault-jwks-bridge/internal/keyset"
)

// Options describe the key to generate.
type Options struct {
	Alg     string
	Kid     string
	Status  keyset.Status
	RSABits int
	Now     time.Time
}

// Generate creates a key pair and returns it as a keyset entry. staged_at is
// set for staged keys and promoted_at for active keys.
func Generate(opts Options) (keyset.Entry, error) {
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	if opts.Status == "" {
		opts.Status = keyset.StatusStaged
	}
	if opts.Kid == "" {
		opts.Kid = opts.Now.Format("20060102T150405Z")
	}
	if opts.RSABits == 0 {
		opts.RSABits = 2048
	}

	var key crypto.Signer
	var err error
	switch opts.Alg {
	case "RS256", "RS512", "PS256", "PS384", "PS512":
		if opts.RSABits < 2048 {
			return keyset.Entry{}, fmt.Errorf("RSA key size %d is below 2048", opts.RSABits)
		}
		key, err = rsa.GenerateKey(rand.Reader, opts.RSABits)
	case "ES256":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ES384":
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "ES512":
		key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case "EdDSA":
		_, key, err = ed25519.GenerateKey(rand.Reader)
	default:
		return keyset.Entry{}, fmt.Errorf("unsupported alg %q", opts.Alg)
	}
	if err != nil {
		return keyset.Entry{}, err
	}

	jwk := jose.JSONWebKey{Key: key, KeyID: opts.Kid, Algorithm: opts.Alg, Use: "sig"}
	raw, err := jwk.MarshalJSON()
	if err != nil {
		return keyset.Entry{}, err
	}

	now := opts.Now
	e := keyset.Entry{Kid: opts.Kid, Status: opts.Status, JWK: json.RawMessage(raw)}
	switch opts.Status {
	case keyset.StatusStaged:
		e.StagedAt = &now
	case keyset.StatusActive:
		e.PromotedAt = &now
	}
	return e, nil
}
