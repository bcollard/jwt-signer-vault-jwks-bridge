package keyset

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// Options control how a document is resolved.
type Options struct {
	// Now is the reference time for the staging guard.
	Now time.Time
	// MinStageDuration is the minimum time between staged_at and the moment a
	// key may be served first in the private keyset.
	MinStageDuration time.Duration
}

// Resolved is a validated document rendered into the two served JWK Sets.
type Resolved struct {
	// Private is the keyset served to Kong data planes, active keys first.
	Private []byte
	// Public is the JWKS served to backend applications, without private members.
	Public []byte
	// PrivateKids and PublicKids list the kids in the order they are served.
	PrivateKids []string
	PublicKids  []string
	// Counts holds the number of entries per status.
	Counts map[Status]int
	// Warnings lists non-fatal findings, for logging.
	Warnings []string
	// GuardedUntil is set when an active key is held back by the staging guard.
	// The document must be resolved again after that time.
	GuardedUntil time.Time
}

// ETag returns a strong entity tag for a body.
func ETag(body []byte) string {
	sum := sha256.Sum256(body)
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}

type parsedEntry struct {
	Entry
	key     jose.JSONWebKey
	members map[string]any
	private bool
	alg     string
}

// Resolve validates a document and renders the private keyset and public JWKS.
// It returns an error when the document must not be served.
func Resolve(doc *Document, opts Options) (*Resolved, error) {
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	if len(doc.Keys) == 0 {
		return nil, errors.New("keyset has no keys")
	}

	seen := map[string]bool{}
	entries := make([]*parsedEntry, 0, len(doc.Keys))
	var errs []error
	for i, e := range doc.Keys {
		pe, err := parseEntry(e)
		if err != nil {
			errs = append(errs, fmt.Errorf("keys[%d] (kid %q): %w", i, e.Kid, err))
			continue
		}
		if seen[pe.Kid] {
			errs = append(errs, fmt.Errorf("keys[%d]: duplicate kid %q", i, pe.Kid))
			continue
		}
		seen[pe.Kid] = true
		entries = append(entries, pe)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	res := &Resolved{Counts: map[Status]int{}}
	activeByAlg := map[string]*parsedEntry{}
	var retired, staged []*parsedEntry
	for _, pe := range entries {
		res.Counts[pe.Status]++
		switch pe.Status {
		case StatusActive:
			if prev, ok := activeByAlg[pe.alg]; ok {
				return nil, fmt.Errorf("more than one active key for alg %s: %q and %q", pe.alg, prev.Kid, pe.Kid)
			}
			activeByAlg[pe.alg] = pe
		case StatusRetired:
			retired = append(retired, pe)
		case StatusStaged:
			staged = append(staged, pe)
		}
	}
	if len(activeByAlg) == 0 {
		return nil, errors.New("keyset has no active key")
	}

	// Retired keys, most recently promoted first: the first one per alg is the
	// fallback used while a newly promoted key is held back by the guard.
	sort.SliceStable(retired, func(i, j int) bool {
		return timeOrZero(retired[i].PromotedAt).After(timeOrZero(retired[j].PromotedAt))
	})

	algs := make([]string, 0, len(activeByAlg))
	for alg := range activeByAlg {
		algs = append(algs, alg)
	}
	sort.Strings(algs)

	var first, held []*parsedEntry
	used := map[string]bool{}
	for _, alg := range algs {
		active := activeByAlg[alg]
		if until, guarded := guardUntil(active, opts); guarded {
			if fb := fallback(retired, alg); fb != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf(
					"active key %q was staged less than %s ago; serving %q first until %s",
					active.Kid, opts.MinStageDuration, fb.Kid, until.Format(time.RFC3339)))
				first = append(first, fb)
				used[fb.Kid] = true
				held = append(held, active)
				if res.GuardedUntil.IsZero() || until.Before(res.GuardedUntil) {
					res.GuardedUntil = until
				}
				continue
			}
			res.Warnings = append(res.Warnings, fmt.Sprintf(
				"active key %q was staged less than %s ago but no retired %s key exists; serving it",
				active.Kid, opts.MinStageDuration, alg))
		}
		first = append(first, active)
	}

	privateOrder := append([]*parsedEntry{}, first...)
	for _, pe := range retired {
		if !used[pe.Kid] {
			privateOrder = append(privateOrder, pe)
		}
	}
	privateOrder = append(privateOrder, held...)

	publicOrder := make([]*parsedEntry, 0, len(entries))
	publicOrder = append(publicOrder, privateOrder...)
	publicOrder = append(publicOrder, staged...)

	var err error
	privKeys := make([]map[string]any, 0, len(privateOrder))
	for _, pe := range privateOrder {
		if !pe.private {
			res.Warnings = append(res.Warnings, fmt.Sprintf("retired key %q has no private members; served as public only", pe.Kid))
		}
		privKeys = append(privKeys, pe.members)
		res.PrivateKids = append(res.PrivateKids, pe.Kid)
	}
	if res.Private, err = json.Marshal(map[string]any{"keys": privKeys}); err != nil {
		return nil, err
	}

	pubKeys := make([]map[string]any, 0, len(publicOrder))
	for _, pe := range publicOrder {
		pubKeys = append(pubKeys, PublicMembers(pe.members))
		res.PublicKids = append(res.PublicKids, pe.Kid)
	}
	if res.Public, err = json.Marshal(map[string]any{"keys": pubKeys}); err != nil {
		return nil, err
	}
	return res, nil
}

// PublicMembers returns a copy of a JWK member map without private members.
func PublicMembers(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	for _, k := range privateMembers {
		delete(out, k)
	}
	return out
}

func guardUntil(pe *parsedEntry, opts Options) (time.Time, bool) {
	if opts.MinStageDuration <= 0 || pe.StagedAt == nil {
		return time.Time{}, false
	}
	until := pe.StagedAt.Add(opts.MinStageDuration)
	return until, opts.Now.Before(until)
}

func fallback(retired []*parsedEntry, alg string) *parsedEntry {
	for _, pe := range retired {
		if pe.alg == alg && pe.private {
			return pe
		}
	}
	return nil
}

func timeOrZero(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

func parseEntry(e Entry) (*parsedEntry, error) {
	if e.Kid == "" {
		return nil, errors.New("empty kid")
	}
	switch e.Status {
	case StatusStaged, StatusActive, StatusRetired:
	default:
		return nil, fmt.Errorf("unknown status %q (want staged, active or retired)", e.Status)
	}
	if len(e.JWK) == 0 {
		return nil, errors.New("missing jwk")
	}

	var members map[string]any
	if err := json.Unmarshal(e.JWK, &members); err != nil {
		return nil, fmt.Errorf("decode jwk: %w", err)
	}
	var key jose.JSONWebKey
	if err := key.UnmarshalJSON(e.JWK); err != nil {
		return nil, fmt.Errorf("decode jwk: %w", err)
	}
	if key.KeyID != e.Kid {
		return nil, fmt.Errorf("jwk.kid %q does not match kid %q", key.KeyID, e.Kid)
	}
	if !algSupported(key.Algorithm) {
		return nil, fmt.Errorf("jwk.alg %q is not one of %s", key.Algorithm, strings.Join(SupportedAlgorithms, ", "))
	}
	if use, ok := members["use"]; ok && use != "sig" {
		return nil, fmt.Errorf("jwk.use is %q, want \"sig\"", use)
	}
	if err := checkKeyType(key); err != nil {
		return nil, err
	}

	pe := &parsedEntry{Entry: e, key: key, members: members, private: !key.IsPublic(), alg: key.Algorithm}
	if e.Status == StatusActive && !pe.private {
		return nil, errors.New("active key has no private members")
	}
	if pe.private {
		if err := checkPair(key); err != nil {
			return nil, err
		}
	}
	return pe, nil
}

func checkKeyType(key jose.JSONWebKey) error {
	alg := key.Algorithm
	switch k := key.Key.(type) {
	case *rsa.PrivateKey, *rsa.PublicKey:
		if !strings.HasPrefix(alg, "RS") && !strings.HasPrefix(alg, "PS") {
			return fmt.Errorf("RSA key cannot be used with alg %s", alg)
		}
		var n int
		if pk, ok := k.(*rsa.PrivateKey); ok {
			n = pk.N.BitLen()
		} else {
			n = k.(*rsa.PublicKey).N.BitLen()
		}
		if n < 2048 {
			return fmt.Errorf("RSA key is %d bits, want at least 2048", n)
		}
	case *ecdsa.PrivateKey, *ecdsa.PublicKey:
		var curve elliptic.Curve
		if pk, ok := k.(*ecdsa.PrivateKey); ok {
			curve = pk.Curve
		} else {
			curve = k.(*ecdsa.PublicKey).Curve
		}
		want := map[string]elliptic.Curve{"ES256": elliptic.P256(), "ES384": elliptic.P384(), "ES512": elliptic.P521()}[alg]
		if want == nil || want != curve {
			return fmt.Errorf("EC key on curve %s cannot be used with alg %s", curve.Params().Name, alg)
		}
	case ed25519.PrivateKey, ed25519.PublicKey:
		if alg != "EdDSA" {
			return fmt.Errorf("Ed25519 key cannot be used with alg %s", alg)
		}
	default:
		return fmt.Errorf("unsupported key type %T", key.Key)
	}
	return nil
}

// checkPair signs a probe with the private key and verifies it with the public
// members, which catches a private key paired with the wrong public key.
func checkPair(key jose.JSONWebKey) error {
	if !key.Valid() {
		return errors.New("invalid private key")
	}
	if pk, ok := key.Key.(*rsa.PrivateKey); ok {
		if err := pk.Validate(); err != nil {
			return fmt.Errorf("invalid RSA private key: %w", err)
		}
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(key.Algorithm), Key: key.Key}, nil)
	if err != nil {
		return fmt.Errorf("build signer: %w", err)
	}
	probe := []byte("jwks-bridge key pair check")
	jws, err := signer.Sign(probe)
	if err != nil {
		return fmt.Errorf("sign probe: %w", err)
	}
	if _, err := jws.Verify(publicKeyOf(key)); err != nil {
		return errors.New("private key does not match public members")
	}
	return nil
}

// publicKeyOf returns the public key described by the JWK's public members,
// not the one derived from the private key.
func publicKeyOf(key jose.JSONWebKey) crypto.PublicKey {
	switch k := key.Key.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public()
	}
	return nil
}
