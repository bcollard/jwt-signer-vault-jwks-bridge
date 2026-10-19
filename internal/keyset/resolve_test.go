package keyset_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bcollard/jwt-signer-vault-jwks-bridge/internal/keygen"
	"github.com/bcollard/jwt-signer-vault-jwks-bridge/internal/keyset"
)

var now = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

func gen(t *testing.T, alg, kid string, status keyset.Status) keyset.Entry {
	t.Helper()
	e, err := keygen.Generate(keygen.Options{Alg: alg, Kid: kid, Status: status, Now: now.Add(-24 * time.Hour)})
	if err != nil {
		t.Fatalf("generate %s: %v", alg, err)
	}
	return e
}

func resolve(t *testing.T, opts keyset.Options, entries ...keyset.Entry) *keyset.Resolved {
	t.Helper()
	if opts.Now.IsZero() {
		opts.Now = now
	}
	res, err := keyset.Resolve(&keyset.Document{Keys: entries}, opts)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	return res
}

func keysOf(t *testing.T, body []byte) []map[string]any {
	t.Helper()
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return doc.Keys
}

func TestResolveAllAlgorithms(t *testing.T) {
	for _, alg := range keyset.SupportedAlgorithms {
		t.Run(alg, func(t *testing.T) {
			res := resolve(t, keyset.Options{}, gen(t, alg, "k1", keyset.StatusActive))
			if got := res.PrivateKids; len(got) != 1 || got[0] != "k1" {
				t.Fatalf("private kids = %v", got)
			}
		})
	}
}

func TestPublicNeverLeaksPrivateMembers(t *testing.T) {
	res := resolve(t, keyset.Options{},
		gen(t, "RS256", "rsa", keyset.StatusActive),
		gen(t, "ES256", "ec", keyset.StatusActive),
		gen(t, "EdDSA", "ed", keyset.StatusActive),
		gen(t, "PS256", "ps-staged", keyset.StatusStaged),
		gen(t, "RS256", "rsa-old", keyset.StatusRetired),
	)
	for _, k := range keysOf(t, res.Public) {
		for _, m := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
			if _, ok := k[m]; ok {
				t.Errorf("public key %v has private member %q", k["kid"], m)
			}
		}
	}
	for _, k := range keysOf(t, res.Private) {
		if _, ok := k["d"]; !ok {
			t.Errorf("private key %v has no d", k["kid"])
		}
	}
}

func TestOrdering(t *testing.T) {
	retiredOld := gen(t, "RS256", "k0", keyset.StatusRetired)
	p0 := now.Add(-48 * time.Hour)
	retiredOld.PromotedAt = &p0
	retiredNew := gen(t, "RS256", "k1", keyset.StatusRetired)
	p1 := now.Add(-2 * time.Hour)
	retiredNew.PromotedAt = &p1

	res := resolve(t, keyset.Options{},
		retiredOld,
		gen(t, "RS256", "k3", keyset.StatusStaged),
		retiredNew,
		gen(t, "RS256", "k2", keyset.StatusActive),
	)
	if got, want := strings.Join(res.PrivateKids, ","), "k2,k1,k0"; got != want {
		t.Errorf("private order = %s, want %s", got, want)
	}
	if got, want := strings.Join(res.PublicKids, ","), "k2,k1,k0,k3"; got != want {
		t.Errorf("public order = %s, want %s", got, want)
	}
	if res.Counts[keyset.StatusRetired] != 2 || res.Counts[keyset.StatusStaged] != 1 || res.Counts[keyset.StatusActive] != 1 {
		t.Errorf("counts = %v", res.Counts)
	}
}

func TestStagingGuard(t *testing.T) {
	k1 := gen(t, "RS256", "k1", keyset.StatusRetired)
	k2 := gen(t, "RS256", "k2", keyset.StatusActive)
	staged := now.Add(-5 * time.Minute)
	k2.StagedAt = &staged
	opts := keyset.Options{MinStageDuration: 10 * time.Minute}

	res := resolve(t, opts, k1, k2)
	if got := strings.Join(res.PrivateKids, ","); got != "k1,k2" {
		t.Errorf("guarded private order = %s, want k1,k2", got)
	}
	if want := staged.Add(10 * time.Minute); !res.GuardedUntil.Equal(want) {
		t.Errorf("GuardedUntil = %s, want %s", res.GuardedUntil, want)
	}
	if len(res.Warnings) == 0 {
		t.Error("expected a warning")
	}

	opts.Now = now.Add(6 * time.Minute)
	res = resolve(t, opts, k1, k2)
	if got := strings.Join(res.PrivateKids, ","); got != "k2,k1" {
		t.Errorf("released private order = %s, want k2,k1", got)
	}

	// Without a retired key the active key is served anyway.
	opts.Now = now
	res = resolve(t, opts, k2)
	if got := strings.Join(res.PrivateKids, ","); got != "k2" {
		t.Errorf("first key order = %s", got)
	}
}

func TestValidationErrors(t *testing.T) {
	a := gen(t, "RS256", "a", keyset.StatusActive)
	b := gen(t, "RS256", "b", keyset.StatusActive)
	other := gen(t, "RS256", "other", keyset.StatusActive)

	mismatched := a
	mismatched.Kid = "not-a"

	var m map[string]any
	_ = json.Unmarshal(a.JWK, &m)
	var om map[string]any
	_ = json.Unmarshal(other.JWK, &om)
	m["n"] = om["n"]
	wrongPair := a
	wrongPair.JWK, _ = json.Marshal(m)

	pub := map[string]any{}
	_ = json.Unmarshal(a.JWK, &pub)
	pub = keyset.PublicMembers(pub)
	publicActive := a
	publicActive.JWK, _ = json.Marshal(pub)

	hs := keyset.Entry{Kid: "hs", Status: keyset.StatusActive, JWK: json.RawMessage(`{"kty":"oct","kid":"hs","alg":"HS256","k":"c2VjcmV0"}`)}
	badStatus := a
	badStatus.Status = "pending"

	cases := map[string][]keyset.Entry{
		"empty":              {},
		"two active":         {a, b},
		"no active":          {gen(t, "RS256", "s", keyset.StatusStaged)},
		"kid mismatch":       {mismatched},
		"duplicate kid":      {a, a},
		"wrong pair":         {wrongPair},
		"public active":      {publicActive},
		"symmetric":          {hs},
		"unknown status":     {badStatus},
		"alg vs key type":    {withAlg(t, gen(t, "ES256", "e", keyset.StatusActive), "RS256")},
		"curve vs alg":       {withAlg(t, gen(t, "ES256", "e", keyset.StatusActive), "ES384")},
		"rsa used for eddsa": {withAlg(t, a, "EdDSA")},
	}
	for name, entries := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := keyset.Resolve(&keyset.Document{Keys: entries}, keyset.Options{Now: now}); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func withAlg(t *testing.T, e keyset.Entry, alg string) keyset.Entry {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(e.JWK, &m); err != nil {
		t.Fatal(err)
	}
	m["alg"] = alg
	e.JWK, _ = json.Marshal(m)
	return e
}

func TestParse(t *testing.T) {
	if _, err := keyset.Parse([]byte(`{"foo":1}`)); err == nil {
		t.Error("missing keys should fail")
	}
	if _, err := keyset.Parse([]byte(`not json`)); err == nil {
		t.Error("invalid json should fail")
	}
	doc, err := keyset.Parse([]byte(`{"keys":[]}`))
	if err != nil || len(doc.Keys) != 0 {
		t.Errorf("parse empty = %v, %v", doc, err)
	}
}

func TestETagStable(t *testing.T) {
	a1, a2, b := keyset.ETag([]byte("a")), keyset.ETag([]byte("a")), keyset.ETag([]byte("b"))
	if a1 != a2 || a1 == b {
		t.Error("ETag is not a function of the body")
	}
}
