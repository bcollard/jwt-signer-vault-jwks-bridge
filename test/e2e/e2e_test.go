//go:build e2e

// Package e2e runs against the environment deployed by run.sh: Vault,
// jwks-bridge and Kong Gateway Enterprise in hybrid mode with two data planes.
package e2e

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	vault "github.com/hashicorp/vault/api"

	"github.com/bcollard/jwt-signer-vault-jwks-bridge/internal/keygen"
	"github.com/bcollard/jwt-signer-vault-jwks-bridge/internal/keyset"
)

const (
	vaultMount = "secret"
	vaultPath  = "jwks-bridge/default"
	issuer     = "https://kong.e2e.test"
	// backendJWKSTTL simulates how long a backend caches the JWKS.
	backendJWKSTTL = 5 * time.Second
)

type env struct {
	dps          []string
	vault        *vault.Client
	bridgeAdmin  string
	rotatePeriod time.Duration
	minStage     time.Duration
	inbound      string
}

func setup(t *testing.T) *env {
	t.Helper()
	dps := os.Getenv("E2E_DP_URLS")
	if dps == "" {
		t.Skip("E2E_DP_URLS not set; run test/e2e/run.sh")
	}
	cfg := vault.DefaultConfig()
	cfg.Address = os.Getenv("E2E_VAULT_ADDR")
	vc, err := vault.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	vc.SetToken(os.Getenv("E2E_VAULT_TOKEN"))
	e := &env{
		dps:          strings.Split(dps, ","),
		vault:        vc,
		bridgeAdmin:  os.Getenv("E2E_BRIDGE_ADMIN_URL"),
		rotatePeriod: mustDuration(t, "E2E_ROTATE_PERIOD"),
		minStage:     mustDuration(t, "E2E_MIN_STAGE"),
	}
	e.inbound = inboundToken(t)
	return e
}

func mustDuration(t *testing.T, key string) time.Duration {
	d, err := time.ParseDuration(os.Getenv(key))
	if err != nil {
		t.Fatalf("%s: %v", key, err)
	}
	return d
}

// inboundToken returns a client token. The plugin is configured not to verify
// its signature, so any key will do.
func inboundToken(t *testing.T) string {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.Signed(signer).Claims(jwt.Claims{
		Subject: "e2e-client", Issuer: "https://idp.e2e.test",
		Expiry: jwt.NewNumericDate(time.Now().Add(time.Hour)), IssuedAt: jwt.NewNumericDate(time.Now()),
	}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

var client = &http.Client{Timeout: 5 * time.Second}

// signedToken sends a request through a data plane and returns the token Kong
// passed upstream.
func (e *env) signedToken(dp string) (string, error) {
	req, _ := http.NewRequest(http.MethodGet, dp+"/echo", nil)
	req.Header.Set("Authorization", "Bearer "+e.inbound)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s/echo: %d %s", dp, resp.StatusCode, body)
	}
	var echo struct {
		Headers map[string][]string `json:"headers"`
	}
	if err := json.Unmarshal(body, &echo); err != nil {
		return "", err
	}
	auth := echo.Headers["Authorization"]
	if len(auth) == 0 || !strings.HasPrefix(auth[0], "Bearer ") {
		return "", fmt.Errorf("no bearer token upstream: %v", echo.Headers)
	}
	return strings.TrimPrefix(auth[0], "Bearer "), nil
}

func fetchJWKS(dp string) (*jose.JSONWebKeySet, error) {
	resp, err := client.Get(dp + "/.well-known/jwks.json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks: %d", resp.StatusCode)
	}
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, err
	}
	for _, k := range set.Keys {
		if !k.IsPublic() {
			return nil, fmt.Errorf("public JWKS contains private key %s", k.KeyID)
		}
	}
	return &set, nil
}

// verify checks a token signature against a JWKS and returns its kid.
func verify(token string, set *jose.JSONWebKeySet) (string, error) {
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return "", err
	}
	kid := parsed.Headers[0].KeyID
	keys := set.Key(kid)
	if len(keys) == 0 {
		return kid, fmt.Errorf("kid %q not in JWKS", kid)
	}
	var claims jwt.Claims
	if err := parsed.Claims(keys[0].Key, &claims); err != nil {
		return kid, fmt.Errorf("signature: %w", err)
	}
	if claims.Issuer != issuer {
		return kid, fmt.Errorf("iss = %q, want %q", claims.Issuer, issuer)
	}
	return kid, nil
}

func (e *env) readEntries(t *testing.T) []keyset.Entry {
	t.Helper()
	sec, err := e.vault.KVv2(vaultMount).Get(context.Background(), vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	var raw []byte
	switch v := sec.Data["keys"].(type) {
	case string:
		raw = []byte(v)
	default:
		raw, _ = json.Marshal(v)
	}
	var entries []keyset.Entry
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatal(err)
	}
	return entries
}

func (e *env) writeEntries(t *testing.T, entries []keyset.Entry) {
	t.Helper()
	raw, _ := json.Marshal(entries)
	if _, err := e.vault.KVv2(vaultMount).Put(context.Background(), vaultPath, map[string]any{"keys": string(raw)}); err != nil {
		t.Fatal(err)
	}
}

func activeKid(entries []keyset.Entry) string {
	for _, e := range entries {
		if e.Status == keyset.StatusActive {
			return e.Kid
		}
	}
	return ""
}

func TestDataPlanesSignWithTheSameKey(t *testing.T) {
	e := setup(t)
	want := activeKid(e.readEntries(t))
	for _, dp := range e.dps {
		var kid string
		var err error
		// The first request can race the initial keyset load on a fresh data plane.
		for range 15 {
			var tok string
			if tok, err = e.signedToken(dp); err == nil {
				set, jerr := fetchJWKS(dp)
				if jerr != nil {
					t.Fatal(jerr)
				}
				if kid, err = verify(tok, set); err == nil {
					break
				}
			}
			time.Sleep(2 * time.Second)
		}
		if err != nil {
			t.Fatalf("%s: %v", dp, err)
		}
		if kid != want {
			t.Errorf("%s signs with %q, want the active key %q", dp, kid, want)
		}
	}
}

func TestPrivateMembersNeverReachBackends(t *testing.T) {
	e := setup(t)
	for _, dp := range e.dps {
		resp, err := client.Get(dp + "/.well-known/jwks.json")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		for _, m := range []string{`"d"`, `"p"`, `"q"`, `"dp"`, `"dq"`, `"qi"`} {
			if strings.Contains(string(body), m+":") {
				t.Errorf("%s: JWKS contains %s", dp, m)
			}
		}
	}
}

// backend simulates a verifier that caches the JWKS for backendJWKSTTL and
// does not refetch on an unknown kid.
type backend struct {
	dp      string
	mu      sync.Mutex
	set     *jose.JSONWebKeySet
	fetched time.Time
}

func (b *backend) jwks() (*jose.JSONWebKeySet, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.set == nil || time.Since(b.fetched) > backendJWKSTTL {
		set, err := fetchJWKS(b.dp)
		if err != nil {
			return nil, err
		}
		b.set, b.fetched = set, time.Now()
	}
	return b.set, nil
}

// TestRotationUnderLoad runs a full k1 -> k2 rotation while requests flow
// through both data planes, and requires every token to verify.
func TestRotationUnderLoad(t *testing.T) {
	e := setup(t)
	entries := e.readEntries(t)
	oldKid := activeKid(entries)
	if oldKid == "" {
		t.Fatal("no active key in Vault")
	}
	newKid := fmt.Sprintf("k-%d", time.Now().Unix())

	var (
		total, failures atomic.Int64
		mu              sync.Mutex
		lastKid         = map[string]string{}
		failMsgs        []string
	)
	backends := make([]*backend, len(e.dps))
	for i, dp := range e.dps {
		backends[i] = &backend{dp: dp}
	}
	ctx, stop := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for i, dp := range e.dps {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each data plane's tokens are verified by the backend behind the other one,
			// so a token is never checked against the JWKS of the node that signed it.
			b := backends[(i+1)%len(backends)]
			for ctx.Err() == nil {
				total.Add(1)
				tok, err := e.signedToken(dp)
				var kid string
				if err == nil {
					var set *jose.JSONWebKeySet
					if set, err = b.jwks(); err == nil {
						kid, err = verify(tok, set)
					}
				}
				mu.Lock()
				if err != nil {
					failures.Add(1)
					if len(failMsgs) < 20 {
						failMsgs = append(failMsgs, fmt.Sprintf("%s %s: %v", time.Now().Format(time.TimeOnly), dp, err))
					}
				} else if lastKid[dp] != kid {
					t.Logf("%s now signs with %s", dp, kid)
					lastKid[dp] = kid
				}
				mu.Unlock()
				time.Sleep(100 * time.Millisecond)
			}
		}()
	}
	defer func() {
		stop()
		wg.Wait()
		t.Logf("%d requests, %d failures", total.Load(), failures.Load())
		for _, m := range failMsgs {
			t.Log(m)
		}
		if failures.Load() > 0 {
			t.Errorf("%d verification failures during rotation", failures.Load())
		}
	}()

	// Step 1: stage k2.
	staged, err := keygen.Generate(keygen.Options{Alg: "RS256", Kid: newKid, Status: keyset.StatusStaged})
	if err != nil {
		t.Fatal(err)
	}
	e.writeEntries(t, append(entries, staged))
	t.Logf("staged %s", newKid)

	// Step 2: wait until every verifier cache can know k2.
	// proxy-cache TTL (5s) + backend TTL (5s) + bridge refresh (2s), and the staging guard.
	time.Sleep(max(15*time.Second, e.minStage+2*time.Second))
	waitFor(t, 30*time.Second, "k2 in the public JWKS", func() bool {
		for _, dp := range e.dps {
			set, err := fetchJWKS(dp)
			if err != nil || len(set.Key(newKid)) == 0 {
				return false
			}
		}
		return true
	})

	// Step 3: promote k2, retire k1.
	now := time.Now().UTC()
	promoted := e.readEntries(t)
	for i := range promoted {
		switch promoted[i].Kid {
		case newKid:
			promoted[i].Status = keyset.StatusActive
			promoted[i].PromotedAt = &now
		case oldKid:
			promoted[i].Status = keyset.StatusRetired
		}
	}
	e.writeEntries(t, promoted)
	t.Logf("promoted %s, retired %s", newKid, oldKid)

	// Step 4: every data plane switches on its own rotate timer.
	waitFor(t, 3*e.rotatePeriod+30*time.Second, "both data planes signing with k2", func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, dp := range e.dps {
			if lastKid[dp] != newKid {
				return false
			}
		}
		return true
	})

	// Step 5 and 6: after rotate period + token lifetime, remove k1.
	time.Sleep(e.rotatePeriod)
	var remaining []keyset.Entry
	for _, en := range e.readEntries(t) {
		if en.Kid != oldKid {
			remaining = append(remaining, en)
		}
	}
	e.writeEntries(t, remaining)
	t.Logf("removed %s", oldKid)

	waitFor(t, 30*time.Second, "k1 gone from the public JWKS", func() bool {
		for _, dp := range e.dps {
			set, err := fetchJWKS(dp)
			if err != nil || len(set.Key(oldKid)) != 0 {
				return false
			}
		}
		return true
	})
	// Keep traffic flowing a little longer after the removal.
	time.Sleep(e.rotatePeriod)
}

func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("timed out after %s waiting for %s", timeout, what)
}

func TestBridgeMetrics(t *testing.T) {
	e := setup(t)
	if e.bridgeAdmin == "" {
		t.Skip("E2E_BRIDGE_ADMIN_URL not set")
	}
	resp, err := client.Get(e.bridgeAdmin + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	// The Service balances across replicas, so only check series every replica has.
	for _, want := range []string{
		`jwksbridge_keys{keyset="default",status="active"} 1`,
		`jwksbridge_refresh_total{keyset="default",result="updated"}`,
		`jwksbridge_snapshot_age_seconds{keyset="default"}`,
		`jwksbridge_build_info{`,
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("metrics missing %s", want)
		}
	}
}
