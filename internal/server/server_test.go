package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/bcollard/jwt-signer-vault-jwks-bridge/internal/cache"
	"github.com/bcollard/jwt-signer-vault-jwks-bridge/internal/keygen"
	"github.com/bcollard/jwt-signer-vault-jwks-bridge/internal/keyset"
	"github.com/bcollard/jwt-signer-vault-jwks-bridge/internal/metrics"
	"github.com/bcollard/jwt-signer-vault-jwks-bridge/internal/source/file"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func newServer(t *testing.T, auth *Auth) *Server {
	t.Helper()
	dir := t.TempDir()
	var entries []keyset.Entry
	for _, spec := range []struct {
		alg, kid string
		st       keyset.Status
	}{{"RS256", "k2", keyset.StatusActive}, {"RS256", "k1", keyset.StatusRetired}, {"ES256", "k3", keyset.StatusStaged}} {
		e, err := keygen.Generate(keygen.Options{Alg: spec.alg, Kid: spec.kid, Status: spec.st})
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, e)
	}
	raw, _ := json.Marshal(keyset.Document{Keys: entries})
	if err := os.WriteFile(filepath.Join(dir, "default.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	m := metrics.New()
	c := cache.New(file.New(dir), cache.Options{
		Keysets: map[string]string{"default": "default.json", "missing": "missing.json"},
		Log:     quiet, Metrics: m,
	})
	_ = c.RefreshAll(context.Background())
	return &Server{Cache: c, Metrics: m, Log: quiet, JWKSMaxAge: 300 * time.Second, Auth: auth}
}

func get(t *testing.T, h http.Handler, path string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func kids(t *testing.T, body []byte) []string {
	t.Helper()
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	var out []string
	for _, k := range doc.Keys {
		out = append(out, k["kid"].(string))
	}
	return out
}

func TestPublicJWKS(t *testing.T) {
	s := newServer(t, nil)
	h := s.Public()
	for _, path := range []string{"/jwks.json", "/.well-known/jwks.json", "/jwks.json?name=default", "/jwks/default"} {
		rec := get(t, h, path, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: code %d", path, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); ct != ContentType {
			t.Errorf("%s: content type %q", path, ct)
		}
		if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=300" {
			t.Errorf("%s: cache control %q", path, cc)
		}
		if got := strings.Join(kids(t, rec.Body.Bytes()), ","); got != "k2,k1,k3" {
			t.Errorf("%s: kids %s", path, got)
		}
		for _, m := range []string{`"d"`, `"p"`, `"q"`, `"dp"`, `"dq"`, `"qi"`} {
			if strings.Contains(rec.Body.String(), m+":") {
				t.Errorf("%s: public body contains %s", path, m)
			}
		}
	}

	if rec := get(t, h, "/jwks.json?name=nope", nil); rec.Code != http.StatusNotFound {
		t.Errorf("unknown keyset: code %d", rec.Code)
	}
	if rec := get(t, h, "/jwks.json?name=missing", nil); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("unloaded keyset: code %d", rec.Code)
	}
}

func TestPublicListenerHasNoKeyset(t *testing.T) {
	h := newServer(t, &Auth{BasicUser: "u", BasicPassword: "p"}).Public()
	for _, path := range []string{"/keyset", "/keyset/default"} {
		rec := get(t, h, path, map[string]string{"Authorization": basic("u", "p")})
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s on public listener: code %d", path, rec.Code)
		}
	}
}

func TestETag(t *testing.T) {
	h := newServer(t, nil).Public()
	first := get(t, h, "/jwks.json", nil)
	etag := first.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag")
	}
	for _, inm := range []string{etag, "W/" + etag, `"other", ` + etag, "*"} {
		if rec := get(t, h, "/jwks.json", map[string]string{"If-None-Match": inm}); rec.Code != http.StatusNotModified || rec.Body.Len() != 0 {
			t.Errorf("If-None-Match %s: code %d", inm, rec.Code)
		}
	}
	if rec := get(t, h, "/jwks.json", map[string]string{"If-None-Match": `"stale"`}); rec.Code != http.StatusOK {
		t.Errorf("stale ETag: code %d", rec.Code)
	}
}

func basic(u, p string) string {
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth(u, p)
	return req.Header.Get("Authorization")
}

func TestPrivateBasicAuth(t *testing.T) {
	h := newServer(t, &Auth{BasicUser: "kong", BasicPassword: "s3cret"}).Private()

	rec := get(t, h, "/keyset", nil)
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") == "" {
		t.Errorf("no credentials: code %d", rec.Code)
	}
	if rec := get(t, h, "/keyset", map[string]string{"Authorization": basic("kong", "wrong")}); rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong password: code %d", rec.Code)
	}
	for _, path := range []string{"/keyset", "/keyset?name=default", "/keyset/default"} {
		rec = get(t, h, path, map[string]string{"Authorization": basic("kong", "s3cret")})
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: code %d", path, rec.Code)
		}
		if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("cache control %q", cc)
		}
		if got := strings.Join(kids(t, rec.Body.Bytes()), ","); got != "k2,k1" {
			t.Errorf("%s: kids %s, want k2,k1 (no staged key)", path, got)
		}
		if !strings.Contains(rec.Body.String(), `"d":`) {
			t.Errorf("%s: private keyset has no private members", path)
		}
	}
}

func TestReadyAndMetrics(t *testing.T) {
	s := newServer(t, nil)
	// "missing" never loads, so the bridge is not ready.
	if rec := get(t, s.Public(), "/readyz", nil); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("readyz: code %d", rec.Code)
	}
	if rec := get(t, s.Public(), "/healthz", nil); rec.Code != http.StatusOK {
		t.Errorf("healthz: code %d", rec.Code)
	}
	get(t, s.Public(), "/jwks.json", nil)
	rec := get(t, s.Admin(), "/metrics", nil)
	body := rec.Body.String()
	for _, want := range []string{
		`jwksbridge_requests_total{code="200",endpoint="jwks"} 1`,
		`jwksbridge_keys{keyset="default",status="active"} 1`,
		`jwksbridge_refresh_total{keyset="missing",result="error"} 1`,
		`jwksbridge_snapshot_age_seconds{keyset="default"}`,
		`jwksbridge_source_errors_total{source="file"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %s", want)
		}
	}
}

func TestTraceContextPropagation(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	prevTP, prevProp := otel.GetTracerProvider(), otel.GetTextMapPropagator()
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() { otel.SetTracerProvider(prevTP); otel.SetTextMapPropagator(prevProp) })

	h := newServer(t, nil).Public()
	const traceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	get(t, h, "/.well-known/jwks.json", map[string]string{"traceparent": "00-" + traceID + "-00f067aa0ba902b7-01"})

	spans := exp.GetSpans()
	if len(spans) == 0 {
		t.Fatal("no span recorded")
	}
	sp := spans[len(spans)-1]
	if sp.SpanContext.TraceID().String() != traceID {
		t.Errorf("trace id = %s, want %s", sp.SpanContext.TraceID(), traceID)
	}
	if sp.Parent.SpanID().String() != "00f067aa0ba902b7" {
		t.Errorf("parent span id = %s", sp.Parent.SpanID())
	}
	if sp.Name != "GET /.well-known/jwks.json" {
		t.Errorf("span name = %q", sp.Name)
	}
}

// pki writes a CA, a server certificate and a client certificate.
type pki struct {
	dir                       string
	caFile, certFile, keyFile string
	ca                        *x509.Certificate
	caKey                     *ecdsa.PrivateKey
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	p := &pki{dir: t.TempDir()}
	p.caKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &p.caKey.PublicKey, p.caKey)
	p.ca, _ = x509.ParseCertificate(der)
	p.caFile = p.write(t, "ca.crt", "CERTIFICATE", der)
	p.certFile, p.keyFile = p.leaf(t, "server", []string{"localhost"}, x509.ExtKeyUsageServerAuth)
	return p
}

func (p *pki) write(t *testing.T, name, typ string, der []byte) string {
	t.Helper()
	f := filepath.Join(p.dir, name)
	if err := os.WriteFile(f, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func (p *pki) leaf(t *testing.T, name string, dns []string, usage x509.ExtKeyUsage) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: dns, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage: []x509.ExtKeyUsage{usage}, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.caKey)
	kder, _ := x509.MarshalPKCS8PrivateKey(key)
	return p.write(t, name+".crt", "CERTIFICATE", der), p.write(t, name+".key", "PRIVATE KEY", kder)
}

func TestPrivateMTLS(t *testing.T) {
	p := newPKI(t)
	cfg, err := TLSConfig(p.certFile, p.keyFile, p.caFile)
	if err != nil {
		t.Fatal(err)
	}
	s := newServer(t, &Auth{MTLS: true, AllowedSANs: []string{"kong-dp.kong.svc"}, Log: quiet})
	// httptest.Server adds its own certificate, which would bypass
	// GetCertificate, so serve with a plain http.Server.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: s.Private(), TLSConfig: cfg}
	go func() { _ = hs.ServeTLS(ln, "", "") }()
	defer hs.Close()
	baseURL := "https://" + ln.Addr().String()

	roots := x509.NewCertPool()
	roots.AddCert(p.ca)
	client := func(certFile, keyFile string) *http.Client {
		tc := &tls.Config{RootCAs: roots}
		if certFile != "" {
			c, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				t.Fatal(err)
			}
			tc.Certificates = []tls.Certificate{c}
		}
		return &http.Client{Transport: &http.Transport{TLSClientConfig: tc}}
	}
	code := func(c *http.Client) int {
		resp, err := c.Get(baseURL + "/keyset")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	allowedCert, allowedKey := p.leaf(t, "kong-dp", []string{"kong-dp.kong.svc"}, x509.ExtKeyUsageClientAuth)
	otherCert, otherKey := p.leaf(t, "other", []string{"other.svc"}, x509.ExtKeyUsageClientAuth)

	if c := code(client(allowedCert, allowedKey)); c != http.StatusOK {
		t.Errorf("allowed client: code %d", c)
	}
	if c := code(client(otherCert, otherKey)); c != http.StatusForbidden {
		t.Errorf("SAN not allowed: code %d", c)
	}
	if c := code(client("", "")); c != http.StatusForbidden {
		t.Errorf("no client cert: code %d", c)
	}
}

func TestAuthEnabled(t *testing.T) {
	if (&Auth{}).Enabled() || (*Auth)(nil).Enabled() || (&Auth{BasicUser: "u"}).Enabled() {
		t.Error("empty auth reported as enabled")
	}
	if !(&Auth{MTLS: true}).Enabled() || !(&Auth{BasicUser: "u", BasicPassword: "p"}).Enabled() {
		t.Error("configured auth reported as disabled")
	}
}
