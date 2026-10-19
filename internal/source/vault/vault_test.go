package vault

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/bcollard/jwt-signer-vault-jwks-bridge/internal/source"
)

// fakeVault serves the KV v2 read and login endpoints used by the source.
func fakeVault(t *testing.T, keys any) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/secret/data/jwks-bridge/default", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "s.k8s" && r.Header.Get("X-Vault-Token") != "root" {
			http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"data":     map[string]any{"keys": keys},
				"metadata": map[string]any{"version": 7, "created_time": "2026-10-19T00:00:00Z"},
			},
		})
	})
	mux.HandleFunc("GET /v1/secret/data/jwks-bridge/missing", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"errors":[]}`)
	})
	mux.HandleFunc("PUT /v1/auth/kubernetes/login", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["role"] != "jwks-bridge" || body["jwt"] != "sa-token" {
			http.Error(w, `{"errors":["invalid role or jwt"]}`, http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{"client_token": "s.k8s", "lease_duration": 3600, "renewable": false},
		})
	})
	mux.HandleFunc("GET /v1/sys/health", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"initialized": true, "sealed": false})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	t.Setenv("VAULT_ADDR", srv.URL)
	return srv
}

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestLoadArrayAndString(t *testing.T) {
	for name, keys := range map[string]any{
		"array":  []any{map[string]any{"kid": "k1"}},
		"string": `[{"kid":"k1"}]`,
	} {
		t.Run(name, func(t *testing.T) {
			fakeVault(t, keys)
			t.Setenv("VAULT_TOKEN", "root")
			s, err := New(Config{}, quiet)
			if err != nil {
				t.Fatal(err)
			}
			raw, version, err := s.Load(context.Background(), "secret/jwks-bridge/default")
			if err != nil {
				t.Fatal(err)
			}
			if string(raw) != `{"keys":[{"kid":"k1"}]}` || version != "7" {
				t.Errorf("Load = %s, %q", raw, version)
			}
			if _, _, err := s.Load(context.Background(), "secret/jwks-bridge/missing"); !errors.Is(err, source.ErrNotFound) {
				t.Errorf("missing err = %v", err)
			}
			if err := s.Ping(context.Background()); err != nil {
				t.Errorf("Ping = %v", err)
			}
		})
	}
}

func TestKubernetesLogin(t *testing.T) {
	fakeVault(t, []any{})
	t.Setenv("VAULT_TOKEN", "")
	tok := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tok, []byte("sa-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{Auth: AuthKubernetes, Role: "jwks-bridge", K8sTokenPath: tok}, quiet)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if s.Client().Token() != "s.k8s" {
		t.Errorf("token = %q", s.Client().Token())
	}
	if _, _, err := s.Load(ctx, "secret/jwks-bridge/default"); err != nil {
		t.Errorf("Load after login: %v", err)
	}
}

func TestConfigErrors(t *testing.T) {
	for name, cfg := range map[string]Config{
		"k8s without role":   {Auth: AuthKubernetes},
		"approle without id": {Auth: AuthAppRole},
		"unknown method":     {Auth: "ldap"},
	} {
		if _, err := New(cfg, quiet); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, _, err := splitPath("secret"); err == nil {
		t.Error("splitPath without a separator should fail")
	}
}
