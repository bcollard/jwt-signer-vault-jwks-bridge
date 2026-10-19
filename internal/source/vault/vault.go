// Package vault reads keyset documents from a HashiCorp Vault KV v2 engine.
package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/bcollard/jwt-signer-vault-jwks-bridge/internal/source"
)

// Auth methods.
const (
	AuthToken      = "token"
	AuthKubernetes = "kubernetes"
	AuthAppRole    = "approle"
)

// Config selects the Vault authentication method. The address, CA, namespace
// and static token come from the standard VAULT_* environment variables.
type Config struct {
	Auth string
	// Role is the Kubernetes auth role.
	Role string
	// AuthMount is the auth method mount path; defaults to the method name.
	AuthMount string
	// K8sTokenPath is the service account token file for Kubernetes auth.
	K8sTokenPath string
	// RoleID and SecretIDFile are the AppRole credentials.
	RoleID       string
	SecretIDFile string
}

// Source reads keysets from Vault KV v2. Paths are "<mount>/<secret path>",
// for example "secret/jwks-bridge/default".
type Source struct {
	cfg    Config
	client *api.Client
	log    *slog.Logger
}

// New builds a Vault source. Call Start before Load when the auth method is
// not "token".
func New(cfg Config, log *slog.Logger) (*Source, error) {
	if cfg.Auth == "" {
		cfg.Auth = AuthToken
	}
	if cfg.AuthMount == "" && cfg.Auth != AuthToken {
		cfg.AuthMount = cfg.Auth
	}
	if cfg.K8sTokenPath == "" {
		cfg.K8sTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	}
	switch cfg.Auth {
	case AuthToken:
	case AuthKubernetes:
		if cfg.Role == "" {
			return nil, errors.New("vault kubernetes auth needs a role")
		}
	case AuthAppRole:
		if cfg.RoleID == "" || cfg.SecretIDFile == "" {
			return nil, errors.New("vault approle auth needs a role id and a secret id file")
		}
	default:
		return nil, fmt.Errorf("unknown vault auth method %q", cfg.Auth)
	}

	vcfg := api.DefaultConfig()
	if vcfg.Error != nil {
		return nil, fmt.Errorf("vault config: %w", vcfg.Error)
	}
	// Propagate the W3C trace context to Vault and record client spans.
	vcfg.HttpClient.Transport = otelhttp.NewTransport(vcfg.HttpClient.Transport)
	client, err := api.NewClient(vcfg)
	if err != nil {
		return nil, fmt.Errorf("vault client: %w", err)
	}
	if log == nil {
		log = slog.Default()
	}
	return &Source{cfg: cfg, client: client, log: log}, nil
}

// Client exposes the underlying Vault client, for tests.
func (s *Source) Client() *api.Client { return s.client }

func (s *Source) Name() string { return "vault" }

// Start logs in and keeps the token renewed until ctx is done. With the token
// auth method it returns immediately.
func (s *Source) Start(ctx context.Context) error {
	if s.cfg.Auth == AuthToken {
		return nil
	}
	secret, err := s.login(ctx)
	if err != nil {
		return err
	}
	go s.manageToken(ctx, secret)
	return nil
}

func (s *Source) login(ctx context.Context) (*api.Secret, error) {
	var path string
	var data map[string]any
	switch s.cfg.Auth {
	case AuthKubernetes:
		jwt, err := os.ReadFile(s.cfg.K8sTokenPath)
		if err != nil {
			return nil, fmt.Errorf("read service account token: %w", err)
		}
		path = "auth/" + s.cfg.AuthMount + "/login"
		data = map[string]any{"role": s.cfg.Role, "jwt": strings.TrimSpace(string(jwt))}
	case AuthAppRole:
		secretID, err := os.ReadFile(s.cfg.SecretIDFile)
		if err != nil {
			return nil, fmt.Errorf("read approle secret id: %w", err)
		}
		path = "auth/" + s.cfg.AuthMount + "/login"
		data = map[string]any{"role_id": s.cfg.RoleID, "secret_id": strings.TrimSpace(string(secretID))}
	}
	secret, err := s.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return nil, fmt.Errorf("vault %s login: %w", s.cfg.Auth, err)
	}
	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return nil, fmt.Errorf("vault %s login returned no token", s.cfg.Auth)
	}
	s.client.SetToken(secret.Auth.ClientToken)
	s.log.Info("vault login succeeded", "auth", s.cfg.Auth, "ttl", secret.Auth.LeaseDuration)
	return secret, nil
}

// manageToken renews the token and logs in again when it can no longer be
// renewed.
func (s *Source) manageToken(ctx context.Context, secret *api.Secret) {
	backoff := time.Second
	for {
		if secret != nil && secret.Auth.Renewable {
			w, err := s.client.NewLifetimeWatcher(&api.LifetimeWatcherInput{Secret: secret})
			if err == nil {
				go w.Start()
				s.watch(ctx, w)
				w.Stop()
			}
		} else if secret != nil {
			// Non-renewable token: log in again at 80 % of its TTL.
			ttl := time.Duration(secret.Auth.LeaseDuration) * time.Second
			if ttl <= 0 {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(ttl * 8 / 10):
			}
		}
		if ctx.Err() != nil {
			return
		}

		var err error
		secret, err = s.login(ctx)
		if err != nil {
			s.log.Error("vault login failed", "err", err, "retry_in", backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, time.Minute)
			continue
		}
		backoff = time.Second
	}
}

func (s *Source) watch(ctx context.Context, w *api.LifetimeWatcher) {
	for {
		select {
		case <-ctx.Done():
			return
		case err := <-w.DoneCh():
			if err != nil {
				s.log.Warn("vault token renewal stopped", "err", err)
			}
			return
		case <-w.RenewCh():
			s.log.Debug("vault token renewed")
		}
	}
}

func splitPath(path string) (mount, rest string, err error) {
	mount, rest, ok := strings.Cut(strings.Trim(path, "/"), "/")
	if !ok || mount == "" || rest == "" {
		return "", "", fmt.Errorf("vault path %q must be <mount>/<path>", path)
	}
	return mount, rest, nil
}

// Load reads the "keys" field of a KV v2 secret. The field holds the JSON array
// of entries, either as a JSON value or as a string containing JSON.
func (s *Source) Load(ctx context.Context, path string) ([]byte, string, error) {
	mount, rest, err := splitPath(path)
	if err != nil {
		return nil, "", err
	}
	sec, err := s.client.KVv2(mount).Get(ctx, rest)
	if errors.Is(err, api.ErrSecretNotFound) {
		return nil, "", fmt.Errorf("%w: %s", source.ErrNotFound, path)
	}
	if err != nil {
		return nil, "", err
	}
	keys, ok := sec.Data["keys"]
	if !ok {
		return nil, "", fmt.Errorf("vault secret %s has no \"keys\" field", path)
	}
	var arr json.RawMessage
	switch v := keys.(type) {
	case string:
		arr = json.RawMessage(v)
	default:
		if arr, err = json.Marshal(v); err != nil {
			return nil, "", err
		}
	}
	raw, err := json.Marshal(map[string]json.RawMessage{"keys": arr})
	if err != nil {
		return nil, "", fmt.Errorf("vault secret %s: \"keys\" is not valid JSON: %w", path, err)
	}
	version := ""
	if sec.VersionMetadata != nil {
		version = strconv.Itoa(sec.VersionMetadata.Version)
	}
	return raw, version, nil
}

// Ping checks that Vault is reachable, initialized and unsealed.
func (s *Source) Ping(ctx context.Context) error {
	h, err := s.client.Sys().HealthWithContext(ctx)
	if err != nil {
		return err
	}
	if !h.Initialized || h.Sealed {
		return fmt.Errorf("vault not ready: initialized=%t sealed=%t", h.Initialized, h.Sealed)
	}
	return nil
}
