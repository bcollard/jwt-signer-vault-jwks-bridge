// Package config reads the serve settings from flags and JWKSB_* environment
// variables. Flags win over the environment.
package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// Config holds the serve settings.
type Config struct {
	PublicAddr  string
	PrivateAddr string
	AdminAddr   string

	TLSCert           string
	TLSKey            string
	ClientCA          string
	AllowedClientSANs []string
	BasicUser         string
	BasicPasswordFile string
	// PrivatePlaintext serves /keyset over plain HTTP. Local development only.
	PrivatePlaintext bool

	Source  string
	FileDir string
	// Keysets maps a keyset name to its source path.
	Keysets map[string]string

	RefreshInterval  time.Duration
	MaxStale         time.Duration
	JWKSMaxAge       time.Duration
	MinStageDuration time.Duration

	VaultAuth             string
	VaultRole             string
	VaultAuthMount        string
	VaultK8sTokenPath     string
	VaultAppRoleID        string
	VaultAppRoleSecretIDF string

	LogLevel  string
	LogFormat string
}

type env func(string) string

func str(getenv env, key, def string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return def
}

// Load parses args with defaults taken from getenv.
func Load(args []string, getenv func(string) string, output io.Writer) (*Config, error) {
	c := &Config{}
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(output)
	var keysets, sans string
	var errs []error
	dur := func(p *time.Duration, name, key, def, usage string) {
		v := str(getenv, key, def)
		d, err := time.ParseDuration(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", key, err))
		}
		fs.DurationVar(p, name, d, usage+" ($"+key+")")
	}
	s := func(p *string, name, key, def, usage string) {
		fs.StringVar(p, name, str(getenv, key, def), usage+" ($"+key+")")
	}

	s(&c.PublicAddr, "public-addr", "JWKSB_PUBLIC_ADDR", ":8080", "public listener address")
	s(&c.PrivateAddr, "private-addr", "JWKSB_PRIVATE_ADDR", ":8443", "private TLS listener address")
	s(&c.AdminAddr, "admin-addr", "JWKSB_ADMIN_ADDR", ":9090", "admin (metrics) listener address")
	s(&c.TLSCert, "tls-cert", "JWKSB_TLS_CERT", "", "server certificate file for the private listener")
	s(&c.TLSKey, "tls-key", "JWKSB_TLS_KEY", "", "server key file for the private listener")
	s(&c.ClientCA, "client-ca", "JWKSB_CLIENT_CA", "", "CA bundle that enables mTLS client authentication")
	s(&sans, "allowed-client-sans", "JWKSB_ALLOWED_CLIENT_SANS", "", "comma-separated client certificate SAN or CN allowlist")
	s(&c.BasicUser, "basic-user", "JWKSB_BASIC_USER", "", "Basic auth user for the private listener")
	s(&c.BasicPasswordFile, "basic-password-file", "JWKSB_BASIC_PASSWORD_FILE", "", "file holding the Basic auth password")
	fs.BoolVar(&c.PrivatePlaintext, "private-insecure-plaintext", getenv("JWKSB_PRIVATE_INSECURE_PLAINTEXT") == "true",
		"serve the private listener without TLS, for local development only ($JWKSB_PRIVATE_INSECURE_PLAINTEXT)")

	s(&c.Source, "source", "JWKSB_SOURCE", "vault", "secret source: vault or file")
	s(&c.FileDir, "file-dir", "JWKSB_FILE_DIR", "", "base directory for relative paths with the file source")
	s(&keysets, "keysets", "JWKSB_KEYSETS", "default=secret/jwks-bridge/default", "comma-separated name=path pairs")

	dur(&c.RefreshInterval, "refresh-interval", "JWKSB_REFRESH_INTERVAL", "30s", "source poll interval")
	dur(&c.MaxStale, "max-stale", "JWKSB_MAX_STALE", "1h", "readiness cutoff when the source is unreachable")
	dur(&c.JWKSMaxAge, "jwks-max-age", "JWKSB_JWKS_MAX_AGE", "300s", "public JWKS Cache-Control max-age")
	dur(&c.MinStageDuration, "min-stage-duration", "JWKSB_MIN_STAGE_DURATION", "10m", "minimum time between staged_at and signing use")

	s(&c.VaultAuth, "vault-auth", "JWKSB_VAULT_AUTH", "token", "Vault auth method: token, kubernetes or approle")
	s(&c.VaultRole, "vault-role", "JWKSB_VAULT_ROLE", "", "Vault Kubernetes auth role")
	s(&c.VaultAuthMount, "vault-auth-mount", "JWKSB_VAULT_AUTH_MOUNT", "", "Vault auth mount path (default: the method name)")
	s(&c.VaultK8sTokenPath, "vault-k8s-token-path", "JWKSB_VAULT_K8S_TOKEN_PATH", "", "service account token file for Kubernetes auth")
	s(&c.VaultAppRoleID, "vault-approle-role-id", "JWKSB_VAULT_APPROLE_ROLE_ID", "", "Vault AppRole role id")
	s(&c.VaultAppRoleSecretIDF, "vault-approle-secret-id-file", "JWKSB_VAULT_APPROLE_SECRET_ID_FILE", "", "file holding the Vault AppRole secret id")

	s(&c.LogLevel, "log-level", "JWKSB_LOG_LEVEL", "info", "log level: debug, info, warn or error")
	s(&c.LogFormat, "log-format", "JWKSB_LOG_FORMAT", "json", "log format: json or text")

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	var err error
	if c.Keysets, err = ParseKeysets(keysets); err != nil {
		return nil, err
	}
	c.AllowedClientSANs = splitList(sans)
	return c, c.Validate()
}

// ParseKeysets parses "name=path,name2=path2".
func ParseKeysets(s string) (map[string]string, error) {
	out := map[string]string{}
	for _, pair := range splitList(s) {
		name, path, ok := strings.Cut(pair, "=")
		name, path = strings.TrimSpace(name), strings.TrimSpace(path)
		if !ok || name == "" || path == "" {
			return nil, fmt.Errorf("keyset %q: want name=path", pair)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("keyset %q is defined twice", name)
		}
		out[name] = path
	}
	if len(out) == 0 {
		return nil, errors.New("no keyset configured")
	}
	return out, nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Validate checks settings that depend on each other.
func (c *Config) Validate() error {
	var errs []error
	switch c.Source {
	case "vault", "file":
	default:
		errs = append(errs, fmt.Errorf("unknown source %q (want vault or file)", c.Source))
	}
	if c.PrivateAddr != "" {
		if !c.PrivatePlaintext && (c.TLSCert == "" || c.TLSKey == "") {
			errs = append(errs, errors.New("the private listener needs --tls-cert and --tls-key"))
		}
		if c.ClientCA == "" && (c.BasicUser == "" || c.BasicPasswordFile == "") {
			errs = append(errs, errors.New("the private listener needs --client-ca or --basic-user with --basic-password-file"))
		}
		if c.PrivatePlaintext && c.ClientCA != "" {
			errs = append(errs, errors.New("mTLS cannot be used with --private-insecure-plaintext"))
		}
	}
	if c.RefreshInterval <= 0 {
		errs = append(errs, errors.New("refresh interval must be positive"))
	}
	if c.MaxStale > 0 && c.MaxStale < c.RefreshInterval {
		errs = append(errs, errors.New("max stale must be at least the refresh interval"))
	}
	if c.MinStageDuration > 0 && c.MinStageDuration < 2*c.RefreshInterval {
		errs = append(errs, fmt.Errorf("min stage duration %s should be at least twice the refresh interval %s", c.MinStageDuration, c.RefreshInterval))
	}
	return errors.Join(errs...)
}

// KeysetNames returns the configured names, sorted.
func (c *Config) KeysetNames() []string {
	names := make([]string, 0, len(c.Keysets))
	for n := range c.Keysets {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
