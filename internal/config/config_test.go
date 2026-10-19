package config

import (
	"io"
	"testing"
	"time"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestDefaultsEnvAndFlags(t *testing.T) {
	env := envMap(map[string]string{
		"JWKSB_TLS_CERT":            "/tls/tls.crt",
		"JWKSB_TLS_KEY":             "/tls/tls.key",
		"JWKSB_BASIC_USER":          "kong",
		"JWKSB_BASIC_PASSWORD_FILE": "/secret/password",
		"JWKSB_REFRESH_INTERVAL":    "10s",
		"JWKSB_KEYSETS":             "default=secret/a, partners=secret/b",
		"JWKSB_ALLOWED_CLIENT_SANS": "dp1, dp2",
	})
	c, err := Load([]string{"--refresh-interval=20s"}, env, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.RefreshInterval != 20*time.Second {
		t.Errorf("flag did not win over env: %s", c.RefreshInterval)
	}
	if c.PublicAddr != ":8080" || c.MaxStale != time.Hour || c.Source != "vault" || c.MinStageDuration != 10*time.Minute {
		t.Errorf("defaults: %+v", c)
	}
	if c.Keysets["partners"] != "secret/b" || len(c.Keysets) != 2 {
		t.Errorf("keysets = %v", c.Keysets)
	}
	if len(c.AllowedClientSANs) != 2 || c.AllowedClientSANs[1] != "dp2" {
		t.Errorf("sans = %v", c.AllowedClientSANs)
	}
}

func TestValidation(t *testing.T) {
	cases := map[string]map[string]string{
		"no tls":         {"JWKSB_BASIC_USER": "u", "JWKSB_BASIC_PASSWORD_FILE": "f"},
		"no auth":        {"JWKSB_TLS_CERT": "c", "JWKSB_TLS_KEY": "k"},
		"bad source":     {"JWKSB_PRIVATE_ADDR": "", "JWKSB_SOURCE": "s3"},
		"bad keysets":    {"JWKSB_PRIVATE_ADDR": "", "JWKSB_KEYSETS": "default"},
		"dup keysets":    {"JWKSB_PRIVATE_ADDR": "", "JWKSB_KEYSETS": "a=x,a=y"},
		"bad duration":   {"JWKSB_PRIVATE_ADDR": "", "JWKSB_MAX_STALE": "soon"},
		"short stage":    {"JWKSB_PRIVATE_ADDR": "", "JWKSB_MIN_STAGE_DURATION": "30s"},
		"plaintext mtls": {"JWKSB_PRIVATE_INSECURE_PLAINTEXT": "true", "JWKSB_CLIENT_CA": "ca"},
	}
	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			// An empty value falls back to the default, so disable the private
			// listener with a flag instead.
			args := []string{}
			if v, ok := m["JWKSB_PRIVATE_ADDR"]; ok && v == "" {
				args = append(args, "--private-addr=")
			}
			if _, err := Load(args, envMap(m), io.Discard); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestPlaintextDev(t *testing.T) {
	_, err := Load(nil, envMap(map[string]string{
		"JWKSB_PRIVATE_INSECURE_PLAINTEXT": "true",
		"JWKSB_BASIC_USER":                 "u",
		"JWKSB_BASIC_PASSWORD_FILE":        "f",
		"JWKSB_SOURCE":                     "file",
	}), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
}
