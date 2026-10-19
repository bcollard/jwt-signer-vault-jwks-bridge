// Command jwks-bridge serves signing key pairs stored in a secret store as a
// private keyset for the Kong jwt-signer plugin and a public JWKS for backends.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bcollard/jwt-signer-vault-jwks-bridge/internal/cache"
	"github.com/bcollard/jwt-signer-vault-jwks-bridge/internal/config"
	"github.com/bcollard/jwt-signer-vault-jwks-bridge/internal/keygen"
	"github.com/bcollard/jwt-signer-vault-jwks-bridge/internal/keyset"
	"github.com/bcollard/jwt-signer-vault-jwks-bridge/internal/metrics"
	"github.com/bcollard/jwt-signer-vault-jwks-bridge/internal/server"
	"github.com/bcollard/jwt-signer-vault-jwks-bridge/internal/source"
	"github.com/bcollard/jwt-signer-vault-jwks-bridge/internal/source/file"
	"github.com/bcollard/jwt-signer-vault-jwks-bridge/internal/source/vault"
	"github.com/bcollard/jwt-signer-vault-jwks-bridge/internal/telemetry"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

const usage = `jwks-bridge serves key pairs from a secret store to the Kong jwt-signer plugin.

Usage:
  jwks-bridge [serve] [flags]   run the bridge (default)
  jwks-bridge keygen [flags]    generate a key pair as a keyset entry
  jwks-bridge validate [flags]  validate a keyset document
  jwks-bridge version           print the version

Run "jwks-bridge <command> -h" for the flags of a command.
`

func main() {
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(args)
	case "keygen":
		err = keygenCmd(args, os.Stdout)
	case "validate":
		err = validateCmd(args, os.Stdin, os.Stdout)
	case "version":
		fmt.Printf("jwks-bridge %s (commit %s, built %s)\n", version, commit, date)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func newLogger(level, format string) (*slog.Logger, error) {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("log level: %w", err)
	}
	opts := &slog.HandlerOptions{Level: lvl}
	switch format {
	case "json":
		return slog.New(slog.NewJSONHandler(os.Stderr, opts)), nil
	case "text":
		return slog.New(slog.NewTextHandler(os.Stderr, opts)), nil
	}
	return nil, fmt.Errorf("unknown log format %q", format)
}

func serve(args []string) error {
	cfg, err := config.Load(args, os.Getenv, os.Stderr)
	if err != nil {
		return err
	}
	log, err := newLogger(cfg.LogLevel, cfg.LogFormat)
	if err != nil {
		return err
	}
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	shutdownTracing, err := telemetry.Setup(ctx, version)
	if err != nil {
		return fmt.Errorf("tracing: %w", err)
	}
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shutdownTracing(sctx)
	}()

	var src source.Source
	switch cfg.Source {
	case "file":
		src = file.New(cfg.FileDir)
	case "vault":
		vs, err := vault.New(vault.Config{
			Auth: cfg.VaultAuth, Role: cfg.VaultRole, AuthMount: cfg.VaultAuthMount,
			K8sTokenPath: cfg.VaultK8sTokenPath, RoleID: cfg.VaultAppRoleID, SecretIDFile: cfg.VaultAppRoleSecretIDF,
		}, log)
		if err != nil {
			return err
		}
		if err := vs.Start(ctx); err != nil {
			return err
		}
		src = vs
	}

	m := metrics.New()
	m.BuildInfo.WithLabelValues(version, commit).Set(1)
	c := cache.New(src, cache.Options{
		Keysets: cfg.Keysets, RefreshInterval: cfg.RefreshInterval, MaxStale: cfg.MaxStale,
		MinStageDuration: cfg.MinStageDuration, Log: log, Metrics: m,
	})

	auth := &server.Auth{MTLS: cfg.ClientCA != "", AllowedSANs: cfg.AllowedClientSANs, BasicUser: cfg.BasicUser, Log: log}
	if cfg.BasicPasswordFile != "" {
		pw, err := os.ReadFile(cfg.BasicPasswordFile) //nolint:gosec // path set by the operator
		if err != nil {
			return fmt.Errorf("read basic password: %w", err)
		}
		auth.BasicPassword = strings.TrimRight(string(pw), "\r\n")
		if auth.BasicPassword == "" {
			return errors.New("the basic password file is empty")
		}
	}
	srv := &server.Server{Cache: c, Metrics: m, Log: log, JWKSMaxAge: cfg.JWKSMaxAge, Auth: auth}

	// Initial load. Failures are not fatal: /readyz stays not ready and the
	// refresher keeps trying.
	if err := c.RefreshAll(ctx); err != nil {
		log.Error("initial keyset load failed", "err", err)
	}
	go c.Run(ctx)

	type listener struct {
		name string
		srv  *http.Server
		tls  bool
	}
	var listeners []listener
	newHTTP := func(addr string, h http.Handler) *http.Server {
		return &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
			WriteTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second,
			BaseContext: func(net.Listener) context.Context { return ctx }}
	}
	if cfg.PublicAddr != "" {
		listeners = append(listeners, listener{"public", newHTTP(cfg.PublicAddr, srv.Public()), false})
	}
	if cfg.PrivateAddr != "" {
		hs := newHTTP(cfg.PrivateAddr, srv.Private())
		useTLS := !cfg.PrivatePlaintext
		if useTLS {
			var tc *tls.Config
			if tc, err = server.TLSConfig(cfg.TLSCert, cfg.TLSKey, cfg.ClientCA); err != nil {
				return err
			}
			hs.TLSConfig = tc
		} else {
			log.Warn("the private listener serves private keys over plain HTTP; use this for local development only")
		}
		listeners = append(listeners, listener{"private", hs, useTLS})
	}
	if cfg.AdminAddr != "" {
		listeners = append(listeners, listener{"admin", newHTTP(cfg.AdminAddr, srv.Admin()), false})
	}

	errCh := make(chan error, len(listeners))
	for _, l := range listeners {
		log.Info("listening", "listener", l.name, "addr", l.srv.Addr, "tls", l.tls)
		go func() {
			var err error
			if l.tls {
				err = l.srv.ListenAndServeTLS("", "")
			} else {
				err = l.srv.ListenAndServe()
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("%s listener: %w", l.name, err)
			}
		}()
	}
	log.Info("jwks-bridge started", "version", version, "source", src.Name(), "keysets", cfg.KeysetNames())

	select {
	case <-ctx.Done():
	case err = <-errCh:
		log.Error("listener failed", "err", err)
	}
	log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, l := range listeners {
		_ = l.srv.Shutdown(sctx)
	}
	return err
}

func keygenCmd(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	alg := fs.String("alg", "RS256", "signing algorithm: "+strings.Join(keyset.SupportedAlgorithms, ", "))
	kid := fs.String("kid", "", "key id (default: a UTC timestamp)")
	status := fs.String("status", "staged", "key status: staged, active or retired")
	bits := fs.Int("bits", 2048, "RSA key size")
	doc := fs.Bool("doc", false, `wrap the entry in a document: {"keys":[entry]}`)
	if err := fs.Parse(args); err != nil {
		return err
	}
	e, err := keygen.Generate(keygen.Options{Alg: *alg, Kid: *kid, Status: keyset.Status(*status), RSABits: *bits})
	if err != nil {
		return err
	}
	var v any = e
	if *doc {
		v = keyset.Document{Keys: []keyset.Entry{e}}
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func validateCmd(args []string, in io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	path := fs.String("file", "-", "keyset document to validate, or - for stdin")
	minStage := fs.Duration("min-stage-duration", 10*time.Minute, "staging guard to apply")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var raw []byte
	var err error
	if *path == "-" {
		raw, err = io.ReadAll(in)
	} else {
		raw, err = os.ReadFile(*path)
	}
	if err != nil {
		return err
	}
	// Accept a bare array of entries as stored in the Vault "keys" field.
	if trimmed := strings.TrimSpace(string(raw)); strings.HasPrefix(trimmed, "[") {
		raw = []byte(`{"keys":` + trimmed + `}`)
	}
	doc, err := keyset.Parse(raw)
	if err != nil {
		return err
	}
	res, err := keyset.Resolve(doc, keyset.Options{MinStageDuration: *minStage})
	if err != nil {
		return err
	}
	for _, w := range res.Warnings {
		fmt.Fprintln(out, "warning:", w)
	}
	fmt.Fprintf(out, "valid: keyset order %v, public JWKS %v\n", res.PrivateKids, res.PublicKids)
	return nil
}
