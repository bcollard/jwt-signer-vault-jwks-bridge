package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"log/slog"
	"net/http"
	"slices"
)

// Auth authenticates callers of the private listener. A caller is accepted
// when it presents a client certificate verified against the client CA whose
// SAN is allowlisted (any SAN when the allowlist is empty), or valid Basic
// credentials. At least one method must be configured.
type Auth struct {
	// MTLS enables client certificate authentication. The TLS layer verifies
	// the chain; Auth checks the SAN allowlist.
	MTLS        bool
	AllowedSANs []string
	BasicUser   string
	// BasicPassword is compared in constant time.
	BasicPassword string
	Log           *slog.Logger
}

// Enabled reports whether any method is configured.
func (a *Auth) Enabled() bool {
	return a != nil && (a.MTLS || (a.BasicUser != "" && a.BasicPassword != ""))
}

// Wrap rejects unauthenticated requests.
func (a *Auth) Wrap(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.allowed(r) {
			next(w, r)
			return
		}
		if a.BasicUser != "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="jwks-bridge"`)
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		writeError(w, http.StatusForbidden, "client certificate required")
	}
}

func (a *Auth) allowed(r *http.Request) bool {
	if a == nil {
		return false
	}
	if a.MTLS && r.TLS != nil && len(r.TLS.VerifiedChains) > 0 {
		leaf := r.TLS.VerifiedChains[0][0]
		if len(a.AllowedSANs) == 0 || sanAllowed(leaf, a.AllowedSANs) {
			return true
		}
		if a.Log != nil {
			a.Log.Warn("client certificate SAN not allowed", "subject", leaf.Subject.String(), "dns", leaf.DNSNames, "uris", leaf.URIs)
		}
	}
	if a.BasicUser != "" && a.BasicPassword != "" {
		u, p, ok := r.BasicAuth()
		if ok && equal(u, a.BasicUser) && equal(p, a.BasicPassword) {
			return true
		}
	}
	return false
}

// equal compares two secrets in constant time, independent of their lengths.
func equal(a, b string) bool {
	ha, hb := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

func sanAllowed(cert *x509.Certificate, allowed []string) bool {
	names := append([]string{}, cert.DNSNames...)
	names = append(names, cert.EmailAddresses...)
	for _, u := range cert.URIs {
		names = append(names, u.String())
	}
	for _, ip := range cert.IPAddresses {
		names = append(names, ip.String())
	}
	if cert.Subject.CommonName != "" {
		names = append(names, cert.Subject.CommonName)
	}
	for _, n := range names {
		if slices.Contains(allowed, n) {
			return true
		}
	}
	return false
}
