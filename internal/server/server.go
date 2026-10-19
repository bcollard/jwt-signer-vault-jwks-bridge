// Package server implements the public, private and admin HTTP handlers.
package server

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"

	"github.com/bcollard/jwt-signer-vault-jwks-bridge/internal/cache"
	"github.com/bcollard/jwt-signer-vault-jwks-bridge/internal/metrics"
)

// ContentType is the media type of JWK Sets (RFC 7517).
const ContentType = "application/jwk-set+json"

// DefaultKeyset is the keyset served when a request names none.
const DefaultKeyset = "default"

// Server builds the HTTP handlers.
type Server struct {
	Cache      *cache.Cache
	Metrics    *metrics.Metrics
	Log        *slog.Logger
	JWKSMaxAge time.Duration
	Auth       *Auth
}

// Public serves the public JWKS and health endpoints. It never serves private
// key material.
func (s *Server) Public() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /jwks.json", s.instrument("jwks", s.servePublic))
	mux.Handle("GET /.well-known/jwks.json", s.instrument("jwks", s.servePublic))
	mux.Handle("GET /jwks/{name}", s.instrument("jwks", s.servePublic))
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /readyz", s.readyz)
	return otelhttp.NewHandler(mux, "public", otelhttp.WithSpanNameFormatter(spanName))
}

// Private serves the keyset with private members to authenticated callers.
func (s *Server) Private() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /keyset", s.instrument("keyset", s.Auth.Wrap(s.servePrivate)))
	mux.Handle("GET /keyset/{name}", s.instrument("keyset", s.Auth.Wrap(s.servePrivate)))
	mux.HandleFunc("GET /healthz", s.healthz)
	return otelhttp.NewHandler(mux, "private", otelhttp.WithSpanNameFormatter(spanName))
}

// Admin serves Prometheus metrics.
func (s *Server) Admin() http.Handler {
	mux := http.NewServeMux()
	metricsHandler := s.Metrics.Handler()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		s.Cache.UpdateAgeMetrics()
		metricsHandler.ServeHTTP(w, r)
	})
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /readyz", s.readyz)
	return mux
}

func spanName(_ string, r *http.Request) string {
	if r.Pattern != "" {
		return r.Pattern
	}
	return r.Method + " " + r.URL.Path
}

func keysetName(r *http.Request) string {
	if n := r.PathValue("name"); n != "" {
		return n
	}
	if n := r.URL.Query().Get("name"); n != "" {
		return n
	}
	return DefaultKeyset
}

func (s *Server) servePublic(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.snapshot(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(int(s.JWKSMaxAge.Seconds())))
	writeJWKS(w, r, snap.Public, snap.PublicETag)
}

func (s *Server) servePrivate(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.snapshot(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJWKS(w, r, snap.Private, snap.PrivateETag)
}

func (s *Server) snapshot(w http.ResponseWriter, r *http.Request) (*cache.Snapshot, bool) {
	name := keysetName(r)
	snap, err := s.Cache.Get(name)
	switch {
	case errors.Is(err, cache.ErrUnknownKeyset):
		writeError(w, http.StatusNotFound, fmt.Sprintf("unknown keyset %q", name))
		return nil, false
	case err != nil:
		writeError(w, http.StatusServiceUnavailable, fmt.Sprintf("keyset %q not loaded yet", name))
		return nil, false
	}
	return snap, true
}

func writeJWKS(w http.ResponseWriter, r *http.Request, body []byte, etag string) {
	w.Header().Set("ETag", etag)
	if etagMatches(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", ContentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}

func etagMatches(header, etag string) bool {
	if header == "" {
		return false
	}
	for _, t := range strings.Split(header, ",") {
		t = strings.TrimPrefix(strings.TrimSpace(t), "W/")
		if t == "*" || t == etag {
			return true
		}
	}
	return false
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_, _ = fmt.Fprintf(w, "{\"error\":%q}\n", msg)
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) readyz(w http.ResponseWriter, _ *http.Request) {
	if err := s.Cache.Ready(); err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("ok\n"))
}

type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.code = code
	r.ResponseWriter.WriteHeader(code)
}

// instrument records request metrics and a debug access log line with the
// trace id.
func (s *Server) instrument(endpoint string, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, code: http.StatusOK}
		next(rec, r)
		d := time.Since(start)
		if s.Metrics != nil {
			s.Metrics.RequestsTotal.WithLabelValues(endpoint, strconv.Itoa(rec.code)).Inc()
			s.Metrics.RequestDuration.WithLabelValues(endpoint).Observe(d.Seconds())
		}
		if s.Log != nil && s.Log.Enabled(r.Context(), slog.LevelDebug) {
			attrs := []any{"endpoint", endpoint, "keyset", keysetName(r), "code", rec.code, "duration", d, "remote", r.RemoteAddr}
			if sc := trace.SpanContextFromContext(r.Context()); sc.IsValid() {
				attrs = append(attrs, "trace_id", sc.TraceID().String(), "span_id", sc.SpanID().String())
			}
			s.Log.Debug("request", attrs...)
		}
	})
}
