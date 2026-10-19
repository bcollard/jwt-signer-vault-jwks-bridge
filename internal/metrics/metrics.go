// Package metrics holds the Prometheus collectors exposed on the admin listener.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics groups the bridge collectors and their registry.
type Metrics struct {
	Registry        *prometheus.Registry
	SnapshotAge     *prometheus.GaugeVec
	RefreshTotal    *prometheus.CounterVec
	Keys            *prometheus.GaugeVec
	KeyInfo         *prometheus.GaugeVec
	RequestsTotal   *prometheus.CounterVec
	RequestDuration *prometheus.HistogramVec
	SourceErrors    *prometheus.CounterVec
	BuildInfo       *prometheus.GaugeVec
}

// New registers the collectors on a fresh registry, with Go and process
// collectors included.
func New() *Metrics {
	m := &Metrics{
		Registry: prometheus.NewRegistry(),
		SnapshotAge: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "jwksbridge_snapshot_age_seconds",
			Help: "Seconds since the keyset was last read successfully from the source.",
		}, []string{"keyset"}),
		RefreshTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "jwksbridge_refresh_total",
			Help: "Keyset refreshes by result (updated, unchanged, error, invalid).",
		}, []string{"keyset", "result"}),
		Keys: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "jwksbridge_keys",
			Help: "Keys in the served snapshot by status.",
		}, []string{"keyset", "status"}),
		KeyInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "jwksbridge_key_info",
			Help: "One series per key in the served snapshot; signing is true for the key Kong signs with.",
		}, []string{"keyset", "kid", "status", "signing"}),
		RequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "jwksbridge_requests_total",
			Help: "HTTP requests by endpoint and status code.",
		}, []string{"endpoint", "code"}),
		RequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "jwksbridge_request_duration_seconds",
			Help:    "HTTP request duration by endpoint.",
			Buckets: []float64{.0005, .001, .0025, .005, .01, .025, .05, .1, .25, .5, 1},
		}, []string{"endpoint"}),
		SourceErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "jwksbridge_source_errors_total",
			Help: "Errors returned by the secret source.",
		}, []string{"source"}),
		BuildInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "jwksbridge_build_info",
			Help: "Build information; always 1.",
		}, []string{"version", "commit"}),
	}
	m.Registry.MustRegister(
		m.SnapshotAge, m.RefreshTotal, m.Keys, m.KeyInfo, m.RequestsTotal, m.RequestDuration, m.SourceErrors, m.BuildInfo,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return m
}

// Handler serves the registry in the Prometheus exposition format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{Registry: m.Registry})
}
