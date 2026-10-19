package cache

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bcollard/jwt-signer-vault-jwks-bridge/internal/keygen"
	"github.com/bcollard/jwt-signer-vault-jwks-bridge/internal/keyset"
	"github.com/bcollard/jwt-signer-vault-jwks-bridge/internal/metrics"
)

type fakeSource struct {
	mu      sync.Mutex
	raw     []byte
	version string
	err     error
	delay   time.Duration
	calls   atomic.Int32
}

func (f *fakeSource) Name() string { return "fake" }

func (f *fakeSource) Load(context.Context, string) ([]byte, string, error) {
	f.calls.Add(1)
	time.Sleep(f.delay)
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.raw, f.version, f.err
}

func (f *fakeSource) Ping(context.Context) error { return nil }

func (f *fakeSource) set(raw []byte, version string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.raw, f.version, f.err = raw, version, err
}

func doc(t *testing.T, entries ...keyset.Entry) []byte {
	t.Helper()
	b, err := json.Marshal(keyset.Document{Keys: entries})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func entry(t *testing.T, kid string, st keyset.Status) keyset.Entry {
	t.Helper()
	e, err := keygen.Generate(keygen.Options{Alg: "ES256", Kid: kid, Status: st, Now: time.Unix(0, 0)})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newCache(src *fakeSource, clk *clock, maxStale time.Duration) *Cache {
	return New(src, Options{
		Keysets:  map[string]string{"default": "secret/x"},
		MaxStale: maxStale,
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Metrics:  metrics.New(),
		Now:      clk.now,
	})
}

func TestStaleIfError(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Unix(1000, 0)}
	src := &fakeSource{}
	src.set(doc(t, entry(t, "k1", keyset.StatusActive)), "1", nil)
	c := newCache(src, clk, time.Hour)

	if err := c.Ready(); !errors.Is(err, ErrNotLoaded) {
		t.Fatalf("Ready before load = %v", err)
	}
	if _, err := c.Get("default"); !errors.Is(err, ErrNotLoaded) {
		t.Fatalf("Get before load = %v", err)
	}
	if err := c.Refresh(ctx, "default"); err != nil {
		t.Fatal(err)
	}
	first, _ := c.Get("default")

	// Source down: the snapshot stays and readiness holds until max stale.
	src.set(nil, "", errors.New("connection refused"))
	clk.t = clk.t.Add(30 * time.Minute)
	if err := c.Refresh(ctx, "default"); err == nil {
		t.Fatal("expected refresh error")
	}
	if s, _ := c.Get("default"); s != first {
		t.Error("snapshot replaced after a source error")
	}
	if err := c.Ready(); err != nil {
		t.Errorf("Ready within max stale = %v", err)
	}
	clk.t = clk.t.Add(31 * time.Minute)
	if err := c.Ready(); err == nil {
		t.Error("Ready after max stale should fail")
	}

	// Invalid document: rejected, previous snapshot kept.
	src.set([]byte(`{"keys":[]}`), "2", nil)
	if err := c.Refresh(ctx, "default"); err == nil {
		t.Fatal("expected invalid document error")
	}
	if s, _ := c.Get("default"); s.Version != "1" {
		t.Errorf("version = %s after invalid document", s.Version)
	}

	// Source back with the same version: CheckedAt moves, content does not.
	src.set(doc(t, entry(t, "k1", keyset.StatusActive)), "1", nil)
	if err := c.Refresh(ctx, "default"); err != nil {
		t.Fatal(err)
	}
	s, _ := c.Get("default")
	if !s.CheckedAt.Equal(clk.t) || s.PrivateETag != first.PrivateETag {
		t.Errorf("unchanged refresh: checked=%s etag changed=%t", s.CheckedAt, s.PrivateETag != first.PrivateETag)
	}
	if err := c.Ready(); err != nil {
		t.Errorf("Ready after recovery = %v", err)
	}
}

func TestSingleflight(t *testing.T) {
	src := &fakeSource{delay: 50 * time.Millisecond}
	src.set(doc(t, entry(t, "k1", keyset.StatusActive)), "1", nil)
	c := newCache(src, &clock{t: time.Unix(0, 0)}, 0)

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = c.Refresh(context.Background(), "default")
		}()
	}
	wg.Wait()
	if n := src.calls.Load(); n != 1 {
		t.Errorf("source called %d times, want 1", n)
	}
}

func TestGuardReleasedWithoutNewVersion(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)}
	k1 := entry(t, "k1", keyset.StatusRetired)
	k2 := entry(t, "k2", keyset.StatusActive)
	staged := clk.t.Add(-time.Minute)
	k2.StagedAt = &staged

	src := &fakeSource{}
	src.set(doc(t, k1, k2), "5", nil)
	c := New(src, Options{
		Keysets:          map[string]string{"default": "x"},
		MinStageDuration: 10 * time.Minute,
		Log:              slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:              clk.now,
	})
	if err := c.Refresh(ctx, "default"); err != nil {
		t.Fatal(err)
	}
	if s, _ := c.Get("default"); strings.Join(s.PrivateKids, ",") != "k1,k2" {
		t.Fatalf("guarded order = %v", s.PrivateKids)
	}
	clk.t = clk.t.Add(10 * time.Minute)
	if err := c.Refresh(ctx, "default"); err != nil {
		t.Fatal(err)
	}
	if s, _ := c.Get("default"); strings.Join(s.PrivateKids, ",") != "k2,k1" {
		t.Fatalf("released order = %v", s.PrivateKids)
	}
}

func TestUnknownKeyset(t *testing.T) {
	c := newCache(&fakeSource{}, &clock{}, 0)
	if _, err := c.Get("nope"); !errors.Is(err, ErrUnknownKeyset) {
		t.Errorf("Get = %v", err)
	}
	if err := c.Refresh(context.Background(), "nope"); !errors.Is(err, ErrUnknownKeyset) {
		t.Errorf("Refresh = %v", err)
	}
}

func TestJitter(t *testing.T) {
	for range 100 {
		if d := jitter(time.Second); d < 900*time.Millisecond || d > 1100*time.Millisecond {
			t.Fatalf("jitter = %s", d)
		}
	}
}
