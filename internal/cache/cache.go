// Package cache keeps one immutable snapshot per keyset and refreshes it from
// the source in the background.
package cache

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"golang.org/x/sync/singleflight"

	"github.com/bcollard/jwt-signer-vault-jwks-bridge/internal/keyset"
	"github.com/bcollard/jwt-signer-vault-jwks-bridge/internal/metrics"
	"github.com/bcollard/jwt-signer-vault-jwks-bridge/internal/source"
)

// Snapshot is an immutable view of one keyset. Handlers read it without locks.
type Snapshot struct {
	Name        string
	Version     string
	Private     []byte
	PrivateETag string
	Public      []byte
	PublicETag  string
	PrivateKids []string
	PublicKids  []string
	Counts      map[keyset.Status]int
	// LoadedAt is when the content last changed; CheckedAt is when the source
	// last confirmed it.
	LoadedAt  time.Time
	CheckedAt time.Time

	doc          *keyset.Document
	guardedUntil time.Time
}

// Options configure a Cache.
type Options struct {
	// Keysets maps a keyset name to its source path.
	Keysets          map[string]string
	RefreshInterval  time.Duration
	MaxStale         time.Duration
	MinStageDuration time.Duration
	Log              *slog.Logger
	Metrics          *metrics.Metrics
	// Now is the clock; tests replace it.
	Now func() time.Time
}

// Cache holds the snapshots.
type Cache struct {
	src   source.Source
	opts  Options
	snaps map[string]*atomic.Pointer[Snapshot]
	group singleflight.Group
	log   *slog.Logger
}

// ErrUnknownKeyset is returned for a name that is not configured.
var ErrUnknownKeyset = errors.New("unknown keyset")

// ErrNotLoaded is returned when a keyset has never loaded successfully.
var ErrNotLoaded = errors.New("keyset not loaded yet")

// New builds a cache. Nothing is loaded until Refresh or Run is called.
func New(src source.Source, opts Options) *Cache {
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.RefreshInterval <= 0 {
		opts.RefreshInterval = 30 * time.Second
	}
	c := &Cache{src: src, opts: opts, snaps: map[string]*atomic.Pointer[Snapshot]{}, log: opts.Log}
	for name := range opts.Keysets {
		c.snaps[name] = &atomic.Pointer[Snapshot]{}
	}
	return c
}

// Names returns the configured keyset names, sorted.
func (c *Cache) Names() []string {
	names := make([]string, 0, len(c.snaps))
	for n := range c.snaps {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Get returns the current snapshot of a keyset.
func (c *Cache) Get(name string) (*Snapshot, error) {
	p, ok := c.snaps[name]
	if !ok {
		return nil, ErrUnknownKeyset
	}
	s := p.Load()
	if s == nil {
		return nil, ErrNotLoaded
	}
	return s, nil
}

// Ready reports an error when a keyset has never loaded or its snapshot has
// not been confirmed by the source for longer than MaxStale.
func (c *Cache) Ready() error {
	now := c.opts.Now()
	for _, name := range c.Names() {
		s := c.snaps[name].Load()
		if s == nil {
			return fmt.Errorf("keyset %q: %w", name, ErrNotLoaded)
		}
		if c.opts.MaxStale > 0 && now.Sub(s.CheckedAt) > c.opts.MaxStale {
			return fmt.Errorf("keyset %q is stale: last confirmed %s ago", name, now.Sub(s.CheckedAt).Round(time.Second))
		}
	}
	return nil
}

// RefreshAll refreshes every keyset once and returns the joined errors.
func (c *Cache) RefreshAll(ctx context.Context) error {
	var errs []error
	for _, name := range c.Names() {
		if err := c.Refresh(ctx, name); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Refresh reads one keyset from the source. Concurrent calls for the same
// keyset share one read. On error the previous snapshot stays in place.
func (c *Cache) Refresh(ctx context.Context, name string) error {
	if _, ok := c.snaps[name]; !ok {
		return ErrUnknownKeyset
	}
	_, err, _ := c.group.Do(name, func() (any, error) {
		return nil, c.refresh(ctx, name)
	})
	return err
}

func (c *Cache) refresh(ctx context.Context, name string) (err error) {
	ctx, span := otel.Tracer("jwks-bridge/cache").Start(ctx, "keyset.refresh")
	span.SetAttributes(attribute.String("keyset.name", name), attribute.String("source", c.src.Name()))
	defer func() {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()

	path := c.opts.Keysets[name]
	ptr := c.snaps[name]
	prev := ptr.Load()
	now := c.opts.Now()

	raw, version, err := c.src.Load(ctx, path)
	if err != nil {
		c.count(name, "error")
		if m := c.opts.Metrics; m != nil {
			m.SourceErrors.WithLabelValues(c.src.Name()).Inc()
		}
		return fmt.Errorf("load keyset %q from %s: %w", name, path, err)
	}

	doc := (*keyset.Document)(nil)
	if prev != nil && version != "" && version == prev.Version {
		if prev.guardedUntil.IsZero() || now.Before(prev.guardedUntil) {
			next := *prev
			next.CheckedAt = now
			ptr.Store(&next)
			c.count(name, "unchanged")
			c.observe(&next)
			return nil
		}
		// The staging guard expired: resolve the same document again.
		doc = prev.doc
	}
	if doc == nil {
		if doc, err = keyset.Parse(raw); err != nil {
			c.count(name, "invalid")
			return fmt.Errorf("keyset %q: %w", name, err)
		}
	}

	res, err := keyset.Resolve(doc, keyset.Options{Now: now, MinStageDuration: c.opts.MinStageDuration})
	if err != nil {
		c.count(name, "invalid")
		return fmt.Errorf("keyset %q rejected, keeping the previous snapshot: %w", name, err)
	}
	for _, w := range res.Warnings {
		c.log.Warn(w, "keyset", name)
	}

	next := &Snapshot{
		Name: name, Version: version,
		Private: res.Private, PrivateETag: keyset.ETag(res.Private),
		Public: res.Public, PublicETag: keyset.ETag(res.Public),
		PrivateKids: res.PrivateKids, PublicKids: res.PublicKids,
		Counts: res.Counts, LoadedAt: now, CheckedAt: now,
		doc: doc, guardedUntil: res.GuardedUntil,
	}
	if prev != nil && prev.PrivateETag == next.PrivateETag && prev.PublicETag == next.PublicETag {
		next.LoadedAt = prev.LoadedAt
	}
	ptr.Store(next)
	c.count(name, "updated")
	c.observe(next)
	if prev == nil || prev.PrivateETag != next.PrivateETag || prev.PublicETag != next.PublicETag {
		c.log.Info("keyset loaded", "keyset", name, "version", version,
			"signing_order", next.PrivateKids, "public", next.PublicKids)
	}
	span.SetAttributes(attribute.String("keyset.version", version))
	return nil
}

func (c *Cache) count(name, result string) {
	if m := c.opts.Metrics; m != nil {
		m.RefreshTotal.WithLabelValues(name, result).Inc()
	}
}

func (c *Cache) observe(s *Snapshot) {
	m := c.opts.Metrics
	if m == nil {
		return
	}
	for _, st := range []keyset.Status{keyset.StatusStaged, keyset.StatusActive, keyset.StatusRetired} {
		m.Keys.WithLabelValues(s.Name, string(st)).Set(float64(s.Counts[st]))
	}
	m.KeyInfo.DeletePartialMatch(prometheus.Labels{"keyset": s.Name})
	signing := ""
	if len(s.PrivateKids) > 0 {
		signing = s.PrivateKids[0]
	}
	for _, e := range s.doc.Keys {
		m.KeyInfo.WithLabelValues(s.Name, e.Kid, string(e.Status), strconv.FormatBool(e.Kid == signing)).Set(1)
	}
}

// UpdateAgeMetrics sets the snapshot age gauge for every keyset.
func (c *Cache) UpdateAgeMetrics() {
	m := c.opts.Metrics
	if m == nil {
		return
	}
	now := c.opts.Now()
	for _, name := range c.Names() {
		if s := c.snaps[name].Load(); s != nil {
			m.SnapshotAge.WithLabelValues(name).Set(now.Sub(s.CheckedAt).Seconds())
		}
	}
}

// Run refreshes every keyset on its own jittered timer until ctx is done.
func (c *Cache) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, name := range c.Names() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(jitter(c.opts.RefreshInterval)):
				}
				if err := c.Refresh(ctx, name); err != nil && ctx.Err() == nil {
					c.log.Error("keyset refresh failed", "keyset", name, "err", err)
				}
				c.UpdateAgeMetrics()
			}
		}()
	}
	wg.Wait()
}

// jitter returns d ± 10 %.
func jitter(d time.Duration) time.Duration {
	return d + time.Duration((rand.Float64()*0.2-0.1)*float64(d)) //nolint:gosec // jitter needs no crypto randomness
}
