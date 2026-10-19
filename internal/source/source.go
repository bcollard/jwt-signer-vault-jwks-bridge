// Package source defines where stored keyset documents are read from.
package source

import (
	"context"
	"errors"
)

// Source reads stored keyset documents.
type Source interface {
	// Name identifies the source in logs and metrics, for example "vault".
	Name() string
	// Load returns the raw document stored at path and a version token. The
	// token changes whenever the document changes (for example the KV v2
	// version), so callers can skip parsing an unchanged document.
	Load(ctx context.Context, path string) (raw []byte, version string, err error)
	// Ping checks connectivity.
	Ping(ctx context.Context) error
}

// ErrNotFound is returned by Load when nothing is stored at the path.
var ErrNotFound = errors.New("keyset not found in source")
