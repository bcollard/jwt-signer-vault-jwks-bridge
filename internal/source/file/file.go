// Package file reads keyset documents from JSON files. It is meant for tests
// and local demos.
package file

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/bcollard/jwt-signer-vault-jwks-bridge/internal/source"
)

// Source reads keyset paths relative to Dir. Absolute paths are used as is.
type Source struct {
	Dir string
}

// New returns a file source rooted at dir.
func New(dir string) *Source { return &Source{Dir: dir} }

func (s *Source) Name() string { return "file" }

func (s *Source) resolve(path string) string {
	if filepath.IsAbs(path) || s.Dir == "" {
		return path
	}
	return filepath.Join(s.Dir, path)
}

func (s *Source) Load(_ context.Context, path string) ([]byte, string, error) {
	raw, err := os.ReadFile(s.resolve(path))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, "", fmt.Errorf("%w: %s", source.ErrNotFound, path)
	}
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:8]), nil
}

func (s *Source) Ping(context.Context) error {
	if s.Dir == "" {
		return nil
	}
	_, err := os.Stat(s.Dir)
	return err
}
