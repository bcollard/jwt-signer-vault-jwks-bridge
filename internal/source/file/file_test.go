package file

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/bcollard/jwt-signer-vault-jwks-bridge/internal/source"
)

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "default.json")
	if err := os.WriteFile(p, []byte(`{"keys":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s := New(dir)
	raw, v1, err := s.Load(context.Background(), "default.json")
	if err != nil || string(raw) != `{"keys":[]}` || v1 == "" {
		t.Fatalf("Load = %q, %q, %v", raw, v1, err)
	}
	if err := os.WriteFile(p, []byte(`{"keys":[ ]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, v2, _ := s.Load(context.Background(), p); v2 == v1 {
		t.Error("version did not change with content")
	}
	if _, _, err := s.Load(context.Background(), "missing.json"); !errors.Is(err, source.ErrNotFound) {
		t.Errorf("missing file err = %v", err)
	}
	if err := s.Ping(context.Background()); err != nil {
		t.Errorf("Ping = %v", err)
	}
}
