package node

import (
	"os"
	"path/filepath"
	"testing"
)

// The panel is the only source of truth in remote mode, so a rotated
// certificate has to reach disk even though a file is already there.
func TestWriteFileIfChangedOverwritesRotatedMaterial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cert.pem")
	if err := writeFileIfChanged(path, []byte("first"), 0644); err != nil {
		t.Fatalf("initial write: %v", err)
	}
	if err := writeFileIfChanged(path, []byte("rotated"), 0644); err != nil {
		t.Fatalf("rotating write: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "rotated" {
		t.Fatalf("content = %q, want rotated", got)
	}
}

// os.WriteFile only honours perm when it creates the file, so a key left
// world-readable by an earlier cert mode has to be tightened explicitly.
func TestWriteFileIfChangedTightensPermissionsOnExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := writeFileIfChanged(path, []byte("rotated"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("perm = %o, want 600", info.Mode().Perm())
	}

	// Identical content still has to fix the mode rather than return early.
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	if err := writeFileIfChanged(path, []byte("rotated"), 0600); err != nil {
		t.Fatalf("idempotent write: %v", err)
	}
	if info, err = os.Stat(path); err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("perm after no-op write = %o, want 600", info.Mode().Perm())
	}
}

func TestWriteFileIfChangedSkipsIdenticalContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := writeFileIfChanged(path, []byte("same"), 0600); err != nil {
		t.Fatalf("initial write: %v", err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if err := writeFileIfChanged(path, []byte("same"), 0600); err != nil {
		t.Fatalf("second write: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("unchanged key material was rewritten")
	}
}
