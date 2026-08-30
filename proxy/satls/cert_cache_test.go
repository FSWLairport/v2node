package satls

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeKeypair(t *testing.T, dir, domain string) (string, string) {
	t.Helper()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := generateSelfSigned(domain, certPath, keyPath); err != nil {
		t.Fatalf("generateSelfSigned: %v", err)
	}
	return certPath, keyPath
}

func TestCertCacheReusesUntilFilesChange(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeKeypair(t, dir, "up.example.com")
	cache := newCertCache(certPath, keyPath)

	first, err := cache.get()
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	again, err := cache.get()
	if err != nil {
		t.Fatalf("second get: %v", err)
	}
	if first != again {
		t.Fatal("an unchanged keypair was reloaded from disk")
	}

	// A rotation replaces both files; the next handshake must see the new one.
	time.Sleep(10 * time.Millisecond)
	if err := generateSelfSigned("rotated.example.com", certPath, keyPath); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	rotated, err := cache.get()
	if err != nil {
		t.Fatalf("get after rotation: %v", err)
	}
	if rotated == first {
		t.Fatal("a rotated keypair was not picked up")
	}
}

func TestCertCacheKeepsLastGoodDuringTornWrite(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeKeypair(t, dir, "up.example.com")
	cache := newCertCache(certPath, keyPath)

	loaded, err := cache.get()
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	// The certificate has landed but the key has not yet been rewritten. The
	// handshake must not fail into the main certificate under the wrong SNI.
	if err := os.WriteFile(keyPath, []byte("-----BEGIN PRIVATE KEY-----\ntruncated\n"), 0600); err != nil {
		t.Fatalf("truncate key: %v", err)
	}
	stale, err := cache.get()
	if err != nil {
		t.Fatalf("get during torn write: %v", err)
	}
	if stale != loaded {
		t.Fatal("a torn write should keep serving the last good keypair")
	}
}

func TestCertCacheNilWithoutPaths(t *testing.T) {
	if newCertCache("", "/tmp/key.pem") != nil || newCertCache("/tmp/cert.pem", "") != nil {
		t.Fatal("a cache without both paths must be nil so callers skip it")
	}
}

func TestCertCacheReportsFirstLoadFailure(t *testing.T) {
	dir := t.TempDir()
	cache := newCertCache(filepath.Join(dir, "missing.pem"), filepath.Join(dir, "missing.key"))
	if _, err := cache.get(); err == nil {
		t.Fatal("a first load with no files on disk must fail")
	}
}
