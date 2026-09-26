package dynamicguard

import (
	"testing"
	"time"
)

func TestIdempotencyCacheSetAndGet(t *testing.T) {
	c := NewIdempotencyCache()
	defer c.Close()

	key := [32]byte{1, 2, 3}
	reply := []byte("test-reply")
	c.Set(key, reply)

	got, ok := c.Get(key)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if string(got) != "test-reply" {
		t.Fatalf("expected 'test-reply', got %q", string(got))
	}
}

func TestIdempotencyCacheMiss(t *testing.T) {
	c := NewIdempotencyCache()
	defer c.Close()

	_, ok := c.Get([32]byte{99})
	if ok {
		t.Fatal("expected cache miss for unknown key")
	}
}

func TestIdempotencyCacheExpiry(t *testing.T) {
	c := NewIdempotencyCache()
	defer c.Close()

	key := [32]byte{1}
	c.Set(key, []byte("data"))

	// Manually expire by storing an old entry
	c.entries.Store(key, &idemEntry{
		reply:     []byte("old-data"),
		createdAt: time.Now().Add(-2 * idemCacheTTL),
	})

	_, ok := c.Get(key)
	if ok {
		t.Fatal("expected cache miss for expired entry")
	}
}

func TestIdempotencyCacheOverwrite(t *testing.T) {
	c := NewIdempotencyCache()
	defer c.Close()

	key := [32]byte{1}
	c.Set(key, []byte("v1"))
	c.Set(key, []byte("v2"))

	got, ok := c.Get(key)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if string(got) != "v2" {
		t.Fatalf("expected 'v2', got %q", string(got))
	}
}
