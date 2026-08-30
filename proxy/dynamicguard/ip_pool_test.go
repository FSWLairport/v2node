package dynamicguard

import (
	"net/netip"
	"testing"
)

func TestIPPoolAllocateSequential(t *testing.T) {
	pool, err := NewIPPool("10.0.0.0/30")
	if err != nil {
		t.Fatalf("NewIPPool: %v", err)
	}
	// /30 = 4 addresses, -2 (network + broadcast) = 2 usable
	ip1, err := pool.Allocate()
	if err != nil {
		t.Fatalf("Allocate 1: %v", err)
	}
	if ip1 != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("expected 10.0.0.1, got %s", ip1)
	}

	ip2, err := pool.Allocate()
	if err != nil {
		t.Fatalf("Allocate 2: %v", err)
	}
	if ip2 != netip.MustParseAddr("10.0.0.2") {
		t.Fatalf("expected 10.0.0.2, got %s", ip2)
	}

	// Pool exhausted
	_, err = pool.Allocate()
	if err != errIPPoolExhausted {
		t.Fatalf("expected errIPPoolExhausted, got %v", err)
	}
}

func TestIPPoolAllocateAfterRelease(t *testing.T) {
	pool, err := NewIPPool("10.0.0.0/30")
	if err != nil {
		t.Fatalf("NewIPPool: %v", err)
	}

	ip1, _ := pool.Allocate()
	ip2, _ := pool.Allocate()

	// Release first IP
	pool.Release(ip1)

	// Should reallocate the released IP (lowest available)
	ip3, err := pool.Allocate()
	if err != nil {
		t.Fatalf("Allocate after release: %v", err)
	}
	if ip3 != ip1 {
		t.Fatalf("expected released IP %s, got %s", ip1, ip3)
	}
	_ = ip2
}

func TestIPPoolReserve(t *testing.T) {
	pool, err := NewIPPool("10.0.0.0/24")
	if err != nil {
		t.Fatalf("NewIPPool: %v", err)
	}

	target := netip.MustParseAddr("10.0.0.100")
	if !pool.Reserve(target) {
		t.Fatal("Reserve should succeed for unused IP")
	}

	// Double reserve should fail
	if pool.Reserve(target) {
		t.Fatal("Reserve should fail for already reserved IP")
	}

	// Allocate should skip the reserved IP
	ip1, _ := pool.Allocate()
	if ip1 != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("expected 10.0.0.1, got %s", ip1)
	}
}

func TestIPPoolReserveOutOfRange(t *testing.T) {
	pool, err := NewIPPool("10.0.0.0/24")
	if err != nil {
		t.Fatalf("NewIPPool: %v", err)
	}

	// Out of range IP
	if pool.Reserve(netip.MustParseAddr("192.168.1.1")) {
		t.Fatal("Reserve should fail for out-of-range IP")
	}
}

func TestIPPoolContains(t *testing.T) {
	pool, err := NewIPPool("10.0.0.0/24")
	if err != nil {
		t.Fatalf("NewIPPool: %v", err)
	}

	if !pool.Contains(netip.MustParseAddr("10.0.0.1")) {
		t.Fatal("should contain 10.0.0.1")
	}
	if !pool.Contains(netip.MustParseAddr("10.0.0.254")) {
		t.Fatal("should contain 10.0.0.254")
	}
	// Network address itself is excluded
	if pool.Contains(netip.MustParseAddr("10.0.0.0")) {
		t.Fatal("should not contain network address 10.0.0.0")
	}
	if pool.Contains(netip.MustParseAddr("10.0.1.1")) {
		t.Fatal("should not contain 10.0.1.1")
	}
}

func TestIPPoolPrefixBits(t *testing.T) {
	pool, err := NewIPPool("10.0.0.0/24")
	if err != nil {
		t.Fatalf("NewIPPool: %v", err)
	}
	if pool.PrefixBits() != 24 {
		t.Fatalf("expected 24, got %d", pool.PrefixBits())
	}
}

func TestIPPoolIPv6(t *testing.T) {
	pool, err := NewIPPool("fd00::/120")
	if err != nil {
		t.Fatalf("NewIPPool IPv6: %v", err)
	}
	// /120 = 256 - 2 = 254 usable
	ip1, err := pool.Allocate()
	if err != nil {
		t.Fatalf("Allocate IPv6: %v", err)
	}
	if ip1 != netip.MustParseAddr("fd00::1") {
		t.Fatalf("expected fd00::1, got %s", ip1)
	}

	if pool.PrefixBits() != 120 {
		t.Fatalf("expected 120, got %d", pool.PrefixBits())
	}
}

func TestIPPoolAddrAtIndexIPv4(t *testing.T) {
	pool, err := NewIPPool("10.77.0.0/16")
	if err != nil {
		t.Fatalf("NewIPPool: %v", err)
	}
	// base = 10.77.0.1, idx=0 → 10.77.0.1, idx=255 → 10.77.1.0
	got := pool.addrAtIndex(0)
	if got != netip.MustParseAddr("10.77.0.1") {
		t.Fatalf("idx=0: expected 10.77.0.1, got %s", got)
	}
	got = pool.addrAtIndex(255)
	if got != netip.MustParseAddr("10.77.1.0") {
		t.Fatalf("idx=255: expected 10.77.1.0, got %s", got)
	}
}

func TestIPPoolAddrAtIndexIPv6(t *testing.T) {
	pool, err := NewIPPool("fd00::/112")
	if err != nil {
		t.Fatalf("NewIPPool: %v", err)
	}
	got := pool.addrAtIndex(0)
	if got != netip.MustParseAddr("fd00::1") {
		t.Fatalf("idx=0: expected fd00::1, got %s", got)
	}
	got = pool.addrAtIndex(255)
	if got != netip.MustParseAddr("fd00::100") {
		t.Fatalf("idx=255: expected fd00::100, got %s", got)
	}
}

func TestIPPoolReleaseAndReallocate(t *testing.T) {
	pool, err := NewIPPool("10.0.0.0/29")
	if err != nil {
		t.Fatalf("NewIPPool: %v", err)
	}
	// /29 = 8 - 2 = 6 usable

	allocated := make([]netip.Addr, 0, 6)
	for i := 0; i < 6; i++ {
		ip, err := pool.Allocate()
		if err != nil {
			t.Fatalf("Allocate %d: %v", i, err)
		}
		allocated = append(allocated, ip)
	}

	// Release middle one
	pool.Release(allocated[2])

	// Should get it back
	ip, err := pool.Allocate()
	if err != nil {
		t.Fatalf("Allocate after release: %v", err)
	}
	if ip != allocated[2] {
		t.Fatalf("expected %s, got %s", allocated[2], ip)
	}
}

func TestNewIPPoolRejectsTooSmall(t *testing.T) {
	_, err := NewIPPool("10.0.0.0/31")
	if err != errIPPoolExhausted {
		t.Fatalf("expected errIPPoolExhausted for /31, got %v", err)
	}

	_, err = NewIPPool("10.0.0.0/32")
	if err != errIPPoolExhausted {
		t.Fatalf("expected errIPPoolExhausted for /32, got %v", err)
	}
}

func TestNewIPPoolRejectsInvalidCIDR(t *testing.T) {
	_, err := NewIPPool("invalid")
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}
