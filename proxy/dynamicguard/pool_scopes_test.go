package dynamicguard

import (
	"net/netip"
	"sync"
	"testing"
)

func TestTenantPoolScenarios(t *testing.T) {
	settings := &DGSettings{
		IPPools:     map[string]string{"1": "10.0.0.0/24", "2": "10.0.0.64/26", "3": "10.0.0.64/27"},
		TenantPools: map[string]string{"2": "10.0.0.64/26", "3": "10.0.0.128/26"},
		ACL:         map[string]DGACL{"1": {OrgID: 1}, "2": {OrgID: 2}, "3": {OrgID: 2}},
	}
	pools, _, err := buildIPPools(settings)
	if err != nil {
		t.Fatal(err)
	}
	// Different networks owned by one customer share occupancy even when nested.
	seen := map[netip.Addr]bool{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, pool := range pools {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 24; i++ {
				ip, err := pool.Allocate()
				if err != nil {
					break
				}
				mu.Lock()
				if seen[ip] {
					t.Errorf("duplicate lease %s", ip)
				}
				seen[ip] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	// An internet network inherits the root, excluding all other customer
	// reservations, including customer 3 who has no attached network yet.
	for {
		ip, err := pools[1].Allocate()
		if err != nil {
			break
		}
		if netip.MustParsePrefix("10.0.0.64/26").Contains(ip) || netip.MustParsePrefix("10.0.0.128/26").Contains(ip) {
			t.Fatalf("shared allocation entered reservation: %s", ip)
		}
	}
	// Node-local state: a second DG serving the same network is independent.
	other, _, err := buildIPPools(settings)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = other[1].Allocate(); err != nil {
		t.Fatal("second node inherited the first node's occupancy")
	}
}

func TestEntireNodeReservationAndLeaseReuse(t *testing.T) {
	settings := &DGSettings{IPPools: map[string]string{"1": "10.0.0.0/29", "2": "10.0.0.0/29", "3": "10.0.0.0/29"}, TenantPools: map[string]string{"2": "10.0.0.0/29"}, ACL: map[string]DGACL{"1": {OrgID: 1}, "2": {OrgID: 2}, "3": {OrgID: 2}}}
	pools, _, err := buildIPPools(settings)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pools[1].Allocate(); err == nil {
		t.Fatal("whole-node reservation leaked to fallback customer")
	}
	ip, err := pools[2].Allocate()
	if err != nil {
		t.Fatal(err)
	}
	if pools[3].Reserve(ip) {
		t.Fatal("another network reserved an occupied address")
	}
	pools[3].Release(ip) // A different view must not release the owner's lease.
	if pools[3].Reserve(ip) {
		t.Fatal("foreign release freed an occupied address")
	}
	pools[2].Release(ip)
	if !pools[3].Reserve(ip) {
		t.Fatal("released address cannot be reused")
	}
}

func TestACLTenantIsolationPrecedesAllowRules(t *testing.T) {
	dt := leaseTable(t, map[string]int{"10.0.0.2": 1, "10.0.0.3": 2, "10.0.0.4": 3})
	// Use the table lock when changing the test fixture's trusted identity.
	dt.mu.Lock()
	dt.byIP[netip.MustParseAddr("10.0.0.3")].OrgID = 2
	dt.mu.Unlock()
	policy := newACLPolicy(map[string]DGACL{
		"1": {OrgID: 1, Default: "allow"},
		"2": {OrgID: 2, Default: "allow"},
		"3": {OrgID: 1, Default: "deny", Rules: []DGACLRule{{Action: "allow", CIDR: "192.168.1.0/24"}}},
	}, map[string]string{"2": "10.0.1.0/24"})
	inner := &fakeTUN{}
	a := newACLTUN(inner, dt, policy, false)
	writeAll(t, a,
		v4Packet("10.0.0.2", "10.0.0.3"), // foreign lease in the shared root
		v4Packet("10.0.0.2", "10.0.1.5"), // foreign reservation, no lease
		v4Packet("10.0.0.2", "8.8.8.8"),  // internet network
		v4Packet("10.0.0.4", "8.8.8.8"),  // same customer, different ACL
		v4Packet("10.0.0.4", "192.168.1.9"),
		v4Packet("10.0.0.99", "8.8.8.8"), // unknown source
	)
	wantDsts(t, inner, "8.8.8.8", "192.168.1.9")
	// A credential's customer must agree with the network's owner.
	policy.networks[1] = networkACL{org: 2, defaultAllow: true}
	writeAll(t, a, v4Packet("10.0.0.2", "8.8.8.8"))
	wantDsts(t, inner, "8.8.8.8", "192.168.1.9")
}
