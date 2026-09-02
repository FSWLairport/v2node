package dynamicguard

import (
	"encoding/json"
	"net/netip"
	"os"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/tun"
)

// fakeTUN records what the ACL layer decided to forward.
type fakeTUN struct {
	written [][]byte
	calls   int
	// countOnly skips recording so allocation tests only measure the ACL layer.
	countOnly bool
}

func (f *fakeTUN) File() *os.File { return nil }
func (f *fakeTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	return 0, nil
}
func (f *fakeTUN) Write(bufs [][]byte, offset int) (int, error) {
	f.calls++
	if f.countOnly {
		return len(bufs), nil
	}
	for _, b := range bufs {
		pkt := make([]byte, len(b)-offset)
		copy(pkt, b[offset:])
		f.written = append(f.written, pkt)
	}
	return len(bufs), nil
}
func (f *fakeTUN) MTU() (int, error)        { return 1420, nil }
func (f *fakeTUN) Name() (string, error)    { return "fake0", nil }
func (f *fakeTUN) Events() <-chan tun.Event { return nil }
func (f *fakeTUN) Close() error             { return nil }
func (f *fakeTUN) BatchSize() int           { return 8 }
func (f *fakeTUN) dsts() []netip.Addr {
	out := make([]netip.Addr, 0, len(f.written))
	for _, p := range f.written {
		_, dst, ok := packetAddrs(p)
		if ok {
			out = append(out, dst)
		}
	}
	return out
}

const testOffset = 16 // mirrors MessageTransportOffsetContent: packets start mid-buffer

func v4Packet(src, dst string) []byte {
	buf := make([]byte, testOffset+20)
	pkt := buf[testOffset:]
	pkt[0] = 4 << 4
	copy(pkt[12:16], netip.MustParseAddr(src).AsSlice())
	copy(pkt[16:20], netip.MustParseAddr(dst).AsSlice())
	return buf
}

func v6Packet(src, dst string) []byte {
	buf := make([]byte, testOffset+40)
	pkt := buf[testOffset:]
	pkt[0] = 6 << 4
	copy(pkt[8:24], netip.MustParseAddr(src).AsSlice())
	copy(pkt[24:40], netip.MustParseAddr(dst).AsSlice())
	return buf
}

// leaseTable registers one device per address so the ACL layer can map a
// packet source back to its network.
func leaseTable(t *testing.T, leases map[string]int) *DeviceTable {
	t.Helper()
	dt := NewDeviceTable()
	i := byte(0)
	for addr, group := range leases {
		i++
		entry := &DeviceEntry{
			UserID:     int(i),
			DeviceID:   [16]byte{i},
			AssignedIP: netip.MustParseAddr(addr),
			GroupID:    group,
			Status:     DeviceStatusActive,
		}
		entry.WGStaticPub[0] = i
		if err := dt.Register(entry); err != nil {
			t.Fatalf("register %s: %v", addr, err)
		}
	}
	return dt
}

func writeAll(t *testing.T, a *aclTUN, pkts ...[]byte) {
	t.Helper()
	if _, err := a.Write(pkts, testOffset); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func wantDsts(t *testing.T, inner *fakeTUN, want ...string) {
	t.Helper()
	got := inner.dsts()
	if len(got) != len(want) {
		t.Fatalf("forwarded %v, want %v", got, want)
	}
	for i, w := range want {
		if got[i] != netip.MustParseAddr(w) {
			t.Fatalf("forwarded[%d]=%s, want %s", i, got[i], w)
		}
	}
}

// TestACLWireShape pins the payload shape the panel sends: "acl" sits next to
// "ip_pools" and is keyed by the same network ids.
func TestACLWireShape(t *testing.T) {
	const payload = `{
	  "server_wg_key_path": "/k", "server_wg_public_key": "p", "lease_ttl": 3600,
	  "ip_pools": {"12": "100.64.0.0/16", "13": "100.64.0.0/16"},
	  "routes": ["0.0.0.0/0"],
	  "acl": {
	    "12": {"default": "allow", "rules": [{"action": "deny", "cidr": "169.254.169.254/32"}]},
	    "13": {"default": "deny", "rules": [{"action": "allow", "cidr": "192.168.7.0/24"}]}
	  },
	  "cookie_enabled": true, "pow_difficulty": 18, "mtu": 1420
	}`
	var settings DGSettings
	if err := json.Unmarshal([]byte(payload), &settings); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if settings.ACL["12"].Default != "allow" || settings.ACL["12"].Rules[0].CIDR != "169.254.169.254/32" {
		t.Fatalf("network 12 decoded as %+v", settings.ACL["12"])
	}
	if settings.ACL["13"].Default != "deny" || settings.ACL["13"].Rules[0].Action != "allow" {
		t.Fatalf("network 13 decoded as %+v", settings.ACL["13"])
	}

	policy := newACLPolicy(settings.ACL)
	if policy.allows(12, netip.MustParseAddr("169.254.169.254")) {
		t.Fatal("metadata endpoint allowed for network 12")
	}
	if !policy.allows(13, netip.MustParseAddr("192.168.7.1")) {
		t.Fatal("allow exception not honoured for network 13")
	}
}

func TestACLPolicyAllAllowIsDisabled(t *testing.T) {
	// Absent ACL and an all-allow ACL must both compile to "no enforcement",
	// so an upgraded node behaves exactly like today.
	if p := newACLPolicy(nil); p != nil {
		t.Fatal("nil ACL should compile to no policy")
	}
	if p := newACLPolicy(map[string]DGACL{"12": {Default: "allow"}}); p != nil {
		t.Fatal("allow with no rules should compile to no policy")
	}

	inner := &fakeTUN{}
	a := newACLTUN(inner, NewDeviceTable(), nil, false)
	// No leases registered either: without a policy nothing is inspected.
	writeAll(t, a, v4Packet("100.64.0.5", "169.254.169.254"))
	wantDsts(t, inner, "169.254.169.254")
	if a.Dropped() != 0 {
		t.Fatalf("dropped %d packets without a policy", a.Dropped())
	}
}

func TestACLDefaultAllowWithDenyRules(t *testing.T) {
	inner := &fakeTUN{}
	dt := leaseTable(t, map[string]int{"100.64.0.5": 12})
	policy := newACLPolicy(map[string]DGACL{"12": {
		Default: "allow",
		Rules: []DGACLRule{
			{Action: "deny", CIDR: "169.254.169.254/32"},
			{Action: "deny", CIDR: "10.10.0.0/16"},
		},
	}})
	a := newACLTUN(inner, dt, policy, false)

	writeAll(t, a,
		v4Packet("100.64.0.5", "169.254.169.254"),
		v4Packet("100.64.0.5", "1.1.1.1"),
		v4Packet("100.64.0.5", "10.10.7.9"),
		v4Packet("100.64.0.5", "10.11.0.1"),
	)
	wantDsts(t, inner, "1.1.1.1", "10.11.0.1")
	if a.Dropped() != 2 {
		t.Fatalf("dropped=%d, want 2", a.Dropped())
	}
}

func TestACLDefaultDenyWithAllowException(t *testing.T) {
	inner := &fakeTUN{}
	dt := leaseTable(t, map[string]int{"100.64.0.9": 13})
	policy := newACLPolicy(map[string]DGACL{"13": {
		Default: "deny",
		Rules:   []DGACLRule{{Action: "allow", CIDR: "192.168.7.0/24"}},
	}})
	a := newACLTUN(inner, dt, policy, false)

	writeAll(t, a,
		v4Packet("100.64.0.9", "192.168.7.20"),
		v4Packet("100.64.0.9", "192.168.8.20"),
		v4Packet("100.64.0.9", "8.8.8.8"),
	)
	wantDsts(t, inner, "192.168.7.20")
}

func TestACLFirstMatchWins(t *testing.T) {
	inner := &fakeTUN{}
	dt := leaseTable(t, map[string]int{"100.64.0.5": 12})
	policy := newACLPolicy(map[string]DGACL{"12": {
		Default: "deny",
		Rules: []DGACLRule{
			{Action: "allow", CIDR: "10.0.0.0/24"},
			{Action: "deny", CIDR: "10.0.0.0/8"}, // shadowed for 10.0.0.0/24
		},
	}})
	a := newACLTUN(inner, dt, policy, false)

	writeAll(t, a,
		v4Packet("100.64.0.5", "10.0.0.7"),
		v4Packet("100.64.0.5", "10.1.0.7"),
	)
	wantDsts(t, inner, "10.0.0.7")
}

func TestACLIPv6(t *testing.T) {
	inner := &fakeTUN{}
	dt := leaseTable(t, map[string]int{"fd00::5": 12})
	policy := newACLPolicy(map[string]DGACL{"12": {
		Default: "allow",
		Rules: []DGACLRule{
			{Action: "deny", CIDR: "fd00:dead::/32"},
			{Action: "deny", CIDR: "2001:db8::1/128"},
		},
	}})
	a := newACLTUN(inner, dt, policy, false)

	writeAll(t, a,
		v6Packet("fd00::5", "fd00:dead::1"),
		v6Packet("fd00::5", "2001:db8::1"),
		v6Packet("fd00::5", "2001:db8::2"),
	)
	wantDsts(t, inner, "2001:db8::2")
}

func TestACLMalformedPacketsDropped(t *testing.T) {
	inner := &fakeTUN{}
	dt := leaseTable(t, map[string]int{"100.64.0.5": 12})
	policy := newACLPolicy(map[string]DGACL{"12": {Default: "deny"}})
	a := newACLTUN(inner, dt, policy, false)

	short := make([]byte, testOffset+10)
	short[testOffset] = 4 << 4
	badVersion := v4Packet("100.64.0.5", "1.1.1.1")
	badVersion[testOffset] = 9 << 4
	empty := make([]byte, testOffset)

	writeAll(t, a, short, badVersion, empty)
	if len(inner.written) != 0 {
		t.Fatalf("forwarded %d malformed packets", len(inner.written))
	}
	if a.Dropped() != 3 {
		t.Fatalf("dropped=%d, want 3", a.Dropped())
	}
}

func TestACLPerNetworkSelection(t *testing.T) {
	inner := &fakeTUN{}
	// Both networks share one CIDR, so only the lease's group can tell them
	// apart; the ACL must never be unioned across networks.
	dt := leaseTable(t, map[string]int{"100.64.0.5": 12, "100.64.0.6": 13})
	policy := newACLPolicy(map[string]DGACL{
		"12": {Default: "allow", Rules: []DGACLRule{{Action: "deny", CIDR: "10.10.0.0/16"}}},
		"13": {Default: "deny", Rules: []DGACLRule{{Action: "allow", CIDR: "10.10.0.0/16"}}},
	})
	a := newACLTUN(inner, dt, policy, false)

	writeAll(t, a,
		v4Packet("100.64.0.5", "10.10.0.1"), // denied for network 12
		v4Packet("100.64.0.6", "10.10.0.1"), // allowed for network 13
		v4Packet("100.64.0.5", "8.8.8.8"),   // allowed for network 12
		v4Packet("100.64.0.6", "8.8.8.8"),   // denied for network 13
		v4Packet("100.64.0.7", "8.8.8.8"),   // no lease: unknown network
	)
	wantDsts(t, inner, "10.10.0.1", "8.8.8.8")
	if a.Dropped() != 3 {
		t.Fatalf("dropped=%d, want 3", a.Dropped())
	}
}

func TestACLNetworkWithoutConfigIsUnfiltered(t *testing.T) {
	inner := &fakeTUN{}
	dt := leaseTable(t, map[string]int{"100.64.0.5": 12, "100.64.0.6": 99})
	policy := newACLPolicy(map[string]DGACL{
		"12": {Default: "deny"},
	})
	a := newACLTUN(inner, dt, policy, false)

	writeAll(t, a,
		v4Packet("100.64.0.5", "8.8.8.8"),
		v4Packet("100.64.0.6", "8.8.8.8"),
	)
	if len(inner.written) != 1 {
		t.Fatalf("forwarded %d packets, want 1", len(inner.written))
	}
}

func TestACLUnknownValuesDeny(t *testing.T) {
	inner := &fakeTUN{}
	dt := leaseTable(t, map[string]int{"100.64.0.5": 12})
	policy := newACLPolicy(map[string]DGACL{"12": {
		Default: "banana",
		Rules:   []DGACLRule{{Action: "maybe", CIDR: "8.8.8.0/24"}},
	}})
	if policy == nil {
		t.Fatal("unknown default must not compile to no policy")
	}
	a := newACLTUN(inner, dt, policy, false)

	writeAll(t, a,
		v4Packet("100.64.0.5", "8.8.8.8"),
		v4Packet("100.64.0.5", "1.1.1.1"),
	)
	if len(inner.written) != 0 {
		t.Fatalf("unknown allow/deny values let %d packets through", len(inner.written))
	}
}

func TestACLPolicySwapTakesEffect(t *testing.T) {
	inner := &fakeTUN{}
	dt := leaseTable(t, map[string]int{"100.64.0.5": 12})
	a := newACLTUN(inner, dt, newACLPolicy(map[string]DGACL{
		"12": {Default: "allow", Rules: []DGACLRule{{Action: "deny", CIDR: "10.0.0.0/8"}}},
	}), false)

	writeAll(t, a, v4Packet("100.64.0.5", "10.0.0.1"))
	if len(inner.written) != 0 {
		t.Fatal("packet passed a deny rule")
	}

	a.SetPolicy(newACLPolicy(map[string]DGACL{
		"12": {Default: "allow", Rules: []DGACLRule{{Action: "allow", CIDR: "10.0.0.0/8"}}},
	}))
	writeAll(t, a, v4Packet("100.64.0.5", "10.0.0.1"))
	wantDsts(t, inner, "10.0.0.1")

	// Clearing the policy restores the unfiltered fast path.
	a.SetPolicy(nil)
	writeAll(t, a, v4Packet("100.64.0.5", "10.0.0.1"))
	wantDsts(t, inner, "10.0.0.1", "10.0.0.1")
}

func TestACLAllAllowedSkipsCopy(t *testing.T) {
	// When nothing is dropped the caller's slice must be handed to the inner
	// device untouched, which is what keeps the hot path allocation free.
	inner := &fakeTUN{countOnly: true}
	dt := leaseTable(t, map[string]int{"100.64.0.5": 12})
	a := newACLTUN(inner, dt, newACLPolicy(map[string]DGACL{
		"12": {Default: "allow", Rules: []DGACLRule{{Action: "deny", CIDR: "10.0.0.0/8"}}},
	}), false)

	bufs := [][]byte{v4Packet("100.64.0.5", "1.1.1.1"), v4Packet("100.64.0.5", "2.2.2.2")}
	allocs := testing.AllocsPerRun(100, func() {
		if _, err := a.Write(bufs, testOffset); err != nil {
			t.Fatalf("write: %v", err)
		}
	})
	if allocs > 0 {
		t.Fatalf("allow path allocated %v times per write", allocs)
	}
	if inner.calls == 0 {
		t.Fatal("inner device never called")
	}
}
