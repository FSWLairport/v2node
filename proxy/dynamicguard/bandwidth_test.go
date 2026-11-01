package dynamicguard

import (
	"github.com/wyx2685/v2node/common/rate"
	"io"
	"net/netip"
	"testing"
)

func TestBandwidthTUNSharesOrganizationAcrossNetworksAndPreservesUUIDLimit(t *testing.T) {
	devices := leaseTable(t, map[string]int{"10.0.0.2": 11, "10.0.0.3": 12, "10.0.0.4": 13})
	inner := &fakeTUN{}
	b := newBandwidthTUN(inner, devices, map[string]int{"11": 7, "12": 7, "13": 8}, map[int]rate.BandwidthLimit{7: {UpMbps: 1, DownMbps: 1}, 8: {UpMbps: 1}})
	first := v4Packet("10.0.0.2", "1.1.1.1")
	second := v4Packet("10.0.0.3", "1.1.1.1")
	other := v4Packet("10.0.0.4", "1.1.1.1")
	up, down := b.organizations.Buckets(7)
	up.Get().Take(1250000)
	if _, err := b.Write([][]byte{first, second, other}, testOffset); err != nil {
		t.Fatal(err)
	}
	if len(inner.written) != 1 {
		t.Fatalf("organization cap did not span networks: %d packets", len(inner.written))
	}
	if !b.allow(v4Packet("1.1.1.1", "10.0.0.2")[testOffset:], false) {
		t.Fatal("upload cap blocked download")
	}
	down.Get().Take(1250000)
	if b.allow(v4Packet("1.1.1.1", "10.0.0.3")[testOffset:], false) {
		t.Fatal("download cap not shared")
	}
	if b.allow(v4Packet("10.0.0.99", "1.1.1.1")[testOffset:], true) {
		t.Fatal("unknown lease bypassed limits")
	}

	// With no org cap, legacy per-credential limits still cover every device/direction.
	b = newBandwidthTUN(inner, devices, nil, nil)
	id, _, _ := devices.bandwidthScopeByIP(netip.MustParseAddr("10.0.0.2"))
	b.updateUsers([]*UserEntry{{UserID: id, SpeedLimit: 1}})
	bucket := (*b.users.Load())[id].bucket
	bucket.Get().Take(1250000)
	b.updateUsers([]*UserEntry{{UserID: id, SpeedLimit: 1}})
	if (*b.users.Load())[id].bucket != bucket || b.allow(first[testOffset:], true) || b.allow(v4Packet("1.1.1.1", "10.0.0.2")[testOffset:], false) {
		t.Fatal("UUID cap lost on refresh or direction change")
	}
	if !b.allow(second[testOffset:], true) {
		t.Fatal("UUID cap blocked another credential")
	}
	b.updateUsers([]*UserEntry{{UserID: id, SpeedLimit: 0}})
	if !b.allow(first[testOffset:], true) {
		t.Fatal("cleared UUID cap still enforced")
	}
}

type bandwidthReadTUN struct {
	fakeTUN
	packets [][]byte
}

func (f *bandwidthReadTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	for i, p := range f.packets {
		copy(bufs[i][offset:], p[testOffset:])
		sizes[i] = len(p) - testOffset
	}
	return len(f.packets), io.EOF
}
func TestBandwidthTUNDownloadCompactsBatchAndKeepsReadError(t *testing.T) {
	devices := leaseTable(t, map[string]int{"10.0.0.2": 11, "10.0.0.3": 12})
	inner := &bandwidthReadTUN{packets: [][]byte{v4Packet("1.1.1.1", "10.0.0.2"), v6Packet("2001:db8::1", "2001:db8::2"), v4Packet("8.8.8.8", "10.0.0.3")}}
	b := newBandwidthTUN(inner, devices, map[string]int{"11": 7, "12": 8}, map[int]rate.BandwidthLimit{7: {DownMbps: 1}})
	_, down := b.organizations.Buckets(7)
	down.Get().Take(1250000)
	bufs := [][]byte{make([]byte, 128), make([]byte, 128), make([]byte, 128)}
	sizes := make([]int, 3)
	n, err := b.Read(bufs, sizes, testOffset)
	if n != 1 || err != io.EOF || sizes[0] != 20 {
		t.Fatalf("read n=%d err=%v sizes=%v", n, err, sizes)
	}
	src, dst, ok := packetAddrs(bufs[0][testOffset : testOffset+sizes[0]])
	if !ok || src.String() != "8.8.8.8" || dst.String() != "10.0.0.3" {
		t.Fatal("wrong packet after compaction")
	}
}

func TestBandwidthTUNOrganizationAndUUIDBothApply(t *testing.T) {
	devices := leaseTable(t, map[string]int{"10.0.0.2": 11})
	b := newBandwidthTUN(&fakeTUN{}, devices, map[string]int{"11": 7}, map[int]rate.BandwidthLimit{7: {UpMbps: 10, DownMbps: 10}})
	id, _, _ := devices.bandwidthScopeByIP(netip.MustParseAddr("10.0.0.2"))
	b.updateUsers([]*UserEntry{{UserID: id, SpeedLimit: 1}})
	packet := v4Packet("10.0.0.2", "1.1.1.1")[testOffset:]
	if !b.allow(packet, true) {
		t.Fatal("initial packet blocked")
	}
	(*b.users.Load())[id].bucket.Get().Take(1250000)
	if b.allow(packet, true) {
		t.Fatal("org limit bypassed UUID limit")
	}
	b.updateUsers([]*UserEntry{{UserID: id, SpeedLimit: 0}})
	up, _ := b.organizations.Buckets(7)
	up.Get().Take(12500000)
	if b.allow(packet, true) {
		t.Fatal("unlimited UUID bypassed org limit")
	}
}
