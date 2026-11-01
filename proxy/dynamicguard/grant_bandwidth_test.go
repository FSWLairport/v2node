package dynamicguard

import (
	"github.com/wyx2685/v2node/common/grantlimit"
	"net/netip"
	"testing"
)

func TestGrantBandwidthGatesEnterpriseTUNBothDirections(t *testing.T) {
	scope := t.Name()
	first, second := scope+"1", scope+"2"
	limit := grantlimit.Limit{ID: 1, UpMbps: 1, DownMbps: 1}
	grantlimit.Configure(scope, map[string][]grantlimit.Limit{first: {limit}, second: {limit}})
	defer grantlimit.Configure(scope, nil)
	users := NewUserKeyMap()
	users.Update([]*UserEntry{{UserID: 1, LeaseTag: first}, {UserID: 2, LeaseTag: second}})
	dt := NewDeviceTable()
	for i, addr := range []string{"100.64.0.5", "100.64.0.6"} {
		if err := dt.Register(&DeviceEntry{UserID: i + 1, DeviceID: [16]byte{byte(i + 1)}, WGStaticPub: [32]byte{byte(i + 1)}, AssignedIP: netip.MustParseAddr(addr), Status: DeviceStatusActive}); err != nil {
			t.Fatal(err)
		}
	}
	a := newACLTUN(&fakeTUN{}, dt, nil, false)
	a.users = users
	if !grantlimit.AllowPacket(first, true, 125000) {
		t.Fatal("initial upload allowance missing")
	}
	// Use large packets to stay above any scheduling-time token refill.
	packet := func(src, dst string) []byte { p := v4Packet(src, dst); return append(p, make([]byte, 100000)...) }
	if a.consumerPermit(packet("100.64.0.6", "8.8.8.8"), testOffset, true) {
		t.Fatal("second device bypassed shared upload")
	}
	if !a.consumerPermit(packet("8.8.8.8", "100.64.0.6"), testOffset, false) {
		t.Fatal("upload depleted download")
	}
	if a.consumerPermit(packet("8.8.8.8", "100.64.0.5"), testOffset, false) {
		t.Fatal("first device bypassed shared download")
	}
}
