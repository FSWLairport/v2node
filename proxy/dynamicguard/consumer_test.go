package dynamicguard

import (
	"github.com/wyx2685/v2node/common/userlease"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

type readTUN struct {
	fakeTUN
	packets [][]byte
}

func (f *readTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	for i, p := range f.packets {
		copy(bufs[i][offset:], p[testOffset:])
		sizes[i] = len(p) - testOffset
	}
	n := len(f.packets)
	f.packets = nil
	return n, io.EOF
}
func TestConsumerDataPlaneLeaseGatesBothDirections(t *testing.T) {
	tag := t.Name()
	userlease.Set(tag, time.Now().Add(time.Minute), nil)
	users := NewUserKeyMap()
	users.Update([]*UserEntry{{UserID: 1, LeaseTag: tag}, {UserID: 2}})
	dt := NewDeviceTable()
	for i, addr := range []string{"100.64.0.5", "100.64.0.6"} {
		if err := dt.Register(&DeviceEntry{UserID: i + 1, DeviceID: [16]byte{byte(i + 1)}, WGStaticPub: [32]byte{byte(i + 1)}, AssignedIP: netip.MustParseAddr(addr), Status: DeviceStatusActive}); err != nil {
			t.Fatal(err)
		}
	}
	inner := &readTUN{}
	a := newACLTUN(inner, dt, nil, false)
	a.users = users
	writeAll(t, a, v4Packet("100.64.0.5", "8.8.8.8"))
	if len(inner.written) != 1 {
		t.Fatal("valid upload dropped")
	}
	inner.packets = [][]byte{v4Packet("8.8.8.8", "100.64.0.5")}
	bufs := [][]byte{make([]byte, 1500), make([]byte, 1500)}
	sizes := make([]int, 2)
	if n, _ := a.Read(bufs, sizes, testOffset); n != 1 {
		t.Fatal("valid download dropped")
	}
	traffic := a.collectConsumerTraffic()
	if len(traffic) != 1 || traffic[0].Upload != 20 || traffic[0].Download != 20 {
		t.Fatalf("IP-byte accounting: %+v", traffic)
	}
	userlease.Revoke(tag)
	writeAll(t, a, v4Packet("100.64.0.5", "8.8.8.8"), v4Packet("100.64.0.6", "8.8.8.8"))
	if len(inner.written) != 2 {
		t.Fatal("expired upload served or enterprise dropped")
	}
	inner.packets = [][]byte{v4Packet("8.8.8.8", "100.64.0.5"), v4Packet("8.8.8.8", "100.64.0.6")}
	original := bufs[0]
	if n, _ := a.Read(bufs, sizes, testOffset); n != 1 {
		t.Fatal("expired download served or enterprise dropped")
	}
	_, dst, _ := packetAddrs(bufs[0][testOffset : testOffset+sizes[0]])
	if dst.String() != "100.64.0.6" || &original[0] != &bufs[0][0] {
		t.Fatal("read filtering changed buffer ownership or served C")
	}
	if traffic = a.collectConsumerTraffic(); len(traffic) != 0 {
		t.Fatalf("denied/enterprise bytes billed to C: %+v", traffic)
	}
}
func TestConsumerACLDropDoesNotConsumeQuota(t *testing.T) {
	tag := t.Name()
	userlease.Set(tag, time.Now().Add(time.Minute), nil)
	users := NewUserKeyMap()
	users.Update([]*UserEntry{{UserID: 1, LeaseTag: tag}})
	a := newACLTUN(&fakeTUN{}, leaseTable(t, map[string]int{"100.64.0.5": 12}), newACLPolicy(map[string]DGACL{"12": {Default: "deny"}}), false)
	a.users = users
	writeAll(t, a, v4Packet("100.64.0.5", "8.8.8.8"))
	if len(a.collectConsumerTraffic()) != 0 {
		t.Fatal("ACL rejected packet was billed")
	}
}

func TestConsumerClientInitRejectsMismatchedDevicePins(t *testing.T) {
	packet := buildClientInitPacket(t, nil, nil)
	msg, err := ParseClientInit(packet)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"device", "key"} {
		t.Run(kind, func(t *testing.T) {
			u := &UserEntry{UserID: 1, UserKey: msg.UserKey, Pinned: true, PinnedDeviceID: msg.DeviceID, PinnedWGKey: msg.WGStaticPub}
			if kind == "device" {
				u.PinnedDeviceID[0] ^= 1
			} else {
				u.PinnedWGKey[0] ^= 1
			}
			users := NewUserKeyMap()
			users.Update([]*UserEntry{u})
			// A mismatch must return before touching cookie, peer, pool or UDP state.
			h := &Handler{userKeyMap: users}
			h.HandleClientInit(packet, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}, nil, netip.Addr{})
			if h.pendingCount.Load() != 0 {
				t.Fatal("pending handshake leaked")
			}
		})
	}
}
