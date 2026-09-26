package dynamicguard

import (
	"net/netip"
	"testing"
)

func TestUserKeyMapUpdateAndGet(t *testing.T) {
	m := NewUserKeyMap()
	users := []*UserEntry{
		{UserID: 1, UUID: "u1", UserKey: [32]byte{1}},
		{UserID: 2, UUID: "u2", UserKey: [32]byte{2}},
	}
	m.Update(users)

	got := m.Get([32]byte{1})
	if got == nil || got.UserID != 1 {
		t.Fatal("expected user 1")
	}

	got = m.Get([32]byte{99})
	if got != nil {
		t.Fatal("expected nil for unknown key")
	}
}

func TestUserKeyMapGetByID(t *testing.T) {
	m := NewUserKeyMap()
	m.Update([]*UserEntry{
		{UserID: 42, UUID: "u42", UserKey: [32]byte{42}},
	})

	got := m.GetByID(42)
	if got == nil || got.UUID != "u42" {
		t.Fatal("expected user 42")
	}

	got = m.GetByID(999)
	if got != nil {
		t.Fatal("expected nil for unknown ID")
	}
}

func TestUserKeyMapUpdateReplacesOld(t *testing.T) {
	m := NewUserKeyMap()
	m.Update([]*UserEntry{
		{UserID: 1, UUID: "old", UserKey: [32]byte{1}},
	})
	m.Update([]*UserEntry{
		{UserID: 2, UUID: "new", UserKey: [32]byte{2}},
	})

	if m.Get([32]byte{1}) != nil {
		t.Fatal("old user should be gone after full update")
	}
	got := m.Get([32]byte{2})
	if got == nil || got.UUID != "new" {
		t.Fatal("expected new user")
	}
}

func TestCollectUserTrafficAggregates(t *testing.T) {
	dt := NewDeviceTable()

	// Register two devices for user 1
	dt.LockDevice(1, [16]byte{1})
	dt.Register(&DeviceEntry{
		UserID: 1, DeviceID: [16]byte{1}, WGStaticPub: [32]byte{10},
		AssignedIP: netip.MustParseAddr("10.0.0.1"), Status: DeviceStatusActive,
	})
	dt.UnlockDevice(1, [16]byte{1})

	dt.LockDevice(1, [16]byte{2})
	dt.Register(&DeviceEntry{
		UserID: 1, DeviceID: [16]byte{2}, WGStaticPub: [32]byte{20},
		AssignedIP: netip.MustParseAddr("10.0.0.2"), Status: DeviceStatusActive,
	})
	dt.UnlockDevice(1, [16]byte{2})

	peerDeltas := map[[32]byte][2]int64{
		{10}: {100, 200},
		{20}: {300, 400},
	}

	result := CollectUserTraffic(peerDeltas, dt)
	if len(result) != 1 {
		t.Fatalf("expected 1 user traffic entry, got %d", len(result))
	}
	if result[0].Upload != 400 || result[0].Download != 600 {
		t.Fatalf("expected upload=400 download=600, got upload=%d download=%d",
			result[0].Upload, result[0].Download)
	}
}

func TestCollectUserTrafficSkipsUnknownPeers(t *testing.T) {
	dt := NewDeviceTable()

	peerDeltas := map[[32]byte][2]int64{
		{99}: {100, 200},
	}

	result := CollectUserTraffic(peerDeltas, dt)
	if len(result) != 0 {
		t.Fatalf("expected 0, got %d", len(result))
	}
}

func TestCollectUserTrafficNilDeltas(t *testing.T) {
	dt := NewDeviceTable()
	result := CollectUserTraffic(nil, dt)
	if result != nil {
		t.Fatal("expected nil for nil input")
	}
}
