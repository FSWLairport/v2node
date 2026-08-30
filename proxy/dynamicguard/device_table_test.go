package dynamicguard

import (
	"net/netip"
	"testing"
	"time"
)

func TestDeviceTableRegisterAndLookup(t *testing.T) {
	dt := NewDeviceTable()
	entry := &DeviceEntry{
		UserID:      1,
		DeviceID:    [16]byte{1},
		WGStaticPub: [32]byte{10},
		AssignedIP:  netip.MustParseAddr("10.0.0.1"),
		LastSeen:    time.Now(),
		Status:      DeviceStatusActive,
	}

	dt.LockDevice(1, entry.DeviceID)
	if err := dt.Register(entry); err != nil {
		t.Fatalf("Register: %v", err)
	}
	dt.UnlockDevice(1, entry.DeviceID)

	found := dt.Lookup(1, entry.DeviceID)
	if found == nil {
		t.Fatal("Lookup returned nil")
	}
	if found.AssignedIP != entry.AssignedIP {
		t.Fatalf("expected IP %s, got %s", entry.AssignedIP, found.AssignedIP)
	}
}

func TestDeviceTableDuplicateWGPubRejected(t *testing.T) {
	dt := NewDeviceTable()
	entry1 := &DeviceEntry{
		UserID:      1,
		DeviceID:    [16]byte{1},
		WGStaticPub: [32]byte{10},
		AssignedIP:  netip.MustParseAddr("10.0.0.1"),
		Status:      DeviceStatusActive,
	}
	entry2 := &DeviceEntry{
		UserID:      2,
		DeviceID:    [16]byte{2},
		WGStaticPub: [32]byte{10}, // same WG pub
		AssignedIP:  netip.MustParseAddr("10.0.0.2"),
		Status:      DeviceStatusActive,
	}

	dt.LockDevice(1, entry1.DeviceID)
	if err := dt.Register(entry1); err != nil {
		t.Fatalf("Register entry1: %v", err)
	}
	dt.UnlockDevice(1, entry1.DeviceID)

	dt.LockDevice(2, entry2.DeviceID)
	err := dt.Register(entry2)
	dt.UnlockDevice(2, entry2.DeviceID)
	if err != errDevicePubMismatch {
		t.Fatalf("expected errDevicePubMismatch, got %v", err)
	}
}

func TestDeviceTableDuplicateIPRejected(t *testing.T) {
	dt := NewDeviceTable()
	entry1 := &DeviceEntry{
		UserID:      1,
		DeviceID:    [16]byte{1},
		WGStaticPub: [32]byte{10},
		AssignedIP:  netip.MustParseAddr("10.0.0.1"),
		Status:      DeviceStatusActive,
	}
	entry2 := &DeviceEntry{
		UserID:      2,
		DeviceID:    [16]byte{2},
		WGStaticPub: [32]byte{20},
		AssignedIP:  netip.MustParseAddr("10.0.0.1"), // same IP
		Status:      DeviceStatusActive,
	}

	dt.LockDevice(1, entry1.DeviceID)
	if err := dt.Register(entry1); err != nil {
		t.Fatalf("Register entry1: %v", err)
	}
	dt.UnlockDevice(1, entry1.DeviceID)

	dt.LockDevice(2, entry2.DeviceID)
	err := dt.Register(entry2)
	dt.UnlockDevice(2, entry2.DeviceID)
	if err != errIPPoolExhausted {
		t.Fatalf("expected errIPPoolExhausted, got %v", err)
	}
}

func TestDeviceTableCountByUserOnlyActive(t *testing.T) {
	dt := NewDeviceTable()
	dt.LockDevice(1, [16]byte{1})
	dt.Register(&DeviceEntry{
		UserID: 1, DeviceID: [16]byte{1}, WGStaticPub: [32]byte{10},
		AssignedIP: netip.MustParseAddr("10.0.0.1"), Status: DeviceStatusActive,
	})
	dt.UnlockDevice(1, [16]byte{1})

	dt.LockDevice(1, [16]byte{2})
	dt.Register(&DeviceEntry{
		UserID: 1, DeviceID: [16]byte{2}, WGStaticPub: [32]byte{20},
		AssignedIP: netip.MustParseAddr("10.0.0.2"), Status: DeviceStatusDisconnected,
	})
	dt.UnlockDevice(1, [16]byte{2})

	if count := dt.CountByUser(1); count != 1 {
		t.Fatalf("expected 1 active device, got %d", count)
	}
}

func TestDeviceTableRemoveByID(t *testing.T) {
	dt := NewDeviceTable()
	entry := &DeviceEntry{
		UserID: 1, DeviceID: [16]byte{1}, WGStaticPub: [32]byte{10},
		AssignedIP: netip.MustParseAddr("10.0.0.1"), Status: DeviceStatusActive,
	}

	dt.LockDevice(1, entry.DeviceID)
	dt.Register(entry)
	dt.UnlockDevice(1, entry.DeviceID)

	removed, ok := dt.RemoveByID(1, entry.DeviceID)
	if !ok || removed.AssignedIP != entry.AssignedIP {
		t.Fatalf("RemoveByID returned (%+v, %v)", removed, ok)
	}

	if dt.Lookup(1, entry.DeviceID) != nil {
		t.Fatal("Lookup should return nil after RemoveByID")
	}
	if dt.GetEntryByWGPub(entry.WGStaticPub) != nil {
		t.Fatal("GetEntryByWGPub should return nil after RemoveByID")
	}
	if len(dt.GetDevicesByUser(1)) != 0 {
		t.Fatal("GetDevicesByUser should return empty after RemoveByID")
	}
	if _, ok := dt.RemoveByID(1, entry.DeviceID); ok {
		t.Fatal("RemoveByID should be idempotent")
	}
}

func TestDeviceTableCleanExpired(t *testing.T) {
	dt := NewDeviceTable()
	entry := &DeviceEntry{
		UserID: 1, DeviceID: [16]byte{1}, WGStaticPub: [32]byte{10},
		AssignedIP: netip.MustParseAddr("10.0.0.5"), Status: DeviceStatusActive,
		LastSeen: time.Now().Add(-2 * time.Hour),
	}

	dt.LockDevice(1, entry.DeviceID)
	dt.Register(entry)
	dt.UnlockDevice(1, entry.DeviceID)

	expired := dt.CleanExpired(1 * time.Hour)
	if len(expired) != 1 {
		t.Fatalf("expected 1 expired, got %d", len(expired))
	}
	if expired[0].OldIP != netip.MustParseAddr("10.0.0.5") {
		t.Fatalf("expected old IP 10.0.0.5, got %s", expired[0].OldIP)
	}
	if entry.Status != DeviceStatusDisconnected {
		t.Fatal("expected status disconnected")
	}
	if entry.AssignedIP.IsValid() {
		t.Fatal("expected AssignedIP cleared")
	}

	// Record should still be in byKey (allows reconnection)
	found := dt.Lookup(1, entry.DeviceID)
	if found == nil {
		t.Fatal("expired device should still be in byKey")
	}
}

func TestDeviceTableCleanExpiredSkipsRecentDevices(t *testing.T) {
	dt := NewDeviceTable()
	entry := &DeviceEntry{
		UserID: 1, DeviceID: [16]byte{1}, WGStaticPub: [32]byte{10},
		AssignedIP: netip.MustParseAddr("10.0.0.5"), Status: DeviceStatusActive,
		LastSeen: time.Now(),
	}

	dt.LockDevice(1, entry.DeviceID)
	dt.Register(entry)
	dt.UnlockDevice(1, entry.DeviceID)

	expired := dt.CleanExpired(1 * time.Hour)
	if len(expired) != 0 {
		t.Fatalf("expected 0 expired for recent device, got %d", len(expired))
	}
}

func TestDeviceTableUpdateLastSeen(t *testing.T) {
	dt := NewDeviceTable()
	oldTime := time.Now().Add(-1 * time.Hour)
	entry := &DeviceEntry{
		UserID: 1, DeviceID: [16]byte{1}, WGStaticPub: [32]byte{10},
		AssignedIP: netip.MustParseAddr("10.0.0.1"), Status: DeviceStatusActive,
		LastSeen: oldTime,
	}

	dt.LockDevice(1, entry.DeviceID)
	dt.Register(entry)
	dt.UnlockDevice(1, entry.DeviceID)

	newTime := time.Now()
	dt.UpdateLastSeen([32]byte{10}, newTime)

	found := dt.GetEntryByWGPub([32]byte{10})
	if found.LastSeen != newTime {
		t.Fatal("UpdateLastSeen did not update time")
	}
}

func TestDeviceTableUpdateLastSeenUnknownKey(t *testing.T) {
	dt := NewDeviceTable()
	// Should not panic
	dt.UpdateLastSeen([32]byte{99}, time.Now())
}

func TestDeviceTableGetAllActive(t *testing.T) {
	dt := NewDeviceTable()

	dt.LockDevice(1, [16]byte{1})
	dt.Register(&DeviceEntry{
		UserID: 1, DeviceID: [16]byte{1}, WGStaticPub: [32]byte{10},
		AssignedIP: netip.MustParseAddr("10.0.0.1"), Status: DeviceStatusActive,
	})
	dt.UnlockDevice(1, [16]byte{1})

	dt.LockDevice(1, [16]byte{2})
	dt.Register(&DeviceEntry{
		UserID: 1, DeviceID: [16]byte{2}, WGStaticPub: [32]byte{20},
		AssignedIP: netip.MustParseAddr("10.0.0.2"), Status: DeviceStatusDisconnected,
	})
	dt.UnlockDevice(1, [16]byte{2})

	active := dt.GetAllActive()
	if len(active) != 1 {
		t.Fatalf("expected 1 active, got %d", len(active))
	}
}

func TestDeviceTableUpdateIP(t *testing.T) {
	dt := NewDeviceTable()
	entry := &DeviceEntry{
		UserID: 1, DeviceID: [16]byte{1}, WGStaticPub: [32]byte{10},
		AssignedIP: netip.MustParseAddr("10.0.0.1"), Status: DeviceStatusActive,
	}

	dt.LockDevice(1, entry.DeviceID)
	dt.Register(entry)
	dt.UnlockDevice(1, entry.DeviceID)

	entry.AssignedIP = netip.MustParseAddr("10.0.0.99")
	dt.UpdateIP(entry)

	// Verify the new IP is in the index
	found := dt.GetEntryByWGPub([32]byte{10})
	if found.AssignedIP != netip.MustParseAddr("10.0.0.99") {
		t.Fatalf("expected updated IP 10.0.0.99, got %s", found.AssignedIP)
	}
}

func TestDeviceTableRemoveByIDIsIdempotent(t *testing.T) {
	dt := NewDeviceTable()
	entry := &DeviceEntry{
		UserID: 7, DeviceID: [16]byte{8}, WGStaticPub: [32]byte{9},
		AssignedIP: netip.MustParseAddr("10.0.0.8"), Status: DeviceStatusActive,
	}
	dt.LockDevice(entry.UserID, entry.DeviceID)
	if err := dt.Register(entry); err != nil {
		t.Fatalf("Register: %v", err)
	}
	dt.UnlockDevice(entry.UserID, entry.DeviceID)

	removed, ok := dt.RemoveByID(entry.UserID, entry.DeviceID)
	if !ok || removed.UserID != entry.UserID || removed.DeviceID != entry.DeviceID {
		t.Fatalf("RemoveByID = (%+v, %v)", removed, ok)
	}
	if removedAgain, ok := dt.RemoveByID(entry.UserID, entry.DeviceID); ok || removedAgain != nil {
		t.Fatalf("second RemoveByID = (%+v, %v), want (nil, false)", removedAgain, ok)
	}
}
