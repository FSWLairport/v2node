package dynamicguard

import (
	"errors"
	"net/netip"
	"testing"
)

type fakePeerRemover struct {
	err     error
	removed [][32]byte
}

func (f *fakePeerRemover) RemovePeer(key [32]byte) error {
	f.removed = append(f.removed, key)
	return f.err
}

func TestDGServerRemoveUserIsReversible(t *testing.T) {
	server, pool, device, remover := newTeardownTestServer(t)
	user := &UserEntry{UserID: device.UserID, UserKey: [32]byte{9}}

	server.RemoveUser(user.UserID)
	if server.userKeyMap.GetByID(user.UserID) != nil {
		t.Fatal("RemoveUser did not disable the credential")
	}
	if len(remover.removed) != 1 || remover.removed[0] != device.WGStaticPub {
		t.Fatalf("removed peers = %#v", remover.removed)
	}
	if server.deviceTable.Lookup(device.UserID, device.DeviceID) != nil {
		t.Fatal("a user dropped by the panel must not leave a device entry")
	}
	if !pool.Reserve(device.AssignedIP) {
		t.Fatal("assigned IP was not released")
	}

	// Expiry followed by a renewal is the common case: the next refresh has to
	// bring the credential straight back without restarting the node.
	pool.Release(device.AssignedIP)
	server.UpdateUsers([]*UserEntry{user})
	if server.userKeyMap.GetByID(user.UserID) == nil {
		t.Fatal("a re-added user was permanently filtered out")
	}
	if server.userKeyMap.Get(user.UserKey) == nil {
		t.Fatal("a re-added user is not reachable by user key")
	}
}

// The panel is the only source of truth for a removed user, so there is no
// later retry: the entry and its address must go even if the IPC call fails.
func TestDGServerRemoveUserPeerFailureStillReleasesResources(t *testing.T) {
	server, pool, device, remover := newTeardownTestServer(t)
	remover.err = errors.New("wg ipc unavailable")

	server.RemoveUser(device.UserID)

	if server.deviceTable.Lookup(device.UserID, device.DeviceID) != nil {
		t.Fatal("device entry leaked after peer-removal failure")
	}
	if !pool.Reserve(device.AssignedIP) {
		t.Fatal("assigned IP leaked after peer-removal failure")
	}
}

func TestDGServerRemoveUserWithoutDevice(t *testing.T) {
	user := &UserEntry{UserID: 11, UserKey: [32]byte{11}}
	server := &DGServer{
		deviceTable: NewDeviceTable(),
		userKeyMap:  NewUserKeyMap(),
		ipPools:     make(map[int]*IPPool),
		peerRemover: &fakePeerRemover{},
	}
	server.userKeyMap.Update([]*UserEntry{user})
	server.RemoveUser(user.UserID)
	if server.userKeyMap.GetByID(user.UserID) != nil {
		t.Fatal("RemoveUser did not disable credential")
	}
}

func newTeardownTestServer(t *testing.T) (*DGServer, *IPPool, *DeviceEntry, *fakePeerRemover) {
	t.Helper()
	pool, err := NewIPPool("10.0.0.0/24")
	if err != nil {
		t.Fatalf("NewIPPool: %v", err)
	}
	ip, err := pool.Allocate()
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	device := &DeviceEntry{
		UserID:      9,
		DeviceID:    [16]byte{1, 2, 3},
		WGStaticPub: [32]byte{4, 5, 6},
		AssignedIP:  netip.MustParseAddr(ip.String()),
		Status:      DeviceStatusActive,
		GroupID:     3,
	}
	table := NewDeviceTable()
	table.LockDevice(device.UserID, device.DeviceID)
	if err := table.Register(device); err != nil {
		t.Fatalf("Register: %v", err)
	}
	table.UnlockDevice(device.UserID, device.DeviceID)
	userMap := NewUserKeyMap()
	userMap.Update([]*UserEntry{{UserID: device.UserID, UserKey: [32]byte{9}}})
	remover := &fakePeerRemover{}
	server := &DGServer{
		deviceTable: table,
		userKeyMap:  userMap,
		ipPools:     map[int]*IPPool{device.GroupID: pool},
		peerRemover: remover,
	}
	return server, pool, device, remover
}
