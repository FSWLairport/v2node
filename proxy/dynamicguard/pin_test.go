package dynamicguard

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestUserEntryPinAllowsOnlyThatDevice(t *testing.T) {
	var deviceID [16]byte
	var pub [32]byte
	deviceID[0], pub[0] = 1, 2

	unpinned := &UserEntry{}
	if !unpinned.Allows(deviceID, pub) {
		t.Fatal("an unpinned credential must accept any device")
	}

	pinned := &UserEntry{}
	if err := pinned.Pin(hex.EncodeToString(deviceID[:]), base64.StdEncoding.EncodeToString(pub[:])); err != nil {
		t.Fatal(err)
	}
	if !pinned.Allows(deviceID, pub) {
		t.Fatal("the pinned device must be accepted")
	}
	other := deviceID
	other[15] = 9
	if pinned.Allows(other, pub) {
		t.Fatal("another device_id must be rejected")
	}
	otherPub := pub
	otherPub[31] = 9
	if pinned.Allows(deviceID, otherPub) {
		t.Fatal("another wg_static_pub must be rejected")
	}

	broken := &UserEntry{}
	if err := broken.Pin("not-hex", "!!"); err == nil || !broken.Pinned || broken.Allows(deviceID, pub) || broken.Allows([16]byte{}, [32]byte{}) {
		t.Fatalf("an unparsable pin must fail closed: err=%v entry=%+v", err, broken)
	}
}
