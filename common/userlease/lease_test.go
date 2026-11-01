package userlease

import (
	"testing"
	"time"
)

func TestLeaseExpiresWithoutRefreshAndClosesConnections(t *testing.T) {
	closed := make(chan struct{}, 1)
	key := t.Name()
	Set(key, time.Now().Add(20*time.Millisecond), func() { closed <- struct{}{} })
	if !Allowed(key) {
		t.Fatal("fresh lease denied")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("expired connections not closed")
	}
	if Allowed(key) {
		t.Fatal("expired lease still authorizes dispatch")
	}
	if !Allowed("unmanaged-enterprise") {
		t.Fatal("unmanaged user affected")
	}
}
func TestRenewalDoesNotRunAnOldExpiryCallback(t *testing.T) {
	closed := make(chan struct{}, 2)
	key := t.Name()
	Set(key, time.Now().Add(30*time.Millisecond), func() { closed <- struct{}{} })
	Set(key, time.Now().Add(time.Second), func() { closed <- struct{}{} })
	select {
	case <-closed:
		t.Fatal("old timer closed a renewed lease")
	case <-time.After(60 * time.Millisecond):
	}
	if !Allowed(key) {
		t.Fatal("renewed lease denied")
	}
	Revoke(key)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("revocation did not close")
	}
	if Allowed(key) {
		t.Fatal("revoked authorization remains")
	}
}
