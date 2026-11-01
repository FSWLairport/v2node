package userlease

import (
	"testing"
	"time"
)

func TestAccountRateIsSharedByDevices(t *testing.T) {
	first, second := t.Name()+"-1", t.Name()+"-2"
	ConfigureRate(first, t.Name(), 1)
	ConfigureRate(second, t.Name(), 1)
	Set(first, time.Now().Add(time.Minute), nil)
	Set(second, time.Now().Add(time.Minute), nil)
	if Bucket(first) != Bucket(second) {
		t.Fatal("devices received separate bandwidth budgets")
	}
	if !AllowPacket(first, 100000) {
		t.Fatal("first packet denied")
	}
	if AllowPacket(second, 100000) {
		t.Fatal("parallel device bypassed account budget")
	}
	Revoke(first)
	if AllowPacket(first, 1) {
		t.Fatal("expired user consumed a shared budget")
	}
}
