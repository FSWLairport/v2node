package dynamicguard

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func TestBuildPeerIPCRequestDoesNotForcePersistentKeepalive(t *testing.T) {
	var publicKey [32]byte
	for i := range publicKey {
		publicKey[i] = byte(i + 1)
	}

	request := buildPeerIPCRequest(publicKey, netip.MustParseAddr("10.77.3.2"))

	if !strings.Contains(request, "replace_allowed_ips=true\n") {
		t.Fatalf("expected replace_allowed_ips in request: %q", request)
	}
	if !strings.Contains(request, "allowed_ip=10.77.3.2/32\n") {
		t.Fatalf("expected ipv4 allowed_ip in request: %q", request)
	}
	if strings.Contains(request, "persistent_keepalive_interval") {
		t.Fatalf("unexpected persistent keepalive in request: %q", request)
	}
}

func TestAllowedIPCIDRSupportsIPv6(t *testing.T) {
	got := allowedIPCIDR(netip.MustParseAddr("fd00::23"))
	if got != "fd00::23/128" {
		t.Fatalf("expected ipv6 /128 cidr, got %q", got)
	}
}

func TestAllowedIPCIDRIPv4(t *testing.T) {
	got := allowedIPCIDR(netip.MustParseAddr("10.0.0.1"))
	if got != "10.0.0.1/32" {
		t.Fatalf("expected 10.0.0.1/32, got %q", got)
	}
}

func TestParsePeerStatsEmpty(t *testing.T) {
	stats := parsePeerStats("")
	if len(stats) != 0 {
		t.Fatalf("expected empty stats, got %d entries", len(stats))
	}
}

func TestParsePeerStatsSinglePeer(t *testing.T) {
	var pubKey [32]byte
	for i := range pubKey {
		pubKey[i] = byte(i + 1)
	}
	pubKeyHex := hex.EncodeToString(pubKey[:])

	ipcOutput := fmt.Sprintf("public_key=%s\nrx_bytes=1000\ntx_bytes=2000\n", pubKeyHex)
	stats := parsePeerStats(ipcOutput)

	if len(stats) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(stats))
	}
	s, ok := stats[pubKey]
	if !ok {
		t.Fatal("expected peer not found in stats")
	}
	if s.rxBytes != 1000 {
		t.Fatalf("expected rx_bytes=1000, got %d", s.rxBytes)
	}
	if s.txBytes != 2000 {
		t.Fatalf("expected tx_bytes=2000, got %d", s.txBytes)
	}
}

func TestParsePeerStatsMultiplePeers(t *testing.T) {
	var key1, key2 [32]byte
	key1[0] = 0xAA
	key2[0] = 0xBB
	hex1 := hex.EncodeToString(key1[:])
	hex2 := hex.EncodeToString(key2[:])

	ipcOutput := fmt.Sprintf(
		"public_key=%s\nrx_bytes=100\ntx_bytes=200\npublic_key=%s\nrx_bytes=300\ntx_bytes=400\n",
		hex1, hex2,
	)
	stats := parsePeerStats(ipcOutput)

	if len(stats) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(stats))
	}
	if stats[key1].rxBytes != 100 || stats[key1].txBytes != 200 {
		t.Fatalf("key1 stats wrong: %+v", stats[key1])
	}
	if stats[key2].rxBytes != 300 || stats[key2].txBytes != 400 {
		t.Fatalf("key2 stats wrong: %+v", stats[key2])
	}
}

func TestParsePeerStatsSkipsInvalidKey(t *testing.T) {
	ipcOutput := "public_key=invalidhex\nrx_bytes=100\ntx_bytes=200\n"
	stats := parsePeerStats(ipcOutput)
	if len(stats) != 0 {
		t.Fatalf("expected 0 peers for invalid key, got %d", len(stats))
	}
}

func TestParsePeerStatsIgnoresNonPeerLines(t *testing.T) {
	var key1 [32]byte
	key1[0] = 0xCC
	hex1 := hex.EncodeToString(key1[:])

	ipcOutput := fmt.Sprintf(
		"private_key=abc\npublic_key=%s\nrx_bytes=50\ntx_bytes=60\nlisten_port=51820\n",
		hex1,
	)
	stats := parsePeerStats(ipcOutput)
	if len(stats) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(stats))
	}
	if stats[key1].rxBytes != 50 {
		t.Fatalf("expected rx=50, got %d", stats[key1].rxBytes)
	}
}

func TestBuildPeerIPCRequestPublicKeyHex(t *testing.T) {
	var publicKey [32]byte
	publicKey[0] = 0xAB
	publicKey[31] = 0xCD

	request := buildPeerIPCRequest(publicKey, netip.MustParseAddr("10.0.0.1"))
	expectedHex := hex.EncodeToString(publicKey[:])
	if !strings.Contains(request, "public_key="+expectedHex) {
		t.Fatalf("expected hex public key in request: %q", request)
	}
}
