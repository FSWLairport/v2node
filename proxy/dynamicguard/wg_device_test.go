package dynamicguard

import (
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
