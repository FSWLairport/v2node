package dynamicguard

import (
	"net"
	"testing"
)

func TestCookieManagerGenerateAndVerify(t *testing.T) {
	cm := NewCookieManager(true, 0)

	srcIP := net.ParseIP("1.2.3.4")
	srcPort := uint16(12345)

	cookie := cm.GenerateCookie(srcIP, srcPort)
	if !cm.VerifyCookie(cookie, srcIP, srcPort) {
		t.Fatal("VerifyCookie should accept freshly generated cookie")
	}
}

func TestCookieManagerRejectsDifferentSource(t *testing.T) {
	cm := NewCookieManager(true, 0)

	cookie := cm.GenerateCookie(net.ParseIP("1.2.3.4"), 12345)

	// Different IP
	if cm.VerifyCookie(cookie, net.ParseIP("5.6.7.8"), 12345) {
		t.Fatal("should reject cookie for different IP")
	}

	// Different port
	if cm.VerifyCookie(cookie, net.ParseIP("1.2.3.4"), 54321) {
		t.Fatal("should reject cookie for different port")
	}
}

func TestCookieManagerDisabled(t *testing.T) {
	cm := NewCookieManager(false, 0)
	if cm.IsEnabled() {
		t.Fatal("should not be enabled")
	}
}

func TestCookieManagerPowDifficulty(t *testing.T) {
	cm := NewCookieManager(true, 16)
	if cm.GetPowDifficulty() != 16 {
		t.Fatalf("expected difficulty 16, got %d", cm.GetPowDifficulty())
	}
}

func TestCookieIPv4MappedIPv6Consistency(t *testing.T) {
	cm := NewCookieManager(true, 0)

	// 同一客户端，纯 IPv4 和 IPv4-mapped IPv6 两种表示
	ipv4 := net.ParseIP("192.168.1.1").To4()    // 4 bytes
	mapped := net.ParseIP("::ffff:192.168.1.1") // 16 bytes IPv4-mapped

	cookie := cm.GenerateCookie(ipv4, 8080)
	if !cm.VerifyCookie(cookie, mapped, 8080) {
		t.Fatal("cookie from IPv4 should verify with IPv4-mapped IPv6")
	}

	cookie2 := cm.GenerateCookie(mapped, 8080)
	if !cm.VerifyCookie(cookie2, ipv4, 8080) {
		t.Fatal("cookie from IPv4-mapped IPv6 should verify with IPv4")
	}
}

func TestCookieRejectsForgery(t *testing.T) {
	cm := NewCookieManager(true, 0)

	srcIP := net.ParseIP("10.0.0.1")
	cookie := cm.GenerateCookie(srcIP, 1234)

	// Tamper with cookie
	tampered := cookie
	tampered[0] ^= 0xFF
	if cm.VerifyCookie(tampered, srcIP, 1234) {
		t.Fatal("should reject tampered cookie")
	}
}
