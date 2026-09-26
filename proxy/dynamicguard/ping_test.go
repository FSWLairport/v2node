package dynamicguard

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"time"
)

func buildClientPingPacket(t *testing.T, userKey []byte, nonce []byte) []byte {
	t.Helper()
	data := make([]byte, 0, clientPingSize)
	data = append(data, dgMagic[:]...)
	data = append(data, dgVersion)
	data = append(data, userKey...)
	data = append(data, nonce...)
	mac := computeTestMAC(t, userKey, nonce, data)
	return append(data, mac[:]...)
}

// pingHarness: server socket (handler writes here) + client socket (reads pong).
func pingHarness(t *testing.T, users ...*UserEntry) (*Handler, *net.UDPConn, *net.UDPConn) {
	t.Helper()
	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen server: %v", err)
	}
	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen client: %v", err)
	}
	t.Cleanup(func() { serverConn.Close(); clientConn.Close() })
	m := NewUserKeyMap()
	m.Update(users)
	return &Handler{userKeyMap: m}, serverConn, clientConn
}

func readPong(t *testing.T, clientConn *net.UDPConn) ([]byte, bool) {
	t.Helper()
	buf := make([]byte, 128)
	clientConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	n, _, err := clientConn.ReadFromUDP(buf)
	if err != nil {
		return nil, false
	}
	return buf[:n], true
}

func TestHandlePingRoundTrip(t *testing.T) {
	userKey := bytesOf(32, 0x01)
	nonce := bytesOf(16, 0x71)
	var key [32]byte
	copy(key[:], userKey)
	h, serverConn, clientConn := pingHarness(t, &UserEntry{UserID: 1, UserKey: key})

	ping := buildClientPingPacket(t, userKey, nonce)
	if len(ping) != clientPingSize {
		t.Fatalf("ping size = %d, want %d", len(ping), clientPingSize)
	}
	h.HandlePing(ping, clientConn.LocalAddr().(*net.UDPAddr), serverConn, netip.Addr{})

	pong, ok := readPong(t, clientConn)
	if !ok {
		t.Fatal("expected pong, got none")
	}
	var n16 [16]byte
	copy(n16[:], nonce)
	if want := BuildServerPong(n16); !bytes.Equal(pong, want) {
		t.Fatalf("pong = %x, want %x", pong, want)
	}
	if len(pong) != serverPongSize || pong[5] != serverPongMsgType || !bytes.Equal(pong[6:], nonce) {
		t.Fatalf("malformed pong: %x", pong)
	}
}

func TestHandlePingSilentDrop(t *testing.T) {
	userKey := bytesOf(32, 0x01)
	nonce := bytesOf(16, 0x71)
	var key [32]byte
	copy(key[:], userKey)

	badMAC := buildClientPingPacket(t, userKey, nonce)
	badMAC[len(badMAC)-1] ^= 0xFF
	unknown := buildClientPingPacket(t, bytesOf(32, 0x02), nonce)

	tests := []struct {
		name   string
		packet []byte
	}{
		{name: "wrong MAC", packet: badMAC},
		{name: "unknown user_key", packet: unknown},
		{name: "wrong size", packet: buildClientPingPacket(t, userKey, nonce)[:clientPingSize-1]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, serverConn, clientConn := pingHarness(t, &UserEntry{UserID: 1, UserKey: key})
			h.HandlePing(tt.packet, clientConn.LocalAddr().(*net.UDPAddr), serverConn, netip.Addr{})
			if pong, ok := readPong(t, clientConn); ok {
				t.Fatalf("expected silent drop, got %x", pong)
			}
		})
	}
}

// 高负载时 Ping 在任何哈希之前被丢：这是 Ping 唯一的过载保护，因为它绕开了 cookie/PoW。
func TestHandlePingDroppedUnderHighLoad(t *testing.T) {
	userKey := bytesOf(32, 0x01)
	var key [32]byte
	copy(key[:], userKey)
	h, serverConn, clientConn := pingHarness(t, &UserEntry{UserID: 1, UserKey: key})
	h.pendingCount.Store(int64(highLoadThreshold) + 1)
	h.HandlePing(buildClientPingPacket(t, userKey, bytesOf(16, 0x71)), clientConn.LocalAddr().(*net.UDPAddr), serverConn, netip.Addr{})
	if pong, ok := readPong(t, clientConn); ok {
		t.Fatalf("under high load a ping must be dropped, got %x", pong)
	}
	h.pendingCount.Store(0)
	h.HandlePing(buildClientPingPacket(t, userKey, bytesOf(16, 0x72)), clientConn.LocalAddr().(*net.UDPAddr), serverConn, netip.Addr{})
	if _, ok := readPong(t, clientConn); !ok {
		t.Fatal("once load drops the same ping must be answered again")
	}
}

// 85 字节的包只能是 ClientPing：readLoop 按 isClientPing 分流，且 ParseClientInit 拒绝该长度。
func TestPingDispatchByLength(t *testing.T) {
	ping := buildClientPingPacket(t, bytesOf(32, 0x01), bytesOf(16, 0x71))
	if !isClientPing(ping) {
		t.Fatal("85-byte packet should dispatch to HandlePing")
	}
	if _, err := ParseClientInit(ping); err != errInvalidPacketSize {
		t.Fatalf("ParseClientInit must reject 85 bytes, got %v", err)
	}
	for _, init := range [][]byte{
		buildClientInitPacket(t, nil, nil),
		buildClientInitPacket(t, bytesOf(32, 0xA0), bytesOf(8, 0xD0)),
	} {
		if isClientPing(init) {
			t.Fatalf("%d-byte ClientInit must not dispatch to HandlePing", len(init))
		}
		if _, err := ParseClientPing(init); err != errInvalidPacketSize {
			t.Fatalf("ParseClientPing must reject %d bytes, got %v", len(init), err)
		}
	}
}
