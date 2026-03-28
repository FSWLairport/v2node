package dynamicguard

import (
	"crypto/hmac"
	"crypto/sha256"
	"io"
	"testing"

	"golang.org/x/crypto/hkdf"
)

func TestParseClientInitAcceptsMinimumPacketSize(t *testing.T) {
	packet := buildClientInitPacket(t, nil, nil)

	if got := len(packet); got != minClientInitSize {
		t.Fatalf("expected min ClientInit size %d, got %d", minClientInitSize, got)
	}

	msg, err := ParseClientInit(packet)
	if err != nil {
		t.Fatalf("ParseClientInit returned error for min packet: %v", err)
	}

	if len(msg.Cookie) != 0 {
		t.Fatalf("expected empty cookie, got %d bytes", len(msg.Cookie))
	}
	if len(msg.PowNonce) != 0 {
		t.Fatalf("expected empty PoW nonce, got %d bytes", len(msg.PowNonce))
	}
}

func TestParseClientInitAcceptsMaximumPacketSize(t *testing.T) {
	cookie := bytesOf(32, 0xA0)
	powNonce := bytesOf(8, 0xD0)
	packet := buildClientInitPacket(t, cookie, powNonce)

	if got := len(packet); got != maxClientInitSize {
		t.Fatalf("expected max ClientInit size %d, got %d", maxClientInitSize, got)
	}

	msg, err := ParseClientInit(packet)
	if err != nil {
		t.Fatalf("ParseClientInit returned error for max packet: %v", err)
	}

	if len(msg.Cookie) != len(cookie) {
		t.Fatalf("expected cookie len %d, got %d", len(cookie), len(msg.Cookie))
	}
	if len(msg.PowNonce) != len(powNonce) {
		t.Fatalf("expected PoW nonce len %d, got %d", len(powNonce), len(msg.PowNonce))
	}
}

func TestParseClientInitRejectsIncorrectBoundarySizes(t *testing.T) {
	validMinPacket := buildClientInitPacket(t, nil, nil)
	validMaxPacket := buildClientInitPacket(t, bytesOf(32, 0xA0), bytesOf(8, 0xD0))

	tests := []struct {
		name   string
		packet []byte
	}{
		{name: "below min", packet: validMinPacket[:len(validMinPacket)-1]},
		{name: "legacy wrong min 171", packet: append(append([]byte{}, validMinPacket...), bytesOf(4, 0xE0)...)},
		{name: "below max", packet: validMaxPacket[:len(validMaxPacket)-1]},
		{name: "above max", packet: append(append([]byte{}, validMaxPacket...), 0xFF)},
		{name: "legacy wrong max 211", packet: append(append([]byte{}, validMaxPacket...), bytesOf(4, 0xF0)...)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseClientInit(tt.packet); err != errInvalidPacketSize {
				t.Fatalf("expected errInvalidPacketSize, got %v", err)
			}
		})
	}
}

func bytesOf(length int, start byte) []byte {
	b := make([]byte, length)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

func buildClientInitPacket(t *testing.T, cookie []byte, powNonce []byte) []byte {
	t.Helper()

	if len(cookie) != 0 && len(cookie) != 32 {
		t.Fatalf("unexpected cookie length %d", len(cookie))
	}
	if len(powNonce) != 0 && len(powNonce) != 8 {
		t.Fatalf("unexpected PoW nonce length %d", len(powNonce))
	}

	userKey := bytesOf(32, 0x01)
	deviceID := bytesOf(16, 0x21)
	ephPub := bytesOf(32, 0x31)
	wgStaticPub := bytesOf(32, 0x51)
	clientNonce := bytesOf(16, 0x71)

	dataBeforeMAC := make([]byte, 0, 5+32+16+32+32+16+1+len(cookie)+1+len(powNonce))
	dataBeforeMAC = append(dataBeforeMAC, dgMagic[:]...)
	dataBeforeMAC = append(dataBeforeMAC, dgVersion)
	dataBeforeMAC = append(dataBeforeMAC, userKey...)
	dataBeforeMAC = append(dataBeforeMAC, deviceID...)
	dataBeforeMAC = append(dataBeforeMAC, ephPub...)
	dataBeforeMAC = append(dataBeforeMAC, wgStaticPub...)
	dataBeforeMAC = append(dataBeforeMAC, clientNonce...)
	dataBeforeMAC = append(dataBeforeMAC, byte(len(cookie)))
	dataBeforeMAC = append(dataBeforeMAC, cookie...)
	dataBeforeMAC = append(dataBeforeMAC, byte(len(powNonce)))
	dataBeforeMAC = append(dataBeforeMAC, powNonce...)

	mac := computeTestMAC(t, userKey, clientNonce, dataBeforeMAC)
	return append(dataBeforeMAC, mac[:]...)
}

func computeTestMAC(t *testing.T, userKey []byte, clientNonce []byte, data []byte) [32]byte {
	t.Helper()

	var macResult [32]byte
	reader := hkdf.New(sha256.New, userKey, clientNonce, macInfo)
	macKey := make([]byte, 32)
	if _, err := io.ReadFull(reader, macKey); err != nil {
		t.Fatalf("read hkdf output: %v", err)
	}

	h := hmac.New(sha256.New, macKey)
	h.Write(data)
	copy(macResult[:], h.Sum(nil))
	return macResult
}
