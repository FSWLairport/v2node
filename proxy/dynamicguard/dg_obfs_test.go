package dynamicguard

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// makeBody 构造长度为 baseLen 的伪 WG 报文，body[4:baseLen] 填充随机字节。
func makeBody(t *testing.T, baseLen int) []byte {
	t.Helper()
	buf := make([]byte, baseLen)
	if baseLen > 4 {
		if _, err := rand.Read(buf[4:]); err != nil {
			t.Fatalf("rand: %v", err)
		}
	}
	return buf
}

// stripDecision 精确复刻 send/receive 中的 strip 判定逻辑（wg_device.go ~250-259）。
func stripDecision(normType byte, body []byte, wire [3]byte, n int) (baseLen int, strip bool) {
	baseLen = wgBaseLen(normType)
	if baseLen == 0 || n < baseLen {
		return baseLen, false
	}
	plain24 := dgDecodeReserved(normType, body, wire)
	padLen := uint8(plain24 & 0xFF)
	return baseLen, padLen >= dgPadMin && padLen <= dgPadMax && n == baseLen+int(padLen)
}

func TestDGEncodeDecodeRoundtrip(t *testing.T) {
	types := []byte{0x01, 0x02, 0x03, 0x04}
	padLens := []uint8{0, 1, 32, 95, 96}
	rand16s := []uint16{0, 1, 0x1234, 0xFFFF}
	for _, normType := range types {
		baseLen := wgBaseLen(normType)
		body := makeBody(t, baseLen)[4:]
		for _, pl := range padLens {
			for _, r := range rand16s {
				enc := dgEncodeReserved(normType, body, pl, r)
				plain24 := dgDecodeReserved(normType, body, enc)
				gotPad := uint8(plain24 & 0xFF)
				gotRand := uint16(plain24 >> 8)
				if gotPad != pl || gotRand != r {
					t.Fatalf("type=%#x pad=%d rand=%#x: got pad=%d rand=%#x", normType, pl, r, gotPad, gotRand)
				}
			}
		}
	}
}

// TestDGDataPacketNeverStripped 核心回归测试：type4 data 编码 padLen=0，永不被截断。
func TestDGDataPacketNeverStripped(t *testing.T) {
	baseLen := wgBaseLen(0x04)
	for n := wgKeepalive + 1; n <= wgKeepalive+256; n++ {
		pkt := make([]byte, n)
		if _, err := rand.Read(pkt[4:]); err != nil {
			t.Fatalf("rand: %v", err)
		}
		enc := dgEncodeReserved(0x04, pkt[4:baseLen], 0, randUint16())
		pkt[1], pkt[2], pkt[3] = enc[0], enc[1], enc[2]
		wire := [3]byte{pkt[1], pkt[2], pkt[3]}
		_, strip := stripDecision(0x04, pkt[4:baseLen], wire, n)
		if strip {
			t.Fatalf("data packet n=%d wrongly stripped (regression!)", n)
		}
	}
}

// TestDGKeepalivePaddedRoundtrip 验证 padded keepalive 被精确还原到 32B。
func TestDGKeepalivePaddedRoundtrip(t *testing.T) {
	baseLen := wgBaseLen(0x04)
	for pl := uint8(dgPadMin); pl <= dgPadMax; pl++ {
		body := makeBody(t, baseLen)
		enc := dgEncodeReserved(0x04, body[4:baseLen], pl, randUint16())
		body[1], body[2], body[3] = enc[0], enc[1], enc[2]
		n := baseLen + int(pl)
		wire := [3]byte{body[1], body[2], body[3]}
		gotBase, strip := stripDecision(0x04, body[4:baseLen], wire, n)
		if !strip {
			t.Fatalf("padded keepalive padLen=%d not stripped", pl)
		}
		if gotBase != wgKeepalive {
			t.Fatalf("padLen=%d: stripped size=%d, want %d", pl, gotBase, wgKeepalive)
		}
	}
}

// TestDGHandshakePaddedRoundtrip 验证 type1/2/3 握手 padding 还原。
func TestDGHandshakePaddedRoundtrip(t *testing.T) {
	for _, normType := range []byte{0x01, 0x02, 0x03} {
		baseLen := wgBaseLen(normType)
		for _, pl := range []uint8{dgPadMin, 48, dgPadMax} {
			body := makeBody(t, baseLen)
			enc := dgEncodeReserved(normType, body[4:baseLen], pl, randUint16())
			body[1], body[2], body[3] = enc[0], enc[1], enc[2]
			n := baseLen + int(pl)
			wire := [3]byte{body[1], body[2], body[3]}
			gotBase, strip := stripDecision(normType, body[4:baseLen], wire, n)
			if !strip {
				t.Fatalf("type=%#x padLen=%d not stripped", normType, pl)
			}
			if gotBase != baseLen {
				t.Fatalf("type=%#x padLen=%d: stripped=%d want=%d", normType, pl, gotBase, baseLen)
			}
		}
	}
}

// TestDGReservedDoesNotCorruptBody 确认编码 reserved 不改动 body[4:baseLen]。
func TestDGReservedDoesNotCorruptBody(t *testing.T) {
	baseLen := wgBaseLen(0x01)
	body := makeBody(t, baseLen)
	orig := append([]byte(nil), body[4:baseLen]...)
	enc := dgEncodeReserved(0x01, body[4:baseLen], 50, 0xBEEF)
	body[1], body[2], body[3] = enc[0], enc[1], enc[2]
	if !bytes.Equal(orig, body[4:baseLen]) {
		t.Fatal("reserved encoding corrupted body region")
	}
}

func TestDGShouldPad(t *testing.T) {
	cases := []struct {
		msgType byte
		msgLen  int
		want    bool
	}{
		{0x01, 148, true},
		{0x02, 92, true},
		{0x03, 64, true},
		{0x04, 32, true},
		{0x04, 33, false},
		{0x04, 1408, false},
		{0x00, 32, false},
		{0x05, 32, false},
	}
	for _, c := range cases {
		if got := dgShouldPad(c.msgType, c.msgLen); got != c.want {
			t.Fatalf("dgShouldPad(%#x, %d)=%v want %v", c.msgType, c.msgLen, got, c.want)
		}
	}
}

func TestRandPadLenRange(t *testing.T) {
	for i := 0; i < 4096; i++ {
		pl := randPadLen()
		if pl < dgPadMin || pl > dgPadMax {
			t.Fatalf("randPadLen=%d out of [%d,%d]", pl, dgPadMin, dgPadMax)
		}
	}
}
