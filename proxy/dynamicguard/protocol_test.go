package dynamicguard

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net/netip"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
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

// --- VerifyMAC tests ---

func TestVerifyMACAcceptsValidMAC(t *testing.T) {
	packet := buildClientInitPacket(t, nil, nil)
	msg, err := ParseClientInit(packet)
	if err != nil {
		t.Fatalf("ParseClientInit: %v", err)
	}
	if !VerifyMAC(msg.UserKey, msg.ClientNonce, msg.DataBeforeMAC, msg.MAC) {
		t.Fatal("VerifyMAC should accept valid MAC")
	}
}

func TestVerifyMACRejectsTamperedData(t *testing.T) {
	packet := buildClientInitPacket(t, nil, nil)
	msg, err := ParseClientInit(packet)
	if err != nil {
		t.Fatalf("ParseClientInit: %v", err)
	}

	// Tamper with DataBeforeMAC
	tampered := make([]byte, len(msg.DataBeforeMAC))
	copy(tampered, msg.DataBeforeMAC)
	tampered[10] ^= 0xFF
	if VerifyMAC(msg.UserKey, msg.ClientNonce, tampered, msg.MAC) {
		t.Fatal("VerifyMAC should reject tampered data")
	}
}

func TestVerifyMACRejectsWrongUserKey(t *testing.T) {
	packet := buildClientInitPacket(t, nil, nil)
	msg, err := ParseClientInit(packet)
	if err != nil {
		t.Fatalf("ParseClientInit: %v", err)
	}

	wrongKey := msg.UserKey
	wrongKey[0] ^= 0xFF
	if VerifyMAC(wrongKey, msg.ClientNonce, msg.DataBeforeMAC, msg.MAC) {
		t.Fatal("VerifyMAC should reject wrong user key")
	}
}

// --- ParseClientInit field tests ---

func TestParseClientInitFieldValues(t *testing.T) {
	packet := buildClientInitPacket(t, nil, nil)
	msg, err := ParseClientInit(packet)
	if err != nil {
		t.Fatalf("ParseClientInit: %v", err)
	}

	// Verify parsed fields match what we put in
	userKey := bytesOf(32, 0x01)
	deviceID := bytesOf(16, 0x21)
	ephPub := bytesOf(32, 0x31)
	wgStaticPub := bytesOf(32, 0x51)
	clientNonce := bytesOf(16, 0x71)

	for i, b := range userKey {
		if msg.UserKey[i] != b {
			t.Fatalf("UserKey mismatch at byte %d", i)
		}
	}
	for i, b := range deviceID {
		if msg.DeviceID[i] != b {
			t.Fatalf("DeviceID mismatch at byte %d", i)
		}
	}
	for i, b := range ephPub {
		if msg.EphPub[i] != b {
			t.Fatalf("EphPub mismatch at byte %d", i)
		}
	}
	for i, b := range wgStaticPub {
		if msg.WGStaticPub[i] != b {
			t.Fatalf("WGStaticPub mismatch at byte %d", i)
		}
	}
	for i, b := range clientNonce {
		if msg.ClientNonce[i] != b {
			t.Fatalf("ClientNonce mismatch at byte %d", i)
		}
	}
}

func TestParseClientInitRejectsInvalidMagic(t *testing.T) {
	packet := buildClientInitPacket(t, nil, nil)
	packet[0] = 0x00 // corrupt magic
	if _, err := ParseClientInit(packet); err != errInvalidMagic {
		t.Fatalf("expected errInvalidMagic, got %v", err)
	}
}

func TestParseClientInitRejectsInvalidVersion(t *testing.T) {
	packet := buildClientInitPacket(t, nil, nil)
	packet[4] = 0x99 // bad version
	if _, err := ParseClientInit(packet); err != errUnsupportedVersion {
		t.Fatalf("expected errUnsupportedVersion, got %v", err)
	}
}

func TestParseClientInitRejectsInvalidCookieLen(t *testing.T) {
	packet := buildClientInitPacket(t, nil, nil)
	// cookie_len field is at offset 133
	packet[133] = 16 // invalid, only 0 or 32 allowed
	if _, err := ParseClientInit(packet); err != errInvalidCookieLen {
		t.Fatalf("expected errInvalidCookieLen, got %v", err)
	}
}

// --- IsDynamicGuardPacket tests ---

func TestIsDynamicGuardPacket(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"valid DG", []byte{0x44, 0x47, 0x30, 0x31, 0x01}, true},
		{"too short", []byte{0x44, 0x47, 0x30}, false},
		{"wrong magic", []byte{0x44, 0x47, 0x30, 0x32, 0x01}, false},
		{"DG magic wrong version", []byte{0x44, 0x47, 0x30, 0x31, 0x99}, false},
		{"WG packet", []byte{0x01, 0x00, 0x00, 0x00, 0x00}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsDynamicGuardPacket(tt.data); got != tt.want {
				t.Fatalf("IsDynamicGuardPacket(%v) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}
}

// --- PoW tests ---

func TestVerifyPoWZeroDifficultyAlwaysTrue(t *testing.T) {
	if !VerifyPoW([32]byte{}, [8]byte{}, 0) {
		t.Fatal("PoW with difficulty 0 should always pass")
	}
}

func TestVerifyPoWBruteForce(t *testing.T) {
	cookie := sha256.Sum256([]byte("test-cookie"))
	difficulty := uint8(8) // easy enough to brute-force quickly

	var found bool
	for i := 0; i < 1<<16; i++ {
		var nonce [8]byte
		binary.LittleEndian.PutUint64(nonce[:], uint64(i))
		if VerifyPoW(cookie, nonce, difficulty) {
			found = true
			// Verify consistency: calling again should also pass
			if !VerifyPoW(cookie, nonce, difficulty) {
				t.Fatal("VerifyPoW inconsistent result")
			}
			break
		}
	}
	if !found {
		t.Fatal("should find valid nonce within 2^16 attempts for difficulty=8")
	}
}

func TestVerifyPoWRejectsInvalidNonce(t *testing.T) {
	cookie := sha256.Sum256([]byte("reject-test"))
	// Very high difficulty almost certainly rejects any random nonce
	if VerifyPoW(cookie, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, 128) {
		t.Fatal("difficulty=128 should reject random nonce")
	}
}

// --- CookieReply tests ---

func TestBuildCookieReplyFormat(t *testing.T) {
	var cookie [32]byte
	for i := range cookie {
		cookie[i] = byte(i)
	}
	reply := BuildCookieReply(cookie, 16)

	if len(reply) != cookieReplySize {
		t.Fatalf("expected size %d, got %d", cookieReplySize, len(reply))
	}
	// Magic
	if reply[0] != dgMagic[0] || reply[1] != dgMagic[1] || reply[2] != dgMagic[2] || reply[3] != dgMagic[3] {
		t.Fatal("magic mismatch")
	}
	// Version
	if reply[4] != dgVersion {
		t.Fatalf("expected version %d, got %d", dgVersion, reply[4])
	}
	// Msg type
	if reply[5] != cookieReplyMsgType {
		t.Fatalf("expected msg_type %d, got %d", cookieReplyMsgType, reply[5])
	}
	// Cookie
	for i := 0; i < 32; i++ {
		if reply[6+i] != cookie[i] {
			t.Fatalf("cookie byte %d mismatch", i)
		}
	}
	// PoW difficulty
	if reply[38] != 16 {
		t.Fatalf("expected pow_difficulty 16, got %d", reply[38])
	}
}

// --- ServerReply tests ---

func TestBuildServerReplyIPv4Decryptable(t *testing.T) {
	// Generate key pair for testing
	var serverPriv [32]byte
	for i := range serverPriv {
		serverPriv[i] = byte(i + 1)
	}
	var clientEphPriv [32]byte
	for i := range clientEphPriv {
		clientEphPriv[i] = byte(i + 100)
	}
	var clientEphPub [32]byte
	curve25519.ScalarBaseMult(&clientEphPub, &clientEphPriv)

	var userKey [32]byte
	for i := range userKey {
		userKey[i] = byte(i + 50)
	}
	clientNonce, _ := GenerateNonce()
	serverNonce, _ := GenerateNonce()

	replyKey, err := DeriveReplyKey(serverPriv, clientEphPub, userKey, clientNonce, serverNonce)
	if err != nil {
		t.Fatalf("DeriveReplyKey: %v", err)
	}

	payload := &ServerReplyPayload{
		AddressFamily: 4,
		AssignedIP:    netip.MustParseAddr("10.0.0.42"),
		PrefixLen:     24,
		LeaseTTL:      3600,
	}

	reply, err := BuildServerReply(serverNonce, replyKey, payload)
	if err != nil {
		t.Fatalf("BuildServerReply: %v", err)
	}

	// Verify format: magic(4) + version(1) + server_nonce(16) + ciphertext
	if len(reply) < 21 {
		t.Fatal("reply too short")
	}
	if reply[0] != dgMagic[0] || reply[1] != dgMagic[1] || reply[2] != dgMagic[2] || reply[3] != dgMagic[3] {
		t.Fatal("magic mismatch")
	}
	if reply[4] != dgVersion {
		t.Fatal("version mismatch")
	}

	// Client-side derivation should produce the same key
	var serverPub [32]byte
	curve25519.ScalarBaseMult(&serverPub, &serverPriv)
	clientDH, _ := curve25519.X25519(clientEphPriv[:], serverPub[:])

	ikm := make([]byte, 64)
	copy(ikm[:32], clientDH)
	copy(ikm[32:], userKey[:])
	salt := make([]byte, 32)
	copy(salt[:16], clientNonce[:])
	copy(salt[16:], serverNonce[:])
	reader := hkdf.New(sha256.New, ikm, salt, replyInfo)
	clientReplyKey := make([]byte, 32)
	io.ReadFull(reader, clientReplyKey)

	// Decrypt
	aead, _ := chacha20poly1305.New(clientReplyKey)
	nonce := make([]byte, 12)
	header := reply[:21]
	ciphertext := reply[21:]
	plaintext, err := aead.Open(nil, nonce, ciphertext, header)
	if err != nil {
		t.Fatalf("client failed to decrypt ServerReply: %v", err)
	}

	// Parse payload
	if plaintext[0] != 4 {
		t.Fatalf("expected address_family=4, got %d", plaintext[0])
	}
	ip := netip.AddrFrom4([4]byte{plaintext[1], plaintext[2], plaintext[3], plaintext[4]})
	if ip != netip.MustParseAddr("10.0.0.42") {
		t.Fatalf("expected 10.0.0.42, got %s", ip)
	}
	if plaintext[5] != 24 {
		t.Fatalf("expected prefix_len=24, got %d", plaintext[5])
	}
	ttl := binary.LittleEndian.Uint32(plaintext[6:10])
	if ttl != 3600 {
		t.Fatalf("expected lease_ttl=3600, got %d", ttl)
	}
}

func TestBuildServerReplyIPv6(t *testing.T) {
	var serverPriv [32]byte
	for i := range serverPriv {
		serverPriv[i] = byte(i + 1)
	}
	var clientEphPriv [32]byte
	for i := range clientEphPriv {
		clientEphPriv[i] = byte(i + 100)
	}
	var clientEphPub [32]byte
	curve25519.ScalarBaseMult(&clientEphPub, &clientEphPriv)

	var userKey [32]byte
	clientNonce, _ := GenerateNonce()
	serverNonce, _ := GenerateNonce()

	replyKey, err := DeriveReplyKey(serverPriv, clientEphPub, userKey, clientNonce, serverNonce)
	if err != nil {
		t.Fatalf("DeriveReplyKey: %v", err)
	}

	payload := &ServerReplyPayload{
		AddressFamily: 6,
		AssignedIP:    netip.MustParseAddr("fd00::42"),
		PrefixLen:     112,
		LeaseTTL:      7200,
	}

	reply, err := BuildServerReply(serverNonce, replyKey, payload)
	if err != nil {
		t.Fatalf("BuildServerReply: %v", err)
	}

	// IPv6 reply = 21(header) + payload + 16(tag)
	// payload = af(1) + ip(16) + prefix(1) + ttl(4) + params(26) = 48
	// => 21 + 48 + 16 = 85
	if len(reply) != 85 {
		t.Fatalf("expected IPv6 reply size 85, got %d", len(reply))
	}
}

// --- AmneziaParams round-trip + generation tests ---

// TestServerReplyParamsRoundTrip 验证 per-node 参数经 encode → 加密 → 解密 →
// decode 后逐字段还原（模拟客户端从 DG01 ServerReply 取参数的完整路径）。
func TestServerReplyParamsRoundTrip(t *testing.T) {
	var serverPriv [32]byte
	for i := range serverPriv {
		serverPriv[i] = byte(i + 7)
	}
	var clientEphPriv [32]byte
	for i := range clientEphPriv {
		clientEphPriv[i] = byte(i + 130)
	}
	var clientEphPub [32]byte
	curve25519.ScalarBaseMult(&clientEphPub, &clientEphPriv)

	var userKey [32]byte
	for i := range userKey {
		userKey[i] = byte(i + 11)
	}
	clientNonce, _ := GenerateNonce()
	serverNonce, _ := GenerateNonce()

	replyKey, err := DeriveReplyKey(serverPriv, clientEphPub, userKey, clientNonce, serverNonce)
	if err != nil {
		t.Fatalf("DeriveReplyKey: %v", err)
	}

	params := AmneziaParams{
		Jc: 9, Jmin: 23, Jmax: 211,
		S1: 76, S2: 129,
		H1: 0x11223344, H2: 0xAABBCCDD, H3: 0x0A0B0C0D, H4: 0xF0E1D2C3,
	}
	payload := &ServerReplyPayload{
		AddressFamily: 4,
		AssignedIP:    netip.MustParseAddr("10.7.0.9"),
		PrefixLen:     24,
		LeaseTTL:      3600,
		Params:        params,
	}

	reply, err := BuildServerReply(serverNonce, replyKey, payload)
	if err != nil {
		t.Fatalf("BuildServerReply: %v", err)
	}

	// 客户端侧解密
	aead, _ := chacha20poly1305.New(replyKey)
	nonce := make([]byte, 12)
	plaintext, err := aead.Open(nil, nonce, reply[21:], reply[:21])
	if err != nil {
		t.Fatalf("decrypt ServerReply: %v", err)
	}

	got, err := decodeReplyPayload(plaintext)
	if err != nil {
		t.Fatalf("decodeReplyPayload: %v", err)
	}

	if got.AddressFamily != 4 || got.AssignedIP != netip.MustParseAddr("10.7.0.9") ||
		got.PrefixLen != 24 || got.LeaseTTL != 3600 {
		t.Fatalf("base fields mismatch: %+v", got)
	}
	if got.Params != params {
		t.Fatalf("params mismatch:\n got %+v\nwant %+v", got.Params, params)
	}
}

// TestDecodeReplyPayloadRejectsShort 验证截断载荷被拒（防越界）。
func TestDecodeReplyPayloadRejectsShort(t *testing.T) {
	full := encodeReplyPayload(&ServerReplyPayload{
		AddressFamily: 4,
		AssignedIP:    netip.MustParseAddr("10.0.0.1"),
		PrefixLen:     24,
		LeaseTTL:      60,
		Params:        AmneziaParams{Jc: 1, Jmin: 2, Jmax: 3, S1: 4, S2: 5, H1: 6, H2: 7, H3: 8, H4: 9},
	})
	if _, err := decodeReplyPayload(full[:len(full)-1]); err != errInvalidPacketSize {
		t.Fatalf("expected errInvalidPacketSize for truncated payload, got %v", err)
	}
	if _, err := decodeReplyPayload([]byte{0x09}); err != errInvalidAddressFamily {
		t.Fatalf("expected errInvalidAddressFamily for af=9, got %v", err)
	}
}

// TestGenerateAmneziaParamsConstraints 验证生成的参数满足 amneziawg-go
// handlePostConfig 的全部约束（多次抽样以覆盖随机性）。
func TestGenerateAmneziaParamsConstraints(t *testing.T) {
	for i := 0; i < 2000; i++ {
		p, err := GenerateAmneziaParams()
		if err != nil {
			t.Fatalf("GenerateAmneziaParams: %v", err)
		}

		// H1-H4：均 > 4、四者互异、避开 DG01 魔数
		hs := []uint32{p.H1, p.H2, p.H3, p.H4}
		seen := map[uint32]struct{}{}
		for _, h := range hs {
			if h <= 4 {
				t.Fatalf("magic header %d not > 4", h)
			}
			if h == dgMagicLEUint32 || h == dgMagicBEUint32 {
				t.Fatalf("magic header collides with DG01 magic: %d", h)
			}
			if _, dup := seen[h]; dup {
				t.Fatalf("magic headers not distinct: %v", hs)
			}
			seen[h] = struct{}{}
		}

		// s1/s2：148+s1 != 92+s2
		if wgInitHeaderSize+p.S1 == wgResponseHeaderSize+p.S2 {
			t.Fatalf("init size %d == response size %d (must differ)",
				wgInitHeaderSize+p.S1, wgResponseHeaderSize+p.S2)
		}

		// jmin <= jmax
		if p.Jmin > p.Jmax {
			t.Fatalf("jmin %d > jmax %d", p.Jmin, p.Jmax)
		}

		// 均为正、远小于 MTU 预算
		if p.Jc <= 0 || p.S1 <= 0 || p.S2 <= 0 || p.Jmin <= 0 {
			t.Fatalf("non-positive size param: %+v", p)
		}
		if wgInitHeaderSize+p.S1 >= 1408 || wgResponseHeaderSize+p.S2 >= 1408 || p.Jmax >= 1408 {
			t.Fatalf("param exceeds MTU budget: %+v", p)
		}
	}
}

// TestSharedAmneziaParamsStable 验证进程级 singleton：多次调用返回同一组参数
// （amnezia magic 是包级全局，同进程所有 DGServer 必须共用一组）。
func TestSharedAmneziaParamsStable(t *testing.T) {
	p1, err := SharedAmneziaParams()
	if err != nil {
		t.Fatalf("SharedAmneziaParams: %v", err)
	}
	p2, err := SharedAmneziaParams()
	if err != nil {
		t.Fatalf("SharedAmneziaParams (2nd): %v", err)
	}
	if p1 != p2 {
		t.Fatalf("singleton returned differing params:\n p1=%+v\n p2=%+v", p1, p2)
	}
}

// --- ComputeIdempotencyKey tests ---

func TestIdempotencyKeyDeterministic(t *testing.T) {
	k1 := ComputeIdempotencyKey([32]byte{1}, [16]byte{2}, [32]byte{3}, [32]byte{4}, [16]byte{5})
	k2 := ComputeIdempotencyKey([32]byte{1}, [16]byte{2}, [32]byte{3}, [32]byte{4}, [16]byte{5})
	if k1 != k2 {
		t.Fatal("same inputs should yield same idempotency key")
	}
}

func TestIdempotencyKeyUnique(t *testing.T) {
	k1 := ComputeIdempotencyKey([32]byte{1}, [16]byte{2}, [32]byte{3}, [32]byte{4}, [16]byte{5})
	k2 := ComputeIdempotencyKey([32]byte{1}, [16]byte{2}, [32]byte{3}, [32]byte{4}, [16]byte{6})
	if k1 == k2 {
		t.Fatal("different inputs should yield different keys")
	}
}

// --- UserKeyFromUUID test ---

func TestUserKeyFromUUIDDeterministic(t *testing.T) {
	k1 := UserKeyFromUUID("550e8400-e29b-41d4-a716-446655440000")
	k2 := UserKeyFromUUID("550e8400-e29b-41d4-a716-446655440000")
	if k1 != k2 {
		t.Fatal("same UUID should yield same key")
	}

	k3 := UserKeyFromUUID("different-uuid")
	if k1 == k3 {
		t.Fatal("different UUIDs should yield different keys")
	}
}

// --- GenerateNonce test ---

func TestGenerateNonceUnique(t *testing.T) {
	n1, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce: %v", err)
	}
	n2, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce: %v", err)
	}
	if n1 == n2 {
		t.Fatal("two nonces should not be equal")
	}
}

// --- checkLeadingZeros tests ---

func TestCheckLeadingZeros(t *testing.T) {
	tests := []struct {
		name       string
		hash       []byte
		difficulty uint8
		want       bool
	}{
		{"0 difficulty", []byte{0xFF}, 0, true},
		{"8 zeros pass", []byte{0x00, 0xFF}, 8, true},
		{"8 zeros fail", []byte{0x01, 0xFF}, 8, false},
		{"4 zeros pass", []byte{0x0F}, 4, true},
		{"4 zeros fail", []byte{0x1F}, 4, false},
		{"16 zeros pass", []byte{0x00, 0x00, 0xFF}, 16, true},
		{"16 zeros fail", []byte{0x00, 0x01, 0xFF}, 16, false},
		{"12 zeros pass", []byte{0x00, 0x0F}, 12, true},
		{"12 zeros fail", []byte{0x00, 0x10}, 12, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkLeadingZeros(tt.hash, tt.difficulty); got != tt.want {
				t.Fatalf("checkLeadingZeros = %v, want %v", got, tt.want)
			}
		})
	}
}
