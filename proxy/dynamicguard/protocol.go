package dynamicguard

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"math/bits"
	"net/netip"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

var (
	dgMagic   = [4]byte{0x44, 0x47, 0x30, 0x31} // "DG01"
	dgVersion = byte(0x01)

	macInfo   = []byte("dynamicguard-mac-v1")
	replyInfo = []byte("dynamicguard-reply-v1")
)

const (
	cookieReplyMsgType = byte(0xFE)
	cookieReplySize    = 39
	minClientInitSize  = 167 // 无 cookie / 无 PoW 时最小大小
	maxClientInitSize  = 207 // 有 cookie + PoW 时最大大小
)

// ClientInitMsg 表示解析后的 ClientInit 报文
type ClientInitMsg struct {
	UserKey     [32]byte
	DeviceID    [16]byte
	EphPub      [32]byte
	WGStaticPub [32]byte
	ClientNonce [16]byte
	Cookie      []byte // 0 或 32 字节
	PowNonce    []byte // 0 或 8 字节
	MAC         [32]byte
	// 用于 MAC 验证的原始数据（magic 到 pow_nonce 末尾）
	DataBeforeMAC []byte
}

// ServerReplyPayload 表示 ServerReply 的明文载荷
type ServerReplyPayload struct {
	AddressFamily byte // 4 = IPv4, 6 = IPv6
	AssignedIP    netip.Addr
	PrefixLen     uint8
	LeaseTTL      uint32
	// Params 是 per-node AmneziaWG 抗 DPI 参数，加密下发给客户端；客户端据此
	// 配置自己的 amnezia 设备后再发起 WireGuard 握手。append-only 追加在载荷
	// 尾部，不影响既有字段的 wire 偏移。
	Params AmneziaParams
}

// IsDynamicGuardPacket 检查报文是否为 DynamicGuard 报文
func IsDynamicGuardPacket(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	// 同时校验 version 字节：把随机 junk 包 / amnezia 握手包首 4 字节意外撞
	// "DG01" 而被误分流到 DG 控制面的概率从 ~1/2^32 收紧到 ~1/2^40。DG01
	// 协议双端 pin 在 v1，未来升级版本号前此守卫无副作用。
	return data[0] == dgMagic[0] && data[1] == dgMagic[1] &&
		data[2] == dgMagic[2] && data[3] == dgMagic[3] &&
		data[4] == dgVersion
}

// ParseClientInit 解析 ClientInit 报文
func ParseClientInit(data []byte) (*ClientInitMsg, error) {
	if len(data) < minClientInitSize || len(data) > maxClientInitSize {
		return nil, errInvalidPacketSize
	}

	// 校验 magic 和 version
	if data[0] != dgMagic[0] || data[1] != dgMagic[1] || data[2] != dgMagic[2] || data[3] != dgMagic[3] {
		return nil, errInvalidMagic
	}
	if data[4] != dgVersion {
		return nil, errUnsupportedVersion
	}

	msg := &ClientInitMsg{}

	offset := 5
	copy(msg.UserKey[:], data[offset:offset+32])
	offset += 32
	copy(msg.DeviceID[:], data[offset:offset+16])
	offset += 16
	copy(msg.EphPub[:], data[offset:offset+32])
	offset += 32
	copy(msg.WGStaticPub[:], data[offset:offset+32])
	offset += 32
	copy(msg.ClientNonce[:], data[offset:offset+16])
	offset += 16

	// cookie_len
	cookieLen := int(data[offset])
	offset++
	if cookieLen != 0 && cookieLen != 32 {
		return nil, errInvalidCookieLen
	}
	if cookieLen > 0 {
		if offset+cookieLen > len(data) {
			return nil, errInvalidPacketSize
		}
		msg.Cookie = make([]byte, cookieLen)
		copy(msg.Cookie, data[offset:offset+cookieLen])
		offset += cookieLen
	}

	// pow_nonce_len
	if offset >= len(data) {
		return nil, errInvalidPacketSize
	}
	powNonceLen := int(data[offset])
	offset++
	if powNonceLen != 0 && powNonceLen != 8 {
		return nil, errInvalidPowNonceLen
	}
	if powNonceLen > 0 {
		if offset+powNonceLen > len(data) {
			return nil, errInvalidPacketSize
		}
		msg.PowNonce = make([]byte, powNonceLen)
		copy(msg.PowNonce, data[offset:offset+powNonceLen])
		offset += powNonceLen
	}

	// MAC (最后 32 字节)
	if offset+32 != len(data) {
		return nil, errInvalidPacketSize
	}
	msg.DataBeforeMAC = make([]byte, offset)
	copy(msg.DataBeforeMAC, data[:offset])
	copy(msg.MAC[:], data[offset:])

	return msg, nil
}

// VerifyMAC 验证 ClientInit 的 MAC
func VerifyMAC(userKey [32]byte, clientNonce [16]byte, dataBeforeMAC []byte, mac [32]byte) bool {
	computed, err := computeMAC(userKey, clientNonce, dataBeforeMAC)
	if err != nil {
		return false
	}
	return hmac.Equal(computed[:], mac[:])
}

// DeriveReplyKey 派生 ServerReply 的 AEAD 密钥
func DeriveReplyKey(serverWGPriv [32]byte, clientEphPub [32]byte, userKey [32]byte, clientNonce [16]byte, serverNonce [16]byte) ([]byte, error) {
	// dh = X25519(server_wg_priv, client_eph_pub)
	dh, err := curve25519.X25519(serverWGPriv[:], clientEphPub[:])
	if err != nil {
		return nil, err
	}

	// ikm = dh || user_key
	ikm := make([]byte, 64)
	copy(ikm[:32], dh)
	copy(ikm[32:], userKey[:])

	// salt = client_nonce || server_nonce
	salt := make([]byte, 32)
	copy(salt[:16], clientNonce[:])
	copy(salt[16:], serverNonce[:])

	// reply_key = HKDF-SHA256(ikm, salt, info="dynamicguard-reply-v1")
	reader := hkdf.New(sha256.New, ikm, salt, replyInfo)
	replyKey := make([]byte, 32)
	if _, err := io.ReadFull(reader, replyKey); err != nil {
		return nil, err
	}
	return replyKey, nil
}

// BuildServerReply 构造 ServerReply 报文
func BuildServerReply(serverNonce [16]byte, replyKey []byte, payload *ServerReplyPayload) ([]byte, error) {
	// 编码明文载荷
	plaintext := encodeReplyPayload(payload)

	// 构造 AEAD
	aead, err := chacha20poly1305.New(replyKey)
	if err != nil {
		return nil, err
	}

	// 构造报文头部: magic(4) + version(1) + server_nonce(16)
	header := make([]byte, 21)
	copy(header[:4], dgMagic[:])
	header[4] = dgVersion
	copy(header[5:21], serverNonce[:])

	// nonce = 12 字节全零
	nonce := make([]byte, 12)

	// aad = header (前 21 字节)
	ciphertext := aead.Seal(nil, nonce, plaintext, header)

	// 组装最终报文
	result := make([]byte, 0, len(header)+len(ciphertext))
	result = append(result, header...)
	result = append(result, ciphertext...)

	return result, nil
}

// BuildCookieReply 构造 CookieReply 报文
func BuildCookieReply(cookie [32]byte, powDifficulty uint8) []byte {
	buf := make([]byte, cookieReplySize)
	copy(buf[:4], dgMagic[:])
	buf[4] = dgVersion
	buf[5] = cookieReplyMsgType
	copy(buf[6:38], cookie[:])
	buf[38] = powDifficulty
	return buf
}

// ComputeIdempotencyKey 计算幂等键
func ComputeIdempotencyKey(userKey [32]byte, deviceID [16]byte, ephPub [32]byte, wgPub [32]byte, clientNonce [16]byte) [32]byte {
	h := sha256.New()
	h.Write(userKey[:])
	h.Write(deviceID[:])
	h.Write(ephPub[:])
	h.Write(wgPub[:])
	h.Write(clientNonce[:])
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// UserKeyFromUUID 从 UUID 字符串派生 32 字节 user_key
func UserKeyFromUUID(uuid string) [32]byte {
	return sha256.Sum256([]byte(uuid))
}

// VerifyPoW 验证工作量证明
func VerifyPoW(cookie [32]byte, powNonce [8]byte, difficulty uint8) bool {
	if difficulty == 0 {
		return true
	}
	input := make([]byte, 40)
	copy(input[:32], cookie[:])
	copy(input[32:], powNonce[:])
	hash := sha256.Sum256(input)
	return checkLeadingZeros(hash[:], difficulty)
}

// GenerateNonce 生成 16 字节随机 nonce
func GenerateNonce() ([16]byte, error) {
	var nonce [16]byte
	_, err := rand.Read(nonce[:])
	return nonce, err
}

// --- 内部函数 ---

func computeMAC(userKey [32]byte, clientNonce [16]byte, data []byte) ([32]byte, error) {
	var macResult [32]byte
	// mac_key = HKDF-SHA256(ikm=user_key, salt=client_nonce, info="dynamicguard-mac-v1")
	macKeyReader := hkdf.New(sha256.New, userKey[:], clientNonce[:], macInfo)
	macKey := make([]byte, 32)
	if _, err := io.ReadFull(macKeyReader, macKey); err != nil {
		return macResult, err
	}
	// mac = HMAC-SHA256(mac_key, data)
	h := hmac.New(sha256.New, macKey)
	h.Write(data)
	copy(macResult[:], h.Sum(nil))
	return macResult, nil
}

// replyParamsSize 是追加在 ServerReply 载荷尾部的 AmneziaWG 参数字节数：
// h1-h4(4×uint32=16) + s1/s2(2×uint16=4) + jc/jmin/jmax(3×uint16=6) = 26。
const replyParamsSize = 4*4 + 2*2 + 3*2

func encodeReplyPayload(p *ServerReplyPayload) []byte {
	var addrBytes []byte
	if p.AddressFamily == 4 {
		addr := p.AssignedIP.As4()
		addrBytes = addr[:]
	} else {
		addr := p.AssignedIP.As16()
		addrBytes = addr[:]
	}
	// address_family(1) + ip(4|16) + prefix_len(1) + lease_ttl(4) + params(26)
	buf := make([]byte, 0, 1+len(addrBytes)+1+4+replyParamsSize)
	buf = append(buf, p.AddressFamily)
	buf = append(buf, addrBytes...)
	buf = append(buf, p.PrefixLen)
	buf = binary.LittleEndian.AppendUint32(buf, p.LeaseTTL)
	// AmneziaWG per-node 参数（append-only）。全部小端编码。
	buf = binary.LittleEndian.AppendUint32(buf, p.Params.H1)
	buf = binary.LittleEndian.AppendUint32(buf, p.Params.H2)
	buf = binary.LittleEndian.AppendUint32(buf, p.Params.H3)
	buf = binary.LittleEndian.AppendUint32(buf, p.Params.H4)
	buf = binary.LittleEndian.AppendUint16(buf, uint16(p.Params.S1))
	buf = binary.LittleEndian.AppendUint16(buf, uint16(p.Params.S2))
	buf = binary.LittleEndian.AppendUint16(buf, uint16(p.Params.Jc))
	buf = binary.LittleEndian.AppendUint16(buf, uint16(p.Params.Jmin))
	buf = binary.LittleEndian.AppendUint16(buf, uint16(p.Params.Jmax))
	return buf
}

// decodeReplyPayload 解析 ServerReply 明文载荷（与 encodeReplyPayload 互逆）。
// 服务端自身不调用，供往返测试与客户端解码复用。
func decodeReplyPayload(data []byte) (*ServerReplyPayload, error) {
	if len(data) < 1 {
		return nil, errInvalidPacketSize
	}
	p := &ServerReplyPayload{}
	offset := 0
	p.AddressFamily = data[offset]
	offset++

	var ipLen int
	switch p.AddressFamily {
	case 4:
		ipLen = 4
	case 6:
		ipLen = 16
	default:
		return nil, errInvalidAddressFamily
	}

	// af(1) + ip(ipLen) + prefix(1) + ttl(4) + params(26)
	if len(data) < offset+ipLen+1+4+replyParamsSize {
		return nil, errInvalidPacketSize
	}

	if p.AddressFamily == 4 {
		var a [4]byte
		copy(a[:], data[offset:offset+ipLen])
		p.AssignedIP = netip.AddrFrom4(a)
	} else {
		var a [16]byte
		copy(a[:], data[offset:offset+ipLen])
		p.AssignedIP = netip.AddrFrom16(a)
	}
	offset += ipLen

	p.PrefixLen = data[offset]
	offset++
	p.LeaseTTL = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	p.Params.H1 = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4
	p.Params.H2 = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4
	p.Params.H3 = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4
	p.Params.H4 = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4
	p.Params.S1 = int(binary.LittleEndian.Uint16(data[offset : offset+2]))
	offset += 2
	p.Params.S2 = int(binary.LittleEndian.Uint16(data[offset : offset+2]))
	offset += 2
	p.Params.Jc = int(binary.LittleEndian.Uint16(data[offset : offset+2]))
	offset += 2
	p.Params.Jmin = int(binary.LittleEndian.Uint16(data[offset : offset+2]))
	offset += 2
	p.Params.Jmax = int(binary.LittleEndian.Uint16(data[offset : offset+2]))

	return p, nil
}

func checkLeadingZeros(hash []byte, difficulty uint8) bool {
	fullBytes := difficulty / 8
	remainBits := difficulty % 8
	for i := range fullBytes {
		if hash[i] != 0 {
			return false
		}
	}
	if remainBits > 0 {
		return bits.LeadingZeros8(hash[fullBytes]) >= int(remainBits)
	}
	return true
}
