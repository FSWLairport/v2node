package dynamicguard

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// ReceivedPacket 从 UDP 分流后的 WireGuard 报文
type ReceivedPacket struct {
	Data      []byte
	Addr      netip.AddrPort
	LocalAddr netip.Addr // 收包时本地目的 IP（源进源出）
	buf       *[]byte    // 池化缓冲区指针，recvFn 处理完后归还到 pktPool
}

// pktPool 复用 readLoop 的读缓冲区，消除每包堆分配
var pktPool = sync.Pool{
	New: func() any {
		b := make([]byte, 65536)
		return &b
	},
}

// dynamicGuardReserved 是 DynamicGuard 专属的 WireGuard reserved 字段标记 "SKY"。
// 必须与客户端 sing-box protocol/dynamicguard/endpoint.go 中的 dynamicGuardReserved 保持一致。
//
// WireGuard 报文前 4 字节被 wireguard-go 当作 LittleEndian uint32 读取 message type，
// reserved 占据其高 3 字节（msg[1:4]）。因此：
//   - 入站（recvFn）：交给 wireguard-go 前必须清零 msg[1:4]，否则 type 校验失败丢包，握手中断。
//   - 出站（Send）：写 UDP 前盖上该标记，与客户端对称伪装。
//
// 仅作用于 DynamicGuard 的 WG 报文（type 0x01..0x04），不影响普通 WireGuard。
var dynamicGuardReserved = [3]byte{0x53, 0x4B, 0x59}

// dgReservedPayload 是 reserved 通道当前承载的明文元数据（预留给未来 dgVersion 等协商）。
// 现阶段全 0：经 dgXorReserved 编码后产出 == dynamicGuardReserved("SKY")，
// 因此线上字节与固定 "SKY" 完全一致，本次改动对 wire 零影响。
var dgReservedPayload = [3]byte{0, 0, 0}

// dgXorReserved 对 reserved 三字节做 XOR 编解码（与 key 异或，自反：encode==decode）。
//   - 出站：dgXorReserved(payload, key) 得到伪装后的 reserved 字节。
//   - 入站：dgXorReserved(wire, key) 还原出 payload 明文。
//
// key 固定为 dynamicGuardReserved，须与客户端保持一致。
func dgXorReserved(v, key [3]byte) [3]byte {
	return [3]byte{v[0] ^ key[0], v[1] ^ key[1], v[2] ^ key[2]}
}

// dgObfsKey 是 reserved 元数据 HMAC 掩码的 32 字节固定密钥。
// 用于将 padLen + 熵编码到 WG reserved[1:4] 中，消除尾部 LV 指纹。
// 必须与客户端 client_bind.go 的 dgObfsKey 逐字节一致。
var dgObfsKey = [32]byte{
	0x7E, 0x3A, 0x91, 0xF5, 0x0C, 0x68, 0xD4, 0xB2,
	0xA1, 0x5F, 0xE8, 0x33, 0x9C, 0x47, 0x6D, 0x0A,
	0x52, 0xBD, 0x1E, 0x89, 0xF4, 0xC7, 0x26, 0x38,
	0xAF, 0x09, 0xE1, 0x5B, 0x77, 0x2C, 0x80, 0xDF,
}

const (
	dgPadMax        = 96
	dgPadMin        = 1
	wgHandshakeInit = 148 // WG type 1
	wgHandshakeResp = 92  // WG type 2
	wgCookieReply   = 64  // WG type 3
	wgKeepalive     = 32  // WG type 4 keepalive (data > 32)
	dgJunkMin       = 32
	dgJunkMax       = 256
	dgJunkMaxCount  = 3
)

// wgBaseLen 返回 WG 消息类型对应的握手/keepalive 基础长度。
func wgBaseLen(msgType byte) int {
	switch msgType {
	case 0x01:
		return wgHandshakeInit
	case 0x02:
		return wgHandshakeResp
	case 0x03:
		return wgCookieReply
	case 0x04:
		return wgKeepalive
	default:
		return 0
	}
}

// dgShouldPad 判断 WG 报文是否需要追加 anti-DPI padding。
func dgShouldPad(msgType byte, msgLen int) bool {
	switch msgType {
	case 0x01, 0x02, 0x03:
		return true
	case 0x04:
		return msgLen == wgKeepalive
	default:
		return false
	}
}

// dgComputeMask 计算 reserved 元数据的 3 字节 HMAC 掩码。
func dgComputeMask(normType byte, msgPayload []byte) [3]byte {
	mac := hmac.New(sha256.New, dgObfsKey[:])
	mac.Write([]byte{normType})
	mac.Write(msgPayload)
	sum := mac.Sum(nil)
	return [3]byte{sum[0], sum[1], sum[2]}
}

// dgEncodeReserved 将 padLen + rand16 编码到 reserved 三字节（masked）。
func dgEncodeReserved(normType byte, msgPayload []byte, padLen uint8, randU16 uint16) [3]byte {
	plain24 := uint32(padLen) | uint32(randU16)<<8
	mask := dgComputeMask(normType, msgPayload)
	return [3]byte{
		byte(plain24) ^ mask[0],
		byte(plain24>>8) ^ mask[1],
		byte(plain24>>16) ^ mask[2],
	}
}

// dgDecodeReserved 从 masked reserved 三字节解码出 plain24。
func dgDecodeReserved(normType byte, msgPayload []byte, wire [3]byte) (plain24 uint32) {
	mask := dgComputeMask(normType, msgPayload)
	return uint32(wire[0]^mask[0]) | uint32(wire[1]^mask[1])<<8 | uint32(wire[2]^mask[2])<<16
}

// randPadLen 返回 [dgPadMin, dgPadMax] 随机 pad 长度。
func randPadLen() uint8 {
	var b [1]byte
	rand.Read(b[:])
	return uint8(b[0]%byte(dgPadMax)) + dgPadMin
}

// randUint16 返回随机 uint16（crypto/rand）。
func randUint16() uint16 {
	var b [2]byte
	rand.Read(b[:])
	return uint16(b[0]) | uint16(b[1])<<8
}

// DGEndpoint 实现 conn.Endpoint 接口（使用值类型 netip.AddrPort 避免逃逸）
type DGEndpoint struct {
	dst             netip.AddrPort
	src             netip.Addr // 收包时的本地 IP（源进源出；roaming 时由 ClearSrc 清除）
	transformType   bool       // 上行 type 是否被 mask（0x81..0x84），用于下行镜像伪装
	reservedPayload [3]byte    // 入站从 reserved 解码出的明文元数据（预留给 dgVersion 协商）
}

// ClearSrc 在 wireguard-go 检测到 endpoint roaming 时调用，清除旧的本地源 IP。
// 下次 recvFn 返回新 endpoint 时会带上新的 src。
func (e *DGEndpoint) ClearSrc() { e.src = netip.Addr{} }
func (e *DGEndpoint) SrcToString() string {
	if e.src.IsValid() {
		return e.src.String()
	}
	return ""
}
func (e *DGEndpoint) DstToString() string { return e.dst.String() }
func (e *DGEndpoint) DstIP() netip.Addr   { return e.dst.Addr() }
func (e *DGEndpoint) SrcIP() netip.Addr   { return e.src }
func (e *DGEndpoint) DstToBytes() []byte {
	b, _ := e.dst.MarshalBinary()
	return b
}

// DGBind 实现 conn.Bind 接口，从外部 channel 接收 WG 报文
type DGBind struct {
	incoming    chan *ReceivedPacket
	udpConn     *net.UDPConn
	deviceTable *DeviceTable
	mu          sync.Mutex
	closed      bool
}

// NewDGBind 创建自定义 Bind
func NewDGBind(udpConn *net.UDPConn, deviceTable *DeviceTable) *DGBind {
	return &DGBind{
		incoming:    make(chan *ReceivedPacket, 4096),
		udpConn:     udpConn,
		deviceTable: deviceTable,
	}
}

// Deliver 将分流后的 WG 报文送入 bind
func (b *DGBind) Deliver(pkt *ReceivedPacket) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		if pkt.buf != nil {
			pktPool.Put(pkt.buf)
			pkt.buf = nil
		}
		return
	}
	ch := b.incoming
	b.mu.Unlock()

	select {
	case ch <- pkt:
	default:
		// 队列满：归还池化缓冲区
		if pkt.buf != nil {
			pktPool.Put(pkt.buf)
			pkt.buf = nil
		}
	}
}

func (b *DGBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	// wireguard-go 在 BindUpdate 时先 Close 再 Open，需要重建 channel
	b.incoming = make(chan *ReceivedPacket, 4096)
	b.closed = false
	ch := b.incoming
	b.mu.Unlock()

	recvFn := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		pkt, ok := <-ch
		if !ok {
			return 0, net.ErrClosed
		}
		n := copy(packets[0], pkt.Data)
		sizes[0] = n

		var masked bool
		var rpayload [3]byte
		if n >= 4 {
			b0 := packets[0][0]
			masked = b0 >= 0x81 && b0 <= 0x84
			normType := b0 & 0x7F

			if (b0 >= 0x01 && b0 <= 0x04) || masked {
				baseLen := wgBaseLen(normType)

				// 尝试从 HMAC-masked reserved 解码 padLen
				if baseLen > 0 && n >= baseLen {
					wire := [3]byte{packets[0][1], packets[0][2], packets[0][3]}
					plain24 := dgDecodeReserved(normType, packets[0][4:baseLen], wire)
					padLen := uint8(plain24 & 0xFF)
					rpayload = [3]byte{byte(plain24), byte(plain24 >> 8), byte(plain24 >> 16)}

					// 校验 padLen 合法且长度匹配 → strip padding
					if padLen >= dgPadMin && padLen <= dgPadMax && n == baseLen+int(padLen) {
						sizes[0] = baseLen
					}
				}

				// 还原 type 并清零 reserved（WG 解析要求 reserved==0）
				packets[0][0] = normType
				packets[0][1] = 0
				packets[0][2] = 0
				packets[0][3] = 0
			}
		}
		eps[0] = &DGEndpoint{dst: pkt.Addr, src: pkt.LocalAddr, transformType: masked, reservedPayload: rpayload}
		// 归还池化缓冲区
		if pkt.buf != nil {
			pktPool.Put(pkt.buf)
			pkt.buf = nil
		}
		return 1, nil
	}
	return []conn.ReceiveFunc{recvFn}, 0, nil
}

func (b *DGBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.closed {
		b.closed = true
		// 排空残留报文，归还池化缓冲区
		for {
			select {
			case pkt := <-b.incoming:
				if pkt.buf != nil {
					pktPool.Put(pkt.buf)
				}
			default:
				close(b.incoming)
				return nil
			}
		}
	}
	return nil
}

func (b *DGBind) SetMark(mark uint32) error { return nil }

func (b *DGBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	dgEp, ok := ep.(*DGEndpoint)
	if !ok {
		return fmt.Errorf("invalid endpoint type")
	}
	// 源进源出：用收包时的本地 IP 作为回包源 IP
	oob := buildSrcOOB(dgEp.src)
	for _, buf := range bufs {
		if len(buf) >= 4 && buf[0] >= 0x01 && buf[0] <= 0x04 {
			normType := buf[0]

			// 出站 type mask：镜像上行伪装（0x01..0x04 → 0x81..0x84）
			if dgEp.transformType {
				buf[0] |= 0x80
			}

			if dgShouldPad(normType, len(buf)) {
				// 握手（type 1/2/3）或 keepalive（type 4, len==32）：
				// reserved[1:4] 用 HMAC-masked padLen + 熵编码，尾部追加随机 pad
				baseLen := wgBaseLen(normType)
				if baseLen > 0 && len(buf) >= baseLen {
					padLen := randPadLen()
					randU16 := randUint16()
					enc := dgEncodeReserved(normType, buf[4:baseLen], padLen, randU16)
					buf[1], buf[2], buf[3] = enc[0], enc[1], enc[2]

					paddedLen := baseLen + int(padLen)
					paddedBuf := make([]byte, paddedLen)
					copy(paddedBuf[:baseLen], buf[:baseLen])
					rand.Read(paddedBuf[baseLen:])

					var err error
					if oob != nil {
						_, _, err = b.udpConn.WriteMsgUDPAddrPort(paddedBuf, oob, dgEp.dst)
					} else {
						_, err = b.udpConn.WriteToUDPAddrPort(paddedBuf, dgEp.dst)
					}
					if err != nil {
						return err
					}
					continue
				}
				// 退化：回退到旧 reserved 编码
				enc := dgXorReserved(dgReservedPayload, dynamicGuardReserved)
				buf[1], buf[2], buf[3] = enc[0], enc[1], enc[2]
			} else if normType == 0x04 && len(buf) > wgKeepalive {
				// Type 4 data 报文：reserved 编码 padLen=0 + 熵，不加 padding
				// 关键：编码 padLen=0 而非纯随机三字节，避免接收端把 data 误当作
				// padded keepalive 截断到 32B（详见 client_bind.go 对称注释）。
				enc := dgEncodeReserved(normType, buf[4:wgKeepalive], 0, randUint16())
				buf[1], buf[2], buf[3] = enc[0], enc[1], enc[2]
			} else {
				// 其他：旧编码
				enc := dgXorReserved(dgReservedPayload, dynamicGuardReserved)
				buf[1], buf[2], buf[3] = enc[0], enc[1], enc[2]
			}
		}
		if oob != nil {
			if _, _, err := b.udpConn.WriteMsgUDPAddrPort(buf, oob, dgEp.dst); err != nil {
				return err
			}
		} else {
			if _, err := b.udpConn.WriteToUDPAddrPort(buf, dgEp.dst); err != nil {
				return err
			}
		}
	}
	return nil
}

func (b *DGBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &DGEndpoint{dst: ap}, nil
}

func (b *DGBind) BatchSize() int { return 1 }

// WGDevice 封装 wireguard-go 设备（使用内核 TUN）
type WGDevice struct {
	device      *device.Device
	bind        *DGBind
	tunName     string
	privateKey  [32]byte
	deviceTable *DeviceTable
	mu          sync.Mutex
	lastStats   map[[32]byte]peerTraffic // 上次采集的 peer 流量
}

type peerTraffic struct {
	rxBytes int64
	txBytes int64
}

// WGDeviceConfig WG 设备配置
type WGDeviceConfig struct {
	PrivateKey  [32]byte
	MTU         int
	UDPConn     *net.UDPConn
	TunnelAddrs []netip.Addr   // 各 IP 池的网关地址
	Prefixes    []netip.Prefix // 各 IP 池的子网前缀（用于路由和 NAT）
}

// NewWGDevice 创建 WireGuard 用户态设备（使用内核 TUN 接口）
func NewWGDevice(cfg *WGDeviceConfig) (*WGDevice, error) {
	// 使用 dg%d 模式让内核自动分配编号，支持多实例共存
	tunDev, err := tun.CreateTUN("dg%d", cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("create TUN: %w", err)
	}
	tunName, err := tunDev.Name()
	if err != nil {
		tunDev.Close()
		return nil, fmt.Errorf("get TUN name: %w", err)
	}
	log.WithFields(log.Fields{
		"tun": tunName,
		"mtu": cfg.MTU,
	}).Info("[DynamicGuard] created TUN device")

	// 创建自定义 bind
	bind := NewDGBind(cfg.UDPConn, nil) // deviceTable 在创建后注入

	// wireguard-go 日志
	wgLogger := &device.Logger{
		Verbosef: func(format string, args ...any) {
			log.Debugf("[WireGuard] "+format, args...)
		},
		Errorf: func(format string, args ...any) {
			log.Errorf("[WireGuard] "+format, args...)
		},
	}

	// 创建 wireguard-go 设备
	dev := device.NewDevice(tunDev, bind, wgLogger)

	// 配置私钥
	privKeyHex := hex.EncodeToString(cfg.PrivateKey[:])
	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\n", privKeyHex)); err != nil {
		dev.Close()
		return nil, fmt.Errorf("set private key: %w", err)
	}

	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("device up: %w", err)
	}

	// 配置系统网络（ip addr + ip_forward）
	if err := configureNetwork(tunName, cfg.TunnelAddrs, cfg.Prefixes); err != nil {
		dev.Close()
		return nil, fmt.Errorf("configure network: %w", err)
	}

	return &WGDevice{
		device:      dev,
		bind:        bind,
		tunName:     tunName,
		privateKey:  cfg.PrivateKey,
		deviceTable: nil, // 在 server 初始化后通过 SetDeviceTable 注入
		lastStats:   make(map[[32]byte]peerTraffic),
	}, nil
}

// SetDeviceTable 注入设备表引用（在 server 初始化完成后调用）
func (w *WGDevice) SetDeviceTable(dt *DeviceTable) {
	w.deviceTable = dt
	w.bind.deviceTable = dt
}

// configureNetwork 配置内核 TUN 的地址和路由
func configureNetwork(tunName string, addrs []netip.Addr, prefixes []netip.Prefix) error {
	// 启动 TUN 接口
	if out, err := exec.Command("ip", "link", "set", tunName, "up").CombinedOutput(); err != nil {
		return fmt.Errorf("ip link set up: %s: %w", strings.TrimSpace(string(out)), err)
	}
	log.WithField("tun", tunName).Info("[DynamicGuard] TUN link is up")

	// 增大 TUN 发送队列，减少高吞吐时的丢包
	if out, err := exec.Command("ip", "link", "set", tunName, "txqueuelen", "1000").CombinedOutput(); err != nil {
		log.WithFields(log.Fields{
			"tun": tunName,
			"err": err,
			"out": strings.TrimSpace(string(out)),
		}).Warn("[DynamicGuard] failed to set txqueuelen")
	}

	// 添加 IP 地址（每个 IP 池的网关地址，同时自动创建连接路由）
	for i, addr := range addrs {
		bits := prefixes[i].Bits()
		cidr := fmt.Sprintf("%s/%d", addr, bits)
		if out, err := exec.Command("ip", "addr", "add", cidr, "dev", tunName).CombinedOutput(); err != nil {
			outStr := strings.TrimSpace(string(out))
			if !strings.Contains(outStr, "File exists") && !strings.Contains(outStr, "Address already assigned") {
				return fmt.Errorf("ip addr add %s: %s: %w", cidr, outStr, err)
			}
		}
		log.Infof("[DynamicGuard] TUN %s: added %s", tunName, cidr)
	}

	// 启用 IP 转发
	if out, err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").CombinedOutput(); err != nil {
		log.WithFields(log.Fields{
			"tun": tunName,
			"err": err,
			"out": strings.TrimSpace(string(out)),
		}).Warn("[DynamicGuard] failed to enable ipv4 forwarding")
	} else {
		log.WithFields(log.Fields{
			"tun": tunName,
			"out": strings.TrimSpace(string(out)),
		}).Debug("[DynamicGuard] ipv4 forwarding enabled")
	}

	return nil
}

// AddPeer 动态添加 WireGuard peer
func (w *WGDevice) AddPeer(publicKey [32]byte, allowedIP netip.Addr) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	ipcRequest := buildPeerIPCRequest(publicKey, allowedIP)

	if err := w.device.IpcSet(ipcRequest); err != nil {
		return fmt.Errorf("add peer: %w", err)
	}

	log.Debugf("[DynamicGuard] added WG peer %s with allowed_ip %s",
		base64.StdEncoding.EncodeToString(publicKey[:]), allowedIPCIDR(allowedIP))
	return nil
}

func buildPeerIPCRequest(publicKey [32]byte, allowedIP netip.Addr) string {
	// DynamicGuard 服务端应等待客户端首个合法 WireGuard 握手来学习 endpoint，
	// 不要在此阶段强制 keepalive 或猜测 endpoint，否则会在 endpoint 未知时触发无意义的主动握手。
	return fmt.Sprintf(
		"public_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s\n",
		hex.EncodeToString(publicKey[:]), allowedIPCIDR(allowedIP),
	)
}

func allowedIPCIDR(allowedIP netip.Addr) string {
	if allowedIP.Is4() {
		return allowedIP.String() + "/32"
	}
	return allowedIP.String() + "/128"
}

// RemovePeer 移除 WireGuard peer
func (w *WGDevice) RemovePeer(publicKey [32]byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	pubKeyHex := hex.EncodeToString(publicKey[:])
	ipcRequest := fmt.Sprintf("public_key=%s\nremove=true\n", pubKeyHex)

	if err := w.device.IpcSet(ipcRequest); err != nil {
		return fmt.Errorf("remove peer: %w", err)
	}

	// 清理 lastStats 中的该 peer 记录
	delete(w.lastStats, publicKey)

	log.Debugf("[DynamicGuard] removed WG peer %s",
		base64.StdEncoding.EncodeToString(publicKey[:]))
	return nil
}

// GetBind 返回自定义 Bind（用于送入 WG 报文）
func (w *WGDevice) GetBind() *DGBind {
	return w.bind
}

// CollectTrafficDelta 通过 WG IPC 读取 peer 流量统计，返回增量
// 同时更新有流量的 peer 对应设备的 last_seen（协议第 14 节）
// 返回 map[peer_pubkey][upload, download]
func (w *WGDevice) CollectTrafficDelta() map[[32]byte][2]int64 {
	w.mu.Lock()
	defer w.mu.Unlock()

	var buf bytes.Buffer
	if err := w.device.IpcGetOperation(&buf); err != nil {
		log.Debugf("[DynamicGuard] IPC get failed: %v", err)
		return nil
	}

	currentStats := parsePeerStats(buf.String())
	result := make(map[[32]byte][2]int64)
	now := time.Now()

	for pubKey, stats := range currentStats {
		prev := w.lastStats[pubKey]
		// rx_bytes = 客户端上传（client → server）
		// tx_bytes = 客户端下载（server → client）
		deltaRx := stats.rxBytes - prev.rxBytes
		deltaTx := stats.txBytes - prev.txBytes
		// 处理计数器重置（peer 被移除后重新添加）
		if deltaRx < 0 {
			deltaRx = stats.rxBytes
		}
		if deltaTx < 0 {
			deltaTx = stats.txBytes
		}
		if deltaRx > 0 || deltaTx > 0 {
			result[pubKey] = [2]int64{deltaRx, deltaTx}
			// 有流量 → 更新 last_seen，防止活跃设备被错误过期
			if w.deviceTable != nil {
				w.deviceTable.UpdateLastSeen(pubKey, now)
			}
		}
		w.lastStats[pubKey] = stats
	}

	// 清理已移除 peer 的残留记录
	for pubKey := range w.lastStats {
		if _, exists := currentStats[pubKey]; !exists {
			delete(w.lastStats, pubKey)
		}
	}

	return result
}

// Close 关闭 WG 设备（TUN 设备随 fd 关闭自动移除，路由随之清除）
func (w *WGDevice) Close() {
	log.WithField("tun", w.tunName).Info("[DynamicGuard] closing WireGuard device")
	w.device.Close()
}

// parsePeerStats 解析 WG IPC 输出中的 peer 流量统计
func parsePeerStats(ipcOutput string) map[[32]byte]peerTraffic {
	stats := make(map[[32]byte]peerTraffic)
	var currentKey [32]byte
	var hasKey bool
	var currentRx, currentTx int64

	for _, line := range strings.Split(ipcOutput, "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		switch parts[0] {
		case "public_key":
			if hasKey {
				stats[currentKey] = peerTraffic{rxBytes: currentRx, txBytes: currentTx}
			}
			keyBytes, err := hex.DecodeString(parts[1])
			if err != nil || len(keyBytes) != 32 {
				hasKey = false
				continue
			}
			copy(currentKey[:], keyBytes)
			hasKey = true
			currentRx = 0
			currentTx = 0
		case "rx_bytes":
			currentRx, _ = strconv.ParseInt(parts[1], 10, 64)
		case "tx_bytes":
			currentTx, _ = strconv.ParseInt(parts[1], 10, 64)
		}
	}
	if hasKey {
		stats[currentKey] = peerTraffic{rxBytes: currentRx, txBytes: currentTx}
	}

	return stats
}
