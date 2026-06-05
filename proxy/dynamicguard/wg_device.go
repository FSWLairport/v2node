package dynamicguard

import (
	"bytes"
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

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun"
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

// DGEndpoint 实现 conn.Endpoint 接口（使用值类型 netip.AddrPort 避免逃逸）
type DGEndpoint struct {
	dst netip.AddrPort
	src netip.Addr // 收包时的本地 IP（源进源出；roaming 时由 ClearSrc 清除）
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
		// 纯透传：原样投递 UDP 字节给 amneziawg-go device。
		// junk 包剔除、magic header(h1-h4) 识别、s1/s2 头部 junk 剥离
		// 均由 amnezia receive.go 内部完成，bind 层不做任何字节变换。
		sizes[0] = copy(packets[0], pkt.Data)
		eps[0] = &DGEndpoint{dst: pkt.Addr, src: pkt.LocalAddr}
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
	// 纯透传：buf 已由 amneziawg-go device 层完成全部抗 DPI 变换
	// （junk 包、s1/s2 头部 junk、h1-h4 magic header），bind 层只负责写 UDP。
	// 源进源出：用收包时的本地 IP 作为回包源 IP。
	oob := buildSrcOOB(dgEp.src)
	for _, buf := range bufs {
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
	Params      AmneziaParams  // per-node AmneziaWG 抗 DPI 参数（与下发给客户端的同一组）
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

	// 配置私钥 + AmneziaWG 抗 DPI 参数（per-node 生成，同一组通过 DG01
	// ServerReply 下发给客户端；客户端须逐字段匹配 s1/s2/h1-h4 才能握手成功）
	privKeyHex := hex.EncodeToString(cfg.PrivateKey[:])
	if err := dev.IpcSet(
		"private_key=" + privKeyHex + "\n" + cfg.Params.IpcLines(),
	); err != nil {
		dev.Close()
		return nil, fmt.Errorf("set private key + awg params: %w", err)
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
