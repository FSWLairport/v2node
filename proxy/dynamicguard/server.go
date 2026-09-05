package dynamicguard

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/curve25519"
)

// DGSettings 从 v2board 下发的 DG 配置
type DGSettings struct {
	ServerWGKeyPath   string            `json:"server_wg_key_path"`
	ServerWGPublicKey string            `json:"server_wg_public_key"`
	LeaseTTL          uint32            `json:"lease_ttl"`
	IPPools           map[string]string `json:"ip_pools"` // group_id(string) -> CIDR
	// Routes 只是客户端分流配置（哪些目标送进隧道），服务端不据此过滤。
	Routes []string `json:"routes"`
	// ACL 是服务端强制的出网策略，按网络（group_id 字符串）区分，绝不做并集，
	// 也绝不下发给客户端。
	ACL           map[string]DGACL `json:"acl"`
	CookieEnabled bool             `json:"cookie_enabled"`
	PowDifficulty uint8            `json:"pow_difficulty"`
	MTU           int              `json:"mtu"`
}

// DGServerConfig 服务端完整配置
type DGServerConfig struct {
	ListenAddr string
	DGSettings *DGSettings
	// AccessLogEnabled comes from base_config, not from dg_settings: the panel
	// offers the same switch for both protocols.
	AccessLogEnabled bool
}

type peerRemover interface {
	RemovePeer([32]byte) error
}

// DGServer DynamicGuard 服务端
type DGServer struct {
	udpConn       *net.UDPConn
	wgDevice      *WGDevice
	peerRemover   peerRemover
	handler       *Handler
	deviceTable   *DeviceTable
	userKeyMap    *UserKeyMap
	ipPools       map[int]*IPPool
	leaseMgr      *LeaseManager
	idemCache     *IdempotencyCache
	cookieMgr     *CookieManager
	serverWGPriv  [32]byte
	leaseTTL      uint32
	stopCh        chan struct{}
	readLoopDone  sync.WaitGroup
	handshakeDone sync.WaitGroup
	closeOnce     sync.Once
	// pingQueue 把 ClientPing 从 readLoop 摘出来交给一个 worker：Ping 是唯一不受
	// cookie/PoW 保护就会碰 HMAC 的路径，洪水时既不能每包一个 goroutine，也不能
	// 在 readLoop 里同步算——那会拖慢同一 socket 上所有人的 WireGuard 数据面。
	// 队列有界，满了就丢：探测是 best-effort，客户端只是少一轮数据。
	pingQueue chan pingJob
}

type pingJob struct {
	data      []byte
	src       *net.UDPAddr
	localAddr netip.Addr
}

// pingQueueSize 是 worker 追不上时允许积压的 Ping 数；再多的直接丢。
const pingQueueSize = 1024

// NewDGServer 创建 DG 服务端
func NewDGServer(cfg *DGServerConfig) (*DGServer, error) {
	settings := cfg.DGSettings

	// 设置默认值
	if settings.LeaseTTL == 0 {
		settings.LeaseTTL = 3600
	}
	if settings.MTU == 0 {
		settings.MTU = 1408
	}

	// 读取 WG 私钥文件
	privKeyBytes, err := os.ReadFile(settings.ServerWGKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read WG private key: %w", err)
	}
	privKeyBytes = []byte(strings.TrimSpace(string(privKeyBytes)))

	var serverWGPriv [32]byte
	if len(privKeyBytes) != 32 {
		// 尝试 base64 解码
		decoded, err := decodeBase64Key(privKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("invalid WG private key format: %w", err)
		}
		serverWGPriv = decoded
	} else {
		copy(serverWGPriv[:], privKeyBytes)
	}

	serverWGPub, err := derivePublicKey(serverWGPriv)
	if err != nil {
		return nil, fmt.Errorf("derive WG public key: %w", err)
	}
	if err := validateServerKeyPair(serverWGPub, settings.ServerWGPublicKey); err != nil {
		return nil, err
	}

	// 创建 IP 池（相同 CIDR 的多个 group 共享同一实例，避免重叠分配）
	cidrToPool := make(map[string]*IPPool)
	ipPools := make(map[int]*IPPool)
	for groupStr, cidr := range settings.IPPools {
		groupID := 0
		fmt.Sscanf(groupStr, "%d", &groupID)
		pool, exists := cidrToPool[cidr]
		if !exists {
			var err error
			pool, err = NewIPPool(cidr)
			if err != nil {
				return nil, fmt.Errorf("create IP pool for group %s (%s): %w", groupStr, cidr, err)
			}
			cidrToPool[cidr] = pool
		}
		ipPools[groupID] = pool
		log.Infof("[DynamicGuard] IP pool group=%d cidr=%s", groupID, cidr)
	}

	// 绑定 UDP 端口
	udpAddr, err := net.ResolveUDPAddr("udp", cfg.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve listen addr: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("listen UDP: %w", err)
	}

	// 增大 socket 缓冲区，减少突发流量下的内核丢包
	udpConn.SetReadBuffer(4 << 20)
	udpConn.SetWriteBuffer(4 << 20)

	// 启用 IP_PKTINFO，使收包时能获取本地目的 IP（源进源出）
	if err := enablePktInfo(udpConn); err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("enable pktinfo: %w", err)
	}

	// 收集所有 IP 池的网关地址和子网前缀（按 CIDR 去重，共享池只处理一次）
	var tunnelAddrs []netip.Addr
	var ipPrefixes []netip.Prefix
	seenPool := make(map[*IPPool]struct{})
	for _, pool := range ipPools {
		if _, dup := seenPool[pool]; dup {
			continue
		}
		seenPool[pool] = struct{}{}
		gwAddr := pool.network.Addr().Next()
		tunnelAddrs = append(tunnelAddrs, gwAddr)
		ipPrefixes = append(ipPrefixes, pool.network)
		pool.Reserve(gwAddr)
		log.WithFields(log.Fields{
			"gateway": gwAddr.String(),
			"network": pool.network.String(),
		}).Debug("[DynamicGuard] reserved pool gateway")
	}
	if len(tunnelAddrs) == 0 {
		udpConn.Close()
		return nil, fmt.Errorf("no IP pools configured")
	}

	// 创建子系统
	deviceTable := NewDeviceTable()
	userKeyMap := NewUserKeyMap()
	idemCache := NewIdempotencyCache()

	// 生成 per-node AmneziaWG 抗 DPI 参数（进程级唯一，进程生命周期内恒定）。
	// 同一组参数既用于配置本机 amnezia 设备，又通过 DG01 ServerReply 加密下发
	// 给客户端，客户端据此配置自己的 amnezia 设备后再发起 WireGuard 握手。
	// 使用进程级 singleton：amnezia magic header 是包级全局，同进程多个
	// DGServer 必须共用同一组，否则后启动者会覆盖全局、破坏先启动节点的握手。
	awgParams, err := SharedAmneziaParams()
	if err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("generate amnezia params: %w", err)
	}
	log.WithFields(log.Fields{
		"jc": awgParams.Jc, "jmin": awgParams.Jmin, "jmax": awgParams.Jmax,
		"s1": awgParams.S1, "s2": awgParams.S2,
		"h1": awgParams.H1, "h2": awgParams.H2, "h3": awgParams.H3, "h4": awgParams.H4,
	}).Debug("[DynamicGuard] generated per-node AmneziaWG params")

	// 创建 WG 设备（使用内核 TUN，自动配置系统路由和 NAT）
	wgDevice, err := NewWGDevice(&WGDeviceConfig{
		PrivateKey:  serverWGPriv,
		MTU:         settings.MTU,
		UDPConn:     udpConn,
		TunnelAddrs: tunnelAddrs,
		Prefixes:    ipPrefixes,
		Params:      awgParams,
		DeviceTable: deviceTable,
		ACL:         newACLPolicy(settings.ACL),

		AccessLogEnabled: cfg.AccessLogEnabled,
	})
	if err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("create WG device: %w", err)
	}
	// 注入设备表引用，使 WG 流量采集时能更新 last_seen
	wgDevice.SetDeviceTable(deviceTable)
	cookieMgr := NewCookieManager(settings.CookieEnabled, settings.PowDifficulty)

	// 创建处理器
	handler := NewHandler(&HandlerConfig{
		UserKeyMap:   userKeyMap,
		DeviceTable:  deviceTable,
		IPPools:      ipPools,
		WGDevice:     wgDevice,
		IdemCache:    idemCache,
		CookieMgr:    cookieMgr,
		ServerWGPriv: serverWGPriv,
		LeaseTTL:     settings.LeaseTTL,
		Params:       awgParams,
	})

	// 创建租约管理器
	leaseMgr := NewLeaseManager(
		deviceTable, wgDevice, ipPools,
		time.Duration(settings.LeaseTTL)*time.Second,
	)

	return &DGServer{
		udpConn:      udpConn,
		wgDevice:     wgDevice,
		peerRemover:  wgDevice,
		handler:      handler,
		deviceTable:  deviceTable,
		userKeyMap:   userKeyMap,
		ipPools:      ipPools,
		leaseMgr:     leaseMgr,
		idemCache:    idemCache,
		cookieMgr:    cookieMgr,
		serverWGPriv: serverWGPriv,
		leaseTTL:     settings.LeaseTTL,
		stopCh:       make(chan struct{}),
		pingQueue:    make(chan pingJob, pingQueueSize),
	}, nil
}

func derivePublicKey(privateKey [32]byte) ([32]byte, error) {
	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return publicKey, nil
}

func validateServerKeyPair(derivedPub [32]byte, configuredPublicKey string) error {
	derivedPublicKey := encodeBase64Key(derivedPub)
	configuredPublicKey = strings.TrimSpace(configuredPublicKey)
	if configuredPublicKey == "" {
		return fmt.Errorf("missing server_wg_public_key; expected %s", derivedPublicKey)
	}
	if configuredPublicKey != derivedPublicKey {
		return fmt.Errorf("server_wg_public_key mismatch: configured=%s actual=%s", configuredPublicKey, derivedPublicKey)
	}
	return nil
}

func encodeBase64Key(key [32]byte) string {
	return base64.StdEncoding.EncodeToString(key[:])
}

// Start 启动 DG 服务端
func (s *DGServer) Start() error {
	// 启动租约管理
	s.leaseMgr.Start()

	// 启动 UDP 读取循环和 Ping worker
	s.readLoopDone.Add(1)
	go s.readLoop()
	s.readLoopDone.Add(1)
	go s.pingLoop()

	log.WithFields(log.Fields{
		"listen":         s.udpConn.LocalAddr().String(),
		"lease_ttl":      s.leaseTTL,
		"user_count":     len(s.userKeyMap.byID),
		"ip_pool_count":  len(s.ipPools),
		"cookie_enabled": s.cookieMgr.IsEnabled(),
		"pow_difficulty": s.cookieMgr.GetPowDifficulty(),
	}).Info("[DynamicGuard] server started")
	return nil
}

// UpdateUsers 更新用户列表
func (s *DGServer) UpdateUsers(users []*UserEntry) {
	oldCount := s.userKeyMap.Len()
	s.userKeyMap.Update(users)
	log.WithFields(log.Fields{
		"old_users": oldCount,
		"new_users": len(users),
	}).Debug("[DynamicGuard] updated users")
}

// ActiveDevices 返回当前活跃设备的快照副本，即这个节点正在出租的地址。
func (s *DGServer) ActiveDevices() []*DeviceEntry {
	return s.deviceTable.GetAllActive()
}

// DrainFlowRecords 取走自上次以来观察到的连接记录。
func (s *DGServer) DrainFlowRecords() []FlowRecord {
	return s.wgDevice.DrainFlowRecords()
}

// GetUserTraffic 通过 WG IPC 采集 peer 流量并按用户聚合
func (s *DGServer) GetUserTraffic() []UserTraffic {
	deltas := s.wgDevice.CollectTrafficDelta()
	return CollectUserTraffic(deltas, s.deviceTable)
}

// RemoveUser 移除已删除用户的所有设备（WG peer、IP 池）。
// 用户从面板消失只表示订阅到期或被暂时移除，因此不留墓碑：面板下一次把该用户
// 发回来时 UpdateUsers 会直接恢复它。
func (s *DGServer) RemoveUser(userID int) {
	s.userKeyMap.Remove(userID)
	devices := s.deviceTable.GetDevicesByUser(userID)
	if len(devices) == 0 {
		return
	}
	log.WithFields(log.Fields{
		"user_id":      userID,
		"device_count": len(devices),
	}).Info("[DynamicGuard] removing deleted user devices")

	removed := 0
	for _, device := range devices {
		// 即使 peer 删除失败也要把条目摘掉：用户已经不在名单里，没有后续重试的
		// 机会，留着条目只会永久占住 IP 和设备表。
		if err := s.peerRemover.RemovePeer(device.WGStaticPub); err != nil {
			log.Warnf("[DynamicGuard] remove peer for deleted user %d: %v", userID, err)
		}
		entry, ok := s.deviceTable.RemoveByID(userID, device.DeviceID)
		if !ok {
			continue
		}
		if entry.AssignedIP.IsValid() {
			if pool, exists := s.ipPools[entry.GroupID]; exists {
				pool.Release(entry.AssignedIP)
			}
		}
		removed++
	}
	log.Infof("[DynamicGuard] removed %d devices for deleted user %d", removed, userID)
}

// Close 关闭 DG 服务端
func (s *DGServer) Close() {
	s.closeOnce.Do(func() {
		listenAddr := ""
		if s.udpConn != nil && s.udpConn.LocalAddr() != nil {
			listenAddr = s.udpConn.LocalAddr().String()
		}

		close(s.stopCh)
		s.udpConn.Close()     // 解除 readLoop 中 ReadFromUDPAddrPort 的阻塞
		s.readLoopDone.Wait() // 确保不会再派生新的握手 goroutine
		s.handshakeDone.Wait()
		s.leaseMgr.Close()
		s.idemCache.Close()
		s.wgDevice.Close()

		log.WithField("listen", listenAddr).Info("[DynamicGuard] server closed")
	})
}

func (s *DGServer) readLoop() {
	defer s.readLoopDone.Done()

	oobBuf := make([]byte, pktInfoOOBSize)

	for {
		bufPtr := pktPool.Get().(*[]byte)
		buf := *bufPtr

		n, oobn, _, addrPort, err := s.udpConn.ReadMsgUDPAddrPort(buf, oobBuf)
		if err != nil {
			pktPool.Put(bufPtr)
			select {
			case <-s.stopCh:
				return
			default:
				log.Debugf("[DynamicGuard] UDP read error: %v", err)
				continue
			}
		}

		if n < 5 {
			pktPool.Put(bufPtr)
			continue
		}

		// 解析收包时的本地目的 IP（源进源出）
		localAddr := parseLocalAddr(oobBuf, oobn)

		data := buf[:n]

		if IsDynamicGuardPacket(data) {
			// DG 控制面（低频）：拷贝数据后立即归还池缓冲区
			dgData := make([]byte, n)
			copy(dgData, data)
			pktPool.Put(bufPtr)
			udpAddr := net.UDPAddrFromAddrPort(addrPort)
			// 按长度分流：ClientPing 固定 85 字节，ClientInit 为 167..207 字节，
			// 二者不重叠，85 字节的包永远不会进入 HandleClientInit。
			if isClientPing(dgData) {
				select {
				case s.pingQueue <- pingJob{data: dgData, src: udpAddr, localAddr: localAddr}:
				default:
					// 队列满 = 正在被 Ping 洪水冲；丢掉，不记日志，日志本身也是成本。
				}
			} else {
				s.handshakeDone.Add(1)
				go func() {
					defer s.handshakeDone.Done()
					s.handler.HandleClientInit(dgData, udpAddr, s.udpConn, localAddr)
				}()
			}
		} else {
			// 非 DG01 控制包 = AmneziaWG 数据/握手（首 4 字节为自定义 h1-h4 magic
			// header，非固定 0x01-04，无法按 type 判定）。统一零拷贝送入 bind，
			// 由 amnezia device 层识别消息类型并剔除 junk 包；非法包由其内部丢弃。
			s.wgDevice.GetBind().Deliver(&ReceivedPacket{
				Data:      data,
				Addr:      addrPort,
				LocalAddr: localAddr,
				buf:       bufPtr,
			})
		}
	}
}

// pingLoop 是唯一处理 ClientPing 的 goroutine：一次一个，CPU 上限就是一个核。
func (s *DGServer) pingLoop() {
	defer s.readLoopDone.Done()
	for {
		select {
		case <-s.stopCh:
			return
		case job := <-s.pingQueue:
			s.handler.HandlePing(job.data, job.src, s.udpConn, job.localAddr)
		}
	}
}

// decodeBase64Key 解码 base64 编码的密钥
func decodeBase64Key(data []byte) ([32]byte, error) {
	var key [32]byte
	s := string(data)

	// 尝试标准 base64
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		// 尝试 raw base64
		decoded, err = base64.RawStdEncoding.DecodeString(s)
		if err != nil {
			return key, err
		}
	}
	if len(decoded) != 32 {
		return key, fmt.Errorf("decoded key length %d, expected 32", len(decoded))
	}
	copy(key[:], decoded)
	return key, nil
}
