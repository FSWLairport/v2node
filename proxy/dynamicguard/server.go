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
	Routes            []string          `json:"routes"`
	CookieEnabled     bool              `json:"cookie_enabled"`
	PowDifficulty     uint8             `json:"pow_difficulty"`
	MTU               int               `json:"mtu"`
}

// DGServerConfig 服务端完整配置
type DGServerConfig struct {
	ListenAddr string
	DGSettings *DGSettings
}

// DGServer DynamicGuard 服务端
type DGServer struct {
	udpConn      *net.UDPConn
	wgDevice     *WGDevice
	handler      *Handler
	deviceTable  *DeviceTable
	userKeyMap   *UserKeyMap
	ipPools      map[int]*IPPool
	leaseMgr     *LeaseManager
	idemCache    *IdempotencyCache
	cookieMgr    *CookieManager
	serverWGPriv [32]byte
	leaseTTL     uint32
	stopCh       chan struct{}
	readLoopDone sync.WaitGroup
	closeOnce    sync.Once
}

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

	// 创建 IP 池
	ipPools := make(map[int]*IPPool)
	for groupStr, cidr := range settings.IPPools {
		groupID := 0
		fmt.Sscanf(groupStr, "%d", &groupID)
		pool, err := NewIPPool(cidr)
		if err != nil {
			return nil, fmt.Errorf("create IP pool for group %s (%s): %w", groupStr, cidr, err)
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

	// 收集所有 IP 池的网关地址和子网前缀
	var tunnelAddrs []netip.Addr
	var ipPrefixes []netip.Prefix
	for _, pool := range ipPools {
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

	// 创建 WG 设备（使用内核 TUN，自动配置系统路由和 NAT）
	wgDevice, err := NewWGDevice(&WGDeviceConfig{
		PrivateKey:  serverWGPriv,
		MTU:         settings.MTU,
		UDPConn:     udpConn,
		TunnelAddrs: tunnelAddrs,
		Prefixes:    ipPrefixes,
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
	})

	// 创建租约管理器
	leaseMgr := NewLeaseManager(
		deviceTable, wgDevice, ipPools,
		time.Duration(settings.LeaseTTL)*time.Second,
	)

	return &DGServer{
		udpConn:      udpConn,
		wgDevice:     wgDevice,
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

	// 启动 UDP 读取循环
	s.readLoopDone.Add(1)
	go s.readLoop()

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
	oldCount := len(s.userKeyMap.byID)
	s.userKeyMap.Update(users)
	log.WithFields(log.Fields{
		"old_users": oldCount,
		"new_users": len(users),
	}).Debug("[DynamicGuard] updated users")
}

// GetUserTraffic 通过 WG IPC 采集 peer 流量并按用户聚合
func (s *DGServer) GetUserTraffic() []UserTraffic {
	deltas := s.wgDevice.CollectTrafficDelta()
	return CollectUserTraffic(deltas, s.deviceTable)
}

// RemoveUser 移除已删除用户的所有设备（WG peer、IP 池）
func (s *DGServer) RemoveUser(userID int) {
	devices := s.deviceTable.GetDevicesByUser(userID)
	if len(devices) > 0 {
		log.WithFields(log.Fields{
			"user_id":      userID,
			"device_count": len(devices),
		}).Info("[DynamicGuard] removing deleted user devices")
	}
	for _, d := range devices {
		if err := s.wgDevice.RemovePeer(d.WGStaticPub); err != nil {
			log.Warnf("[DynamicGuard] remove peer for deleted user %d: %v", userID, err)
		}
		if d.AssignedIP.IsValid() {
			if pool, ok := s.ipPools[d.GroupID]; ok {
				pool.Release(d.AssignedIP)
			}
		}
		s.deviceTable.Remove(d)
	}
	if len(devices) > 0 {
		log.Infof("[DynamicGuard] removed %d devices for deleted user %d", len(devices), userID)
	}
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
		s.readLoopDone.Wait() // 确保 readLoop 退出后再关闭下游子系统
		s.leaseMgr.Close()
		s.idemCache.Close()
		s.wgDevice.Close()

		log.WithField("listen", listenAddr).Info("[DynamicGuard] server closed")
	})
}

func (s *DGServer) readLoop() {
	defer s.readLoopDone.Done()

	for {
		bufPtr := pktPool.Get().(*[]byte)
		buf := *bufPtr

		n, addrPort, err := s.udpConn.ReadFromUDPAddrPort(buf)
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

		data := buf[:n]

		if IsDynamicGuardPacket(data) {
			// DG 握手（低频）：拷贝数据后立即归还池缓冲区
			dgData := make([]byte, n)
			copy(dgData, data)
			pktPool.Put(bufPtr)
			udpAddr := net.UDPAddrFromAddrPort(addrPort)
			go s.handler.HandleClientInit(dgData, udpAddr, s.udpConn)
		} else if IsWireGuardPacket(data) {
			// WG 数据（高频热路径）：零拷贝送入 bind，由 recvFn 归还缓冲区
			s.wgDevice.GetBind().Deliver(&ReceivedPacket{
				Data: data,
				Addr: addrPort,
				buf:  bufPtr,
			})
		} else {
			pktPool.Put(bufPtr)
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
