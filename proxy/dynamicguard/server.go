package dynamicguard

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
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

	// 收集所有 IP 池的网关地址和子网前缀
	var tunnelAddrs []netip.Addr
	var ipPrefixes []netip.Prefix
	for _, pool := range ipPools {
		gwAddr := pool.network.Addr().Next()
		tunnelAddrs = append(tunnelAddrs, gwAddr)
		ipPrefixes = append(ipPrefixes, pool.network)
		pool.Reserve(gwAddr)
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

// Start 启动 DG 服务端
func (s *DGServer) Start() error {
	// 启动租约管理
	s.leaseMgr.Start()

	// 启动 UDP 读取循环
	go s.readLoop()

	log.Infof("[DynamicGuard] server started on %s", s.udpConn.LocalAddr())
	return nil
}

// UpdateUsers 更新用户列表
func (s *DGServer) UpdateUsers(users []*UserEntry) {
	s.userKeyMap.Update(users)
	log.Debugf("[DynamicGuard] updated %d users", len(users))
}

// GetUserTraffic 通过 WG IPC 采集 peer 流量并按用户聚合
func (s *DGServer) GetUserTraffic() []UserTraffic {
	deltas := s.wgDevice.CollectTrafficDelta()
	return CollectUserTraffic(deltas, s.deviceTable)
}

// RemoveUser 移除已删除用户的所有设备（WG peer、IP 池）
func (s *DGServer) RemoveUser(userID int) {
	devices := s.deviceTable.GetDevicesByUser(userID)
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
	close(s.stopCh)
	s.leaseMgr.Close()
	s.idemCache.Close()
	s.wgDevice.Close()
	s.udpConn.Close()
	log.Info("[DynamicGuard] server closed")
}

func (s *DGServer) readLoop() {
	buf := make([]byte, 65536)
	for {
		select {
		case <-s.stopCh:
			return
		default:
		}

		s.udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, addr, err := s.udpConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-s.stopCh:
				return
			default:
				log.Debugf("[DynamicGuard] UDP read error: %v", err)
				continue
			}
		}

		if n < 5 {
			continue // 太短，丢弃
		}

		// 复制数据以避免并发问题
		data := make([]byte, n)
		copy(data, buf[:n])

		// 按首字节分流
		if IsDynamicGuardPacket(data) {
			go s.handler.HandleClientInit(data, addr, s.udpConn)
		} else if IsWireGuardPacket(data) {
			// 送入 WG Bind channel
			s.wgDevice.GetBind().Deliver(&ReceivedPacket{
				Data: data,
				Addr: addr,
			})
		}
		// 其他情况静默丢弃
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
