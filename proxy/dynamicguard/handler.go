package dynamicguard

import (
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

// UserEntry 用户信息
type UserEntry struct {
	UserID      int
	UUID        string
	UserKey     [32]byte
	DeviceLimit int
	SpeedLimit  int
	GroupID     int
}

// Handler 处理 ClientInit 报文
type Handler struct {
	userKeyMap   *UserKeyMap
	deviceTable  *DeviceTable
	ipPools      map[int]*IPPool // group_id -> pool
	wgDevice     *WGDevice
	idemCache    *IdempotencyCache
	cookieMgr    *CookieManager
	serverWGPriv [32]byte
	leaseTTL     uint32

	pendingCount atomic.Int64
}

// HandlerConfig 处理器配置
type HandlerConfig struct {
	UserKeyMap   *UserKeyMap
	DeviceTable  *DeviceTable
	IPPools      map[int]*IPPool
	WGDevice     *WGDevice
	IdemCache    *IdempotencyCache
	CookieMgr    *CookieManager
	ServerWGPriv [32]byte
	LeaseTTL     uint32
}

// NewHandler 创建处理器
func NewHandler(cfg *HandlerConfig) *Handler {
	return &Handler{
		userKeyMap:   cfg.UserKeyMap,
		deviceTable:  cfg.DeviceTable,
		ipPools:      cfg.IPPools,
		wgDevice:     cfg.WGDevice,
		idemCache:    cfg.IdemCache,
		cookieMgr:    cfg.CookieMgr,
		serverWGPriv: cfg.ServerWGPriv,
		leaseTTL:     cfg.LeaseTTL,
	}
}

// HandleClientInit 处理 ClientInit 报文（协议第 9 节 14 步）
func (h *Handler) HandleClientInit(data []byte, srcAddr *net.UDPAddr, udpConn *net.UDPConn) {
	h.pendingCount.Add(1)
	defer h.pendingCount.Add(-1)

	// Step 1: 解析报文（校验 magic/version/size）
	msg, err := ParseClientInit(data)
	if err != nil {
		log.WithFields(log.Fields{
			"src":          srcAddr.String(),
			"packet_bytes": len(data),
			"err":          err,
		}).Debug("[DynamicGuard] parse ClientInit failed")
		return // 静默丢弃
	}

	// Step 2: 查 userKeyMap
	user := h.userKeyMap.Get(msg.UserKey)
	if user == nil {
		log.WithFields(log.Fields{
			"src":    srcAddr.String(),
			"device": fmt.Sprintf("%x", msg.DeviceID[:4]),
		}).Debug("[DynamicGuard] unknown user key")
		return // 静默丢弃
	}

	// Step 3: Cookie 校验
	if h.cookieMgr.IsEnabled() {
		if len(msg.Cookie) > 0 {
			var cookie [32]byte
			copy(cookie[:], msg.Cookie)
			if !h.cookieMgr.VerifyCookie(cookie, srcAddr.IP, uint16(srcAddr.Port)) {
				log.WithFields(log.Fields{
					"src":     srcAddr.String(),
					"user_id": user.UserID,
					"device":  fmt.Sprintf("%x", msg.DeviceID[:4]),
				}).Debug("[DynamicGuard] cookie verification failed")
				return // 静默丢弃
			}

			// Step 4: PoW 校验
			if h.cookieMgr.GetPowDifficulty() > 0 {
				if len(msg.PowNonce) != 8 {
					log.WithFields(log.Fields{
						"src":     srcAddr.String(),
						"user_id": user.UserID,
						"device":  fmt.Sprintf("%x", msg.DeviceID[:4]),
					}).Debug("[DynamicGuard] invalid PoW nonce length")
					return // 静默丢弃
				}
				var powNonce [8]byte
				copy(powNonce[:], msg.PowNonce)
				if !VerifyPoW(cookie, powNonce, h.cookieMgr.GetPowDifficulty()) {
					log.WithFields(log.Fields{
						"src":     srcAddr.String(),
						"user_id": user.UserID,
						"device":  fmt.Sprintf("%x", msg.DeviceID[:4]),
					}).Debug("[DynamicGuard] PoW verification failed")
					return // 静默丢弃
				}
			}
		} else {
			// Step 5: 无 cookie 且高负载 → 发 CookieReply
			if h.pendingCount.Load() > int64(highLoadThreshold) {
				cookie := h.cookieMgr.GenerateCookie(srcAddr.IP, uint16(srcAddr.Port))
				reply := BuildCookieReply(cookie, h.cookieMgr.GetPowDifficulty())
				udpConn.WriteToUDP(reply, srcAddr)
				log.WithFields(log.Fields{
					"src":              srcAddr.String(),
					"user_id":          user.UserID,
					"device":           fmt.Sprintf("%x", msg.DeviceID[:4]),
					"pending_requests": h.pendingCount.Load(),
				}).Debug("[DynamicGuard] sent cookie challenge")
				return
			}
		}
	}

	// Step 6: MAC 校验
	if !VerifyMAC(msg.UserKey, msg.ClientNonce, msg.DataBeforeMAC, msg.MAC) {
		log.WithFields(log.Fields{
			"src":     srcAddr.String(),
			"user_id": user.UserID,
			"device":  fmt.Sprintf("%x", msg.DeviceID[:4]),
		}).Debug("[DynamicGuard] MAC verification failed")
		return // 静默丢弃
	}

	// Step 7: 幂等缓存检查
	idemKey := ComputeIdempotencyKey(msg.UserKey, msg.DeviceID, msg.EphPub, msg.WGStaticPub, msg.ClientNonce)
	if cached, ok := h.idemCache.Get(idemKey); ok {
		udpConn.WriteToUDP(cached, srcAddr)
		log.WithFields(log.Fields{
			"src":     srcAddr.String(),
			"user_id": user.UserID,
			"device":  fmt.Sprintf("%x", msg.DeviceID[:4]),
		}).Debug("[DynamicGuard] idempotent reply reused")
		return
	}

	// Step 8: X25519 DH（在 MAC 之后执行，保护计算资源）
	// DH 将在 Step 12 中通过 DeriveReplyKey 自动完成

	// Step 9-10: 查设备表 + 分配 IP（原子操作）
	h.deviceTable.LockDevice(user.UserID, msg.DeviceID)
	defer h.deviceTable.UnlockDevice(user.UserID, msg.DeviceID)

	entry := h.deviceTable.Lookup(user.UserID, msg.DeviceID)

	var assignedIP netip.Addr

	if entry != nil {
		// 已有记录
		if entry.Status == DeviceStatusRevoked {
			log.WithFields(log.Fields{
				"src":     srcAddr.String(),
				"user_id": user.UserID,
				"device":  fmt.Sprintf("%x", msg.DeviceID[:4]),
			}).Debug("[DynamicGuard] revoked device rejected")
			return // 静默丢弃
		}
		if entry.WGStaticPub != msg.WGStaticPub {
			log.WithFields(log.Fields{
				"src":     srcAddr.String(),
				"user_id": user.UserID,
				"device":  fmt.Sprintf("%x", msg.DeviceID[:4]),
			}).Warn("[DynamicGuard] device public key mismatch")
			return // wg_static_pub 不一致，静默丢弃
		}

		if entry.Status == DeviceStatusDisconnected || !entry.AssignedIP.IsValid() {
			// disconnected 设备重连：IP 已被释放，需重新分配
			// 同步 GroupID（用户可能被移到新权限组）
			entry.GroupID = user.GroupID
			pool, ok := h.ipPools[user.GroupID]
			if !ok {
				log.Warnf("[DynamicGuard] no IP pool for group %d", user.GroupID)
				return
			}
			newIP, allocErr := pool.Allocate()
			if allocErr != nil {
				log.Warnf("[DynamicGuard] IP re-allocation failed for group %d: %v", user.GroupID, allocErr)
				return
			}
			assignedIP = newIP
			entry.AssignedIP = newIP
			h.deviceTable.UpdateIP(entry)
			log.WithFields(log.Fields{
				"src":      srcAddr.String(),
				"user_id":  user.UserID,
				"device":   fmt.Sprintf("%x", msg.DeviceID[:4]),
				"group_id": user.GroupID,
				"ip":       newIP.String(),
			}).Info("[DynamicGuard] disconnected device reallocated IP")
		} else {
			// active 设备重连，复用原 IP
			assignedIP = entry.AssignedIP
			log.WithFields(log.Fields{
				"src":      srcAddr.String(),
				"user_id":  user.UserID,
				"device":   fmt.Sprintf("%x", msg.DeviceID[:4]),
				"group_id": user.GroupID,
				"ip":       assignedIP.String(),
			}).Debug("[DynamicGuard] active device reused IP")
		}
		entry.Status = DeviceStatusActive
		entry.LastSeen = time.Now()
	} else {
		// 新设备：检查设备数限制
		if user.DeviceLimit > 0 && h.deviceTable.CountByUser(user.UserID) >= user.DeviceLimit {
			log.WithFields(log.Fields{
				"src":          srcAddr.String(),
				"user_id":      user.UserID,
				"device":       fmt.Sprintf("%x", msg.DeviceID[:4]),
				"device_limit": user.DeviceLimit,
			}).Info("[DynamicGuard] device limit reached")
			return // 静默丢弃
		}

		// 按 group_id 分配 IP
		pool, ok := h.ipPools[user.GroupID]
		if !ok {
			log.Warnf("[DynamicGuard] no IP pool for group %d", user.GroupID)
			return
		}

		assignedIP, err = pool.Allocate()
		if err != nil {
			log.Warnf("[DynamicGuard] IP allocation failed for group %d: %v", user.GroupID, err)
			return
		}

		entry = &DeviceEntry{
			UserID:      user.UserID,
			DeviceID:    msg.DeviceID,
			WGStaticPub: msg.WGStaticPub,
			AssignedIP:  assignedIP,
			LastSeen:    time.Now(),
			Status:      DeviceStatusActive,
			GroupID:     user.GroupID,
		}

		if err := h.deviceTable.Register(entry); err != nil {
			pool.Release(assignedIP)
			log.Warnf("[DynamicGuard] device register failed: %v", err)
			return
		}
		log.WithFields(log.Fields{
			"src":      srcAddr.String(),
			"user_id":  user.UserID,
			"device":   fmt.Sprintf("%x", msg.DeviceID[:4]),
			"group_id": user.GroupID,
			"ip":       assignedIP.String(),
		}).Info("[DynamicGuard] registered new device")
	}

	// Step 11: WireGuard AddPeer
	if err := h.wgDevice.AddPeer(msg.WGStaticPub, assignedIP); err != nil {
		log.Errorf("[DynamicGuard] WG AddPeer failed: %v", err)
		return
	}

	// Step 12: 生成 server_nonce，派生 reply_key
	serverNonce, err := GenerateNonce()
	if err != nil {
		log.Errorf("[DynamicGuard] generate nonce failed: %v", err)
		return
	}

	replyKey, err := DeriveReplyKey(h.serverWGPriv, msg.EphPub, msg.UserKey, msg.ClientNonce, serverNonce)
	if err != nil {
		log.Errorf("[DynamicGuard] derive reply key failed: %v", err)
		return
	}

	// 确定 prefix_len
	var prefixLen uint8
	if pool, ok := h.ipPools[user.GroupID]; ok {
		prefixLen = uint8(pool.PrefixBits())
	} else if assignedIP.Is4() {
		prefixLen = 24
	} else {
		prefixLen = 112
	}

	// 确定 address_family
	var addrFamily byte = 4
	if assignedIP.Is6() {
		addrFamily = 6
	}

	payload := &ServerReplyPayload{
		AddressFamily: addrFamily,
		AssignedIP:    assignedIP,
		PrefixLen:     prefixLen,
		LeaseTTL:      h.leaseTTL,
	}

	// Step 13: 加密并发送 ServerReply
	reply, err := BuildServerReply(serverNonce, replyKey, payload)
	if err != nil {
		log.Errorf("[DynamicGuard] build server reply failed: %v", err)
		return
	}

	if _, err := udpConn.WriteToUDP(reply, srcAddr); err != nil {
		log.Debugf("[DynamicGuard] send reply failed: %v", err)
		return
	}

	// Step 14: 写入幂等缓存
	h.idemCache.Set(idemKey, reply)

	log.WithFields(log.Fields{
		"src":     srcAddr.String(),
		"user_id": user.UserID,
		"device":  fmt.Sprintf("%x", msg.DeviceID[:4]),
		"ip":      assignedIP.String(),
	}).Debug("[DynamicGuard] handshake completed")
}
