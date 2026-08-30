package dynamicguard

import (
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"sync"
	"time"
)

// DeviceStatus 设备状态
type DeviceStatus int

const (
	DeviceStatusActive       DeviceStatus = iota // 活跃
	DeviceStatusDisconnected                     // 断开（允许重连）
	DeviceStatusRevoked                          // 已撤销
)

// DeviceEntry 设备表条目
type DeviceEntry struct {
	UserID      int
	DeviceID    [16]byte
	WGStaticPub [32]byte
	AssignedIP  netip.Addr
	LastSeen    time.Time
	Status      DeviceStatus
	GroupID     int
}

// deviceKey 用于设备表的主键
type deviceKey struct {
	UserID   int
	DeviceID [16]byte
}

// DeviceTable 设备表（内存数据结构）
type DeviceTable struct {
	byKey   map[deviceKey]*DeviceEntry
	byWGPub map[[32]byte]*DeviceEntry
	byIP    map[netip.Addr]*DeviceEntry
	byUser  map[int][]*DeviceEntry // user_id -> entries

	// 分片锁: 避免全局锁争用
	shards [256]sync.Mutex
	mu     sync.RWMutex // 全局读写锁（用于遍历和整体操作）
}

// NewDeviceTable 创建设备表
func NewDeviceTable() *DeviceTable {
	return &DeviceTable{
		byKey:   make(map[deviceKey]*DeviceEntry),
		byWGPub: make(map[[32]byte]*DeviceEntry),
		byIP:    make(map[netip.Addr]*DeviceEntry),
		byUser:  make(map[int][]*DeviceEntry),
	}
}

// shardIndex 计算分片锁索引
func shardIndex(userID int, deviceID [16]byte) uint8 {
	buf := make([]byte, 4+16)
	binary.LittleEndian.PutUint32(buf, uint32(userID))
	copy(buf[4:], deviceID[:])
	h := sha256.Sum256(buf)
	return h[0]
}

// LockDevice 获取 per-device 粒度的锁
func (dt *DeviceTable) LockDevice(userID int, deviceID [16]byte) {
	idx := shardIndex(userID, deviceID)
	dt.shards[idx].Lock()
}

// UnlockDevice 释放 per-device 粒度的锁
func (dt *DeviceTable) UnlockDevice(userID int, deviceID [16]byte) {
	idx := shardIndex(userID, deviceID)
	dt.shards[idx].Unlock()
}

// Lookup 按主键查找设备（调用前需持有 per-device 锁）
func (dt *DeviceTable) Lookup(userID int, deviceID [16]byte) *DeviceEntry {
	dt.mu.RLock()
	defer dt.mu.RUnlock()
	return dt.byKey[deviceKey{userID, deviceID}]
}

// Register 注册新设备（调用前需持有 per-device 锁）
func (dt *DeviceTable) Register(entry *DeviceEntry) error {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	key := deviceKey{entry.UserID, entry.DeviceID}

	// 唯一约束: wg_static_pub
	if existing, ok := dt.byWGPub[entry.WGStaticPub]; ok {
		if existing.UserID != entry.UserID || existing.DeviceID != entry.DeviceID {
			return errDevicePubMismatch
		}
	}

	// 唯一约束: assigned_ip
	if existing, ok := dt.byIP[entry.AssignedIP]; ok {
		if existing.UserID != entry.UserID || existing.DeviceID != entry.DeviceID {
			return errIPPoolExhausted
		}
	}

	dt.byKey[key] = entry
	dt.byWGPub[entry.WGStaticPub] = entry
	dt.byIP[entry.AssignedIP] = entry

	// 更新 byUser
	userDevices := dt.byUser[entry.UserID]
	// 检查是否已在列表中
	found := false
	for i, d := range userDevices {
		if d.DeviceID == entry.DeviceID {
			userDevices[i] = entry
			found = true
			break
		}
	}
	if !found {
		dt.byUser[entry.UserID] = append(userDevices, entry)
	}

	return nil
}

// UpdateLastSeen 更新设备最后活跃时间（协议第 14 节：收到有效 WG 包时调用）
func (dt *DeviceTable) UpdateLastSeen(wgPub [32]byte, t time.Time) {
	dt.mu.Lock()
	entry, ok := dt.byWGPub[wgPub]
	if ok {
		entry.LastSeen = t
	}
	dt.mu.Unlock()
}

// CountByUser 统计用户设备数
func (dt *DeviceTable) CountByUser(userID int) int {
	dt.mu.RLock()
	defer dt.mu.RUnlock()

	count := 0
	for _, d := range dt.byUser[userID] {
		if d.Status == DeviceStatusActive {
			count++
		}
	}
	return count
}

// RemoveByID removes a device by its stable composite key. It returns an
// immutable copy of the removed entry so callers can safely release resources
// after the table lock has been released.
func (dt *DeviceTable) RemoveByID(userID int, deviceID [16]byte) (*DeviceEntry, bool) {
	dt.LockDevice(userID, deviceID)
	defer dt.UnlockDevice(userID, deviceID)
	return dt.removeByIDLocked(userID, deviceID)
}

// removeByIDLocked requires the caller to hold the per-device shard lock.
func (dt *DeviceTable) removeByIDLocked(userID int, deviceID [16]byte) (*DeviceEntry, bool) {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	key := deviceKey{userID, deviceID}
	entry, ok := dt.byKey[key]
	if !ok {
		return nil, false
	}
	snapshot := *entry
	delete(dt.byKey, key)
	delete(dt.byWGPub, entry.WGStaticPub)
	delete(dt.byIP, entry.AssignedIP)

	// 从 byUser 列表中移除
	userDevices := dt.byUser[userID]
	for i, d := range userDevices {
		if d.DeviceID == deviceID {
			dt.byUser[userID] = append(userDevices[:i], userDevices[i+1:]...)
			break
		}
	}
	if len(dt.byUser[userID]) == 0 {
		delete(dt.byUser, userID)
	}
	return &snapshot, true
}

// ExpiredDevice 过期设备信息，携带旧 IP 用于资源释放
type ExpiredDevice struct {
	Entry *DeviceEntry
	OldIP netip.Addr
}

// CleanExpired 将过期设备标记为 disconnected，从 IP 索引中移除，但保留设备记录
// 保留 byKey/byWGPub/byUser 索引，确保重连时仍能校验 wg_static_pub 一致性
// 返回过期条目及其旧 IP，调用方负责用旧 IP 释放地址池和清理流量记录
func (dt *DeviceTable) CleanExpired(ttl time.Duration) []ExpiredDevice {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	now := time.Now()
	var expired []ExpiredDevice

	for _, entry := range dt.byKey {
		if entry.Status == DeviceStatusActive && now.Sub(entry.LastSeen) > ttl {
			oldIP := entry.AssignedIP
			entry.Status = DeviceStatusDisconnected
			// 从 IP 索引中移除
			delete(dt.byIP, oldIP)
			// 清空 entry 上的 IP，重连时需重新分配
			entry.AssignedIP = netip.Addr{}
			expired = append(expired, ExpiredDevice{Entry: entry, OldIP: oldIP})
		}
	}

	return expired
}

// GroupIDByIP resolves a tunnel address to the network (group) whose pool
// leased it. It reports false when no device currently holds the address.
func (dt *DeviceTable) GroupIDByIP(ip netip.Addr) (int, bool) {
	dt.mu.RLock()
	defer dt.mu.RUnlock()
	entry, ok := dt.byIP[ip]
	if !ok {
		return 0, false
	}
	return entry.GroupID, true
}

// UpdateIP 更新设备的 IP 索引（disconnected 重连后重新分配 IP 时调用）
func (dt *DeviceTable) UpdateIP(entry *DeviceEntry) {
	dt.mu.Lock()
	defer dt.mu.Unlock()
	dt.byIP[entry.AssignedIP] = entry
}

// GetEntryByWGPub 按 WG 公钥查找设备
func (dt *DeviceTable) GetEntryByWGPub(pub [32]byte) *DeviceEntry {
	dt.mu.RLock()
	defer dt.mu.RUnlock()
	return dt.byWGPub[pub]
}

// GetDevicesByUser 返回用户的所有设备（副本）
func (dt *DeviceTable) GetDevicesByUser(userID int) []*DeviceEntry {
	dt.mu.RLock()
	defer dt.mu.RUnlock()
	src := dt.byUser[userID]
	result := make([]*DeviceEntry, len(src))
	for i, entry := range src {
		copyOfEntry := *entry
		result[i] = &copyOfEntry
	}
	return result
}

// GetAllActive 返回所有活跃设备
func (dt *DeviceTable) GetAllActive() []*DeviceEntry {
	dt.mu.RLock()
	defer dt.mu.RUnlock()

	var result []*DeviceEntry
	for _, entry := range dt.byKey {
		if entry.Status == DeviceStatusActive {
			copyOfEntry := *entry
			result = append(result, &copyOfEntry)
		}
	}
	return result
}
