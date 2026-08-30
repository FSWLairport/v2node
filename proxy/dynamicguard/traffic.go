package dynamicguard

import (
	"sync"
)

// UserKeyMap 用户密钥映射（user_key → UserEntry）
type UserKeyMap struct {
	mu      sync.RWMutex
	entries map[[32]byte]*UserEntry
	byID    map[int]*UserEntry // user_id → UserEntry
}

// NewUserKeyMap 创建用户密钥映射
func NewUserKeyMap() *UserKeyMap {
	return &UserKeyMap{
		entries: make(map[[32]byte]*UserEntry),
		byID:    make(map[int]*UserEntry),
	}
}

// Get 按 user_key 查找用户
func (m *UserKeyMap) Get(key [32]byte) *UserEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.entries[key]
}

// GetByID 按 user_id 查找用户
func (m *UserKeyMap) GetByID(userID int) *UserEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.byID[userID]
}

// Update 全量更新用户列表
func (m *UserKeyMap) Update(users []*UserEntry) {
	newEntries := make(map[[32]byte]*UserEntry, len(users))
	newByID := make(map[int]*UserEntry, len(users))
	for _, u := range users {
		newEntries[u.UserKey] = u
		newByID[u.UserID] = u
	}

	m.mu.Lock()
	m.entries = newEntries
	m.byID = newByID
	m.mu.Unlock()
}

// Remove disables a credential immediately. It is idempotent so a retried
// revocation can safely run after the local device entry has already gone.
func (m *UserKeyMap) Remove(userID int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.byID[userID]
	if !ok {
		return false
	}
	delete(m.byID, userID)
	if current, exists := m.entries[entry.UserKey]; exists && current.UserID == userID {
		delete(m.entries, entry.UserKey)
	}
	return true
}

func (m *UserKeyMap) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.byID)
}

// UserTraffic 用户流量数据（用于上报面板）
type UserTraffic struct {
	UserID   int
	Upload   int64
	Download int64
}

// CollectUserTraffic 将 WG peer 流量增量聚合为按用户的流量数据
// peerDeltas: map[peer_pubkey][upload, download]
func CollectUserTraffic(peerDeltas map[[32]byte][2]int64, deviceTable *DeviceTable) []UserTraffic {
	if len(peerDeltas) == 0 {
		return nil
	}

	userTraffic := make(map[int]*UserTraffic)
	for pubKey, delta := range peerDeltas {
		entry := deviceTable.GetEntryByWGPub(pubKey)
		if entry == nil {
			continue
		}
		ut, ok := userTraffic[entry.UserID]
		if !ok {
			ut = &UserTraffic{UserID: entry.UserID}
			userTraffic[entry.UserID] = ut
		}
		ut.Upload += delta[0]
		ut.Download += delta[1]
	}

	result := make([]UserTraffic, 0, len(userTraffic))
	for _, ut := range userTraffic {
		if ut.Upload > 0 || ut.Download > 0 {
			result = append(result, *ut)
		}
	}
	return result
}
