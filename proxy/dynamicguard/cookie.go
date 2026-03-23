package dynamicguard

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"time"
)

const (
	cookieTimeSlot    = 120 * time.Second // cookie secret 每 120 秒轮换
	defaultPowDiff    = uint8(16)         // 默认 PoW 难度
	highLoadThreshold = 1000              // 高负载判定阈值（pending 请求数）
)

// CookieManager 管理 Cookie 和 PoW
type CookieManager struct {
	mu            sync.RWMutex
	currentSecret [32]byte
	prevSecret    [32]byte
	lastRotation  time.Time

	powDifficulty uint8
	enabled       bool
}

// NewCookieManager 创建 Cookie 管理器
func NewCookieManager(enabled bool, powDifficulty uint8) *CookieManager {
	cm := &CookieManager{
		enabled:       enabled,
		powDifficulty: powDifficulty,
	}
	if enabled {
		cm.rotateSecret()
	}
	return cm
}

// IsEnabled 是否启用 Cookie 保护
func (cm *CookieManager) IsEnabled() bool {
	return cm.enabled
}

// GetPowDifficulty 返回当前 PoW 难度
func (cm *CookieManager) GetPowDifficulty() uint8 {
	return cm.powDifficulty
}

// GenerateCookie 为指定源地址生成 cookie
func (cm *CookieManager) GenerateCookie(srcIP []byte, srcPort uint16) [32]byte {
	cm.maybeRotate()
	cm.mu.RLock()
	secret := cm.currentSecret
	cm.mu.RUnlock()

	return computeCookie(srcIP, srcPort, secret)
}

// VerifyCookie 验证 cookie（接受当前和前一个 time_slot）
func (cm *CookieManager) VerifyCookie(cookie [32]byte, srcIP []byte, srcPort uint16) bool {
	cm.maybeRotate()
	cm.mu.RLock()
	current := cm.currentSecret
	prev := cm.prevSecret
	cm.mu.RUnlock()

	expected := computeCookie(srcIP, srcPort, current)
	if hmac.Equal(cookie[:], expected[:]) {
		return true
	}

	// 尝试前一个 time_slot
	if prev != [32]byte{} {
		expected = computeCookie(srcIP, srcPort, prev)
		return hmac.Equal(cookie[:], expected[:])
	}
	return false
}

func (cm *CookieManager) maybeRotate() {
	cm.mu.RLock()
	needRotate := time.Since(cm.lastRotation) > cookieTimeSlot
	cm.mu.RUnlock()

	if needRotate {
		cm.mu.Lock()
		defer cm.mu.Unlock()
		// double check
		if time.Since(cm.lastRotation) > cookieTimeSlot {
			cm.rotateSecret()
		}
	}
}

func (cm *CookieManager) rotateSecret() {
	cm.prevSecret = cm.currentSecret
	rand.Read(cm.currentSecret[:])
	cm.lastRotation = time.Now()
}

func computeCookie(srcIP []byte, srcPort uint16, secret [32]byte) [32]byte {
	h := hmac.New(sha256.New, secret[:])
	h.Write(srcIP)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, srcPort)
	h.Write(portBuf)
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}
