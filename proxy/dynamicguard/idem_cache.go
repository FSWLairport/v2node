package dynamicguard

import (
	"sync"
	"time"
)

const idemCacheTTL = 60 * time.Second

type idemEntry struct {
	reply     []byte
	createdAt time.Time
}

// IdempotencyCache 幂等缓存 (SHA256 key → ServerReply 字节)
type IdempotencyCache struct {
	entries sync.Map
	stopCh  chan struct{}
}

// NewIdempotencyCache 创建幂等缓存并启动清理 goroutine
func NewIdempotencyCache() *IdempotencyCache {
	c := &IdempotencyCache{
		stopCh: make(chan struct{}),
	}
	go c.cleanupLoop()
	return c
}

// Get 查询缓存
func (c *IdempotencyCache) Get(key [32]byte) ([]byte, bool) {
	v, ok := c.entries.Load(key)
	if !ok {
		return nil, false
	}
	entry := v.(*idemEntry)
	if time.Since(entry.createdAt) > idemCacheTTL {
		c.entries.Delete(key)
		return nil, false
	}
	return entry.reply, true
}

// Set 写入缓存
func (c *IdempotencyCache) Set(key [32]byte, reply []byte) {
	c.entries.Store(key, &idemEntry{
		reply:     reply,
		createdAt: time.Now(),
	})
}

// Close 停止清理 goroutine
func (c *IdempotencyCache) Close() {
	close(c.stopCh)
}

func (c *IdempotencyCache) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			c.entries.Range(func(key, value any) bool {
				entry := value.(*idemEntry)
				if now.Sub(entry.createdAt) > idemCacheTTL {
					c.entries.Delete(key)
				}
				return true
			})
		case <-c.stopCh:
			return
		}
	}
}
