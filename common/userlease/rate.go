package userlease

import (
	"sync"

	"github.com/wyx2685/v2node/common/rate"
)

type accountRate struct {
	mu     sync.Mutex
	mbps   int
	bucket *rate.DynamicBucket
}

var accounts sync.Map
var userRates sync.Map

// One account's devices share the node's upload/download bandwidth budget.
func ConfigureRate(key, account string, mbps int) {
	bytes := int64(mbps) * 1000000 / 8
	initial := &accountRate{mbps: -1}
	stored, _ := accounts.LoadOrStore(account, initial)
	state := stored.(*accountRate)
	state.mu.Lock()
	if state.mbps != mbps {
		state.mbps = mbps
		if state.bucket == nil && bytes > 0 {
			state.bucket = rate.NewDynamicBucket(bytes)
		} else if state.bucket != nil {
			if bytes <= 0 {
				bytes = 1 << 50
			}
			state.bucket.Update(bytes)
		}
	}
	state.mu.Unlock()
	userRates.Store(key, state)
}
func Bucket(key string) *rate.DynamicBucket {
	stored, ok := userRates.Load(key)
	if !ok {
		return nil
	}
	state := stored.(*accountRate)
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.mbps <= 0 {
		return nil
	}
	return state.bucket
}
func AllowPacket(key string, size int) bool {
	if !Allowed(key) {
		return false
	}
	stored, ok := userRates.Load(key)
	if !ok {
		return true
	}
	state := stored.(*accountRate)
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.mbps <= 0 {
		return true
	}
	bucket := state.bucket.Get()
	if bucket.Available() < int64(size) {
		return false
	}
	return bucket.TakeAvailable(int64(size)) == int64(size)
}
