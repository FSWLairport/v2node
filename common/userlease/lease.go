package userlease

import (
	"sync"
	"time"
)

type entry struct {
	deadline time.Time
	timer    *time.Timer
	close    func()
}

var leases sync.Map
var updates sync.Mutex

// Unmanaged enterprise/box users keep their existing authorization behavior.
func Allowed(key string) bool {
	value, ok := leases.Load(key)
	return !ok || time.Now().Before(value.(*entry).deadline)
}
func Managed(key string) bool { _, ok := leases.Load(key); return ok }
func Set(key string, deadline time.Time, closeConnections func()) {
	updates.Lock()
	defer updates.Unlock()
	next := &entry{deadline: deadline, close: closeConnections}
	if old, ok := leases.Swap(key, next); ok && old.(*entry).timer != nil {
		old.(*entry).timer.Stop()
	}
	next.timer = time.AfterFunc(max(time.Until(deadline), 0), func() {
		updates.Lock()
		current, ok := leases.Load(key)
		valid := ok && current == next
		updates.Unlock()
		if valid && closeConnections != nil {
			closeConnections()
		}
	})
}
func Revoke(key string) {
	if old, ok := leases.Load(key); ok {
		Set(key, time.Now(), old.(*entry).close)
	}
}
