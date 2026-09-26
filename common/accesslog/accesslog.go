// Package accesslog collects one record per connection for the panel's access
// log. It is a registry keyed by inbound tag, the same shape the limiter uses,
// because the dispatcher is shared by every node in the process while the
// panel's switch is per node.
//
// The global log.Handler is not usable for this: xray installs exactly one, so
// hooking it would replace the operator's own access log rather than add to it.
package accesslog

import (
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

// pendingPerTag bounds what one tag may accumulate between report ticks. A
// record is one connection, not one packet, so this is generous for a push
// interval; overflow is counted rather than grown.
const pendingPerTag = 16384

const dropLogPeriod = 30 * time.Second

// Record is one connection an inbound carried. Email is the user tag the
// inbound authenticated ("tag|uuid"); the caller resolves it to a credential id
// when it drains, because only the core owns that mapping.
type Record struct {
	Email   string
	At      time.Time
	IPProto int
	SrcIP   string
	SrcPort int
	DstIP   string
	DstPort int
	Domain  string
}

var (
	mu      sync.Mutex
	pending = map[string][]Record{}
	// enabled is read once per connection on the dispatch path, so it stays a
	// sync.Map rather than something the mutex guards.
	enabled sync.Map // tag -> struct{}
	dropped atomic.Uint64
	lastLog atomic.Int64
)

// Enable starts collecting for one inbound tag.
func Enable(tag string) {
	if tag == "" {
		return
	}
	enabled.Store(tag, struct{}{})
}

// Disable stops collecting and discards what that tag had buffered. A node that
// is going away has no reader left for it.
func Disable(tag string) {
	enabled.Delete(tag)
	mu.Lock()
	delete(pending, tag)
	mu.Unlock()
}

// Enabled reports whether this inbound collects. It is the whole cost of the
// feature on a node that leaves it off.
func Enabled(tag string) bool {
	if tag == "" {
		return false
	}
	_, ok := enabled.Load(tag)
	return ok
}

// Push buffers one record. It drops rather than blocks: telemetry must not
// throttle the connection it describes.
func Push(tag string, record Record) {
	mu.Lock()
	held := pending[tag]
	if len(held) >= pendingPerTag {
		mu.Unlock()
		noteDropped()
		return
	}
	pending[tag] = append(held, record)
	mu.Unlock()
}

// Drain hands over what one tag accumulated.
func Drain(tag string) []Record {
	mu.Lock()
	defer mu.Unlock()
	held := pending[tag]
	delete(pending, tag)
	return held
}

func noteDropped() {
	total := dropped.Add(1)
	now := time.Now().UnixNano()
	last := lastLog.Load()
	if now-last < int64(dropLogPeriod) {
		return
	}
	if !lastLog.CompareAndSwap(last, now) {
		return
	}
	log.WithField("dropped_total", total).Info("access log records dropped")
}
