// Package grantlimit enforces node-local, shared access-grant budgets.
package grantlimit

import (
	"sync"
	"time"

	"github.com/juju/ratelimit"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

type Limit struct {
	ID       int64 `json:"id" msgpack:"id"`
	UpMbps   int   `json:"up_mbps" msgpack:"up_mbps"`
	DownMbps int   `json:"down_mbps" msgpack:"down_mbps"`
}
type budget struct {
	limit    Limit
	up, down *ratelimit.Bucket
}

var mu sync.Mutex
var scopes = map[string]map[int64]*budget{}
var bindings = map[string][]*budget{}
var scopeKeys = map[string][]string{}

// Configure preserves unchanged buckets across user-list refreshes.
func Configure(scope string, users map[string][]Limit) {
	mu.Lock()
	defer mu.Unlock()
	previous := scopes[scope]
	next := map[int64]*budget{}
	for _, key := range scopeKeys[scope] {
		delete(bindings, key)
	}
	keys := make([]string, 0, len(users))
	for key, limits := range users {
		keys = append(keys, key)
		for _, limit := range limits {
			state := next[limit.ID]
			if state == nil {
				state = previous[limit.ID]
				if state == nil || state.limit != limit {
					state = &budget{limit: limit, up: newBucket(limit.UpMbps), down: newBucket(limit.DownMbps)}
				}
				next[limit.ID] = state
			}
			bindings[key] = append(bindings[key], state)
		}
	}
	scopes[scope], scopeKeys[scope] = next, keys
}
func newBucket(mbps int) *ratelimit.Bucket {
	if mbps <= 0 {
		return nil
	}
	bytes := int64(mbps) * 1000000 / 8
	return ratelimit.NewBucketWithRate(float64(bytes), bytes)
}
func buckets(key string, upload bool) []*ratelimit.Bucket {
	mu.Lock()
	defer mu.Unlock()
	var out []*ratelimit.Bucket
	for _, state := range bindings[key] {
		b := state.down
		if upload {
			b = state.up
		}
		if b != nil {
			out = append(out, b)
		}
	}
	return out
}
func wait(key string, upload bool, size int32) {
	for _, b := range buckets(key, upload) {
		b.Wait(int64(size))
	}
}
func AllowPacket(key string, upload bool, size int) bool {
	mu.Lock()
	defer mu.Unlock()
	var selected []*ratelimit.Bucket
	for _, state := range bindings[key] {
		b := state.down
		if upload {
			b = state.up
		}
		if b != nil {
			if b.Available() < int64(size) {
				return false
			}
			selected = append(selected, b)
		}
	}
	for _, b := range selected {
		b.TakeAvailable(int64(size))
	}
	return true
}

type writer struct {
	writer buf.Writer
	key    string
	upload bool
}

func NewWriter(w buf.Writer, key string, upload bool) buf.Writer { return &writer{w, key, upload} }
func (w *writer) Close() error                                   { return common.Close(w.writer) }
func (w *writer) WriteMultiBuffer(mb buf.MultiBuffer) error {
	wait(w.key, w.upload, mb.Len())
	return w.writer.WriteMultiBuffer(mb)
}

type reader struct {
	buf.TimeoutReader
	key string
}

func NewReader(r buf.Reader, key string) buf.TimeoutReader {
	return &reader{&buf.TimeoutWrapperReader{Reader: r}, key}
}
func (r *reader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.TimeoutReader.ReadMultiBuffer()
	wait(r.key, true, mb.Len())
	return mb, err
}
func (r *reader) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	mb, err := r.TimeoutReader.ReadMultiBufferTimeout(timeout)
	wait(r.key, true, mb.Len())
	return mb, err
}
