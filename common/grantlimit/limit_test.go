package grantlimit

import (
	"github.com/xtls/xray-core/common/buf"
	"testing"
	"time"
)

func TestSharedDirectionalAndOverlappingBudgets(t *testing.T) {
	scope := t.Name()
	a, b := scope+"a", scope+"b"
	limit := Limit{ID: 1, UpMbps: 1, DownMbps: 2}
	users := map[string][]Limit{a: {limit}, b: {limit}}
	Configure(scope, users)
	defer Configure(scope, nil)
	bucket := buckets(a, true)[0]
	if bucket != buckets(b, true)[0] {
		t.Fatal("devices do not share grant")
	}
	if !AllowPacket(a, true, 125000) || AllowPacket(b, true, 100000) {
		t.Fatal("shared upload budget bypassed")
	}
	if !AllowPacket(b, false, 250000) {
		t.Fatal("directions not independent")
	}
	Configure(scope, users)
	if buckets(a, true)[0] != bucket || AllowPacket(a, true, 100000) {
		t.Fatal("refresh reset bucket")
	}
	users[a] = append(users[a], Limit{ID: 2, UpMbps: 3})
	Configure(scope, users)
	if len(buckets(a, true)) != 2 || len(buckets(b, true)) != 1 || AllowPacket(a, true, 100000) {
		t.Fatal("overlap bypassed or leaked")
	}
	users[a] = nil
	Configure(scope, users)
	if !AllowPacket(a, true, 1000000) || AllowPacket(b, true, 100000) {
		t.Fatal("clearing one binding changed another")
	}
	Configure(scope+"other", map[string][]Limit{scope + "other": {limit}})
	defer Configure(scope+"other", nil)
	if !AllowPacket(scope+"other", true, 125000) {
		t.Fatal("nodes share buckets")
	}
}

type discardWriter struct{}

func (discardWriter) WriteMultiBuffer(mb buf.MultiBuffer) error { buf.ReleaseMulti(mb); return nil }

func TestExistingStreamPicksUpNewGrantLimit(t *testing.T) {
	scope := t.Name()
	key := scope + "device"
	w := NewWriter(discardWriter{}, key, true)
	limit := Limit{ID: 1, UpMbps: 1}
	Configure(scope, map[string][]Limit{key: {limit}})
	defer Configure(scope, nil)
	if !AllowPacket(key, true, 125000) {
		t.Fatal("failed to drain initial burst")
	}
	var mb buf.MultiBuffer
	for range 8 {
		b := buf.New()
		b.Write(make([]byte, 2048))
		mb = append(mb, b)
	}
	started := time.Now()
	if err := w.WriteMultiBuffer(mb); err != nil {
		t.Fatal(err)
	}
	if time.Since(started) < 50*time.Millisecond {
		t.Fatal("existing writer bypassed newly installed limit")
	}
	Configure(scope, nil)
	if len(buckets(key, true)) != 0 {
		t.Fatal("cleared grant still bound to stream")
	}
}
