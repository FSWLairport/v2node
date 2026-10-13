package core

import (
	"github.com/wyx2685/v2node/common/counter"
	"github.com/wyx2685/v2node/core/app/dispatcher"
	"sync"
	"testing"
)

func TestTrafficDrainPreservesConcurrentBytes(t *testing.T) {
	vc := &V2Core{users: &UserMap{uidMap: map[string]int{"node|uuid": 1}}, dispatcher: &dispatcher.DefaultDispatcher{}}
	traffic := counter.NewTrafficCounter()
	vc.dispatcher.Counter.Store("node", traffic)
	storage := traffic.GetCounter("node|uuid")
	var wg sync.WaitGroup
	const writers = 8
	const increments = 10000
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < increments; j++ {
				storage.UpCounter.Add(1)
				storage.DownCounter.Add(1)
			}
		}()
	}
	total := int64(0)
	drain := func() {
		items, err := vc.GetUserTrafficSlice("node", 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range items {
			total += item.Upload + item.Download
		}
	}
	for i := 0; i < 1000; i++ {
		drain()
	}
	wg.Wait()
	drain()
	if total != 2*writers*increments {
		t.Fatalf("recorded %d bytes, want %d", total, 2*writers*increments)
	}
}
