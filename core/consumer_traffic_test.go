package core

import (
	"sync"
	"testing"
	"time"

	"github.com/wyx2685/v2node/common/counter"
	"github.com/wyx2685/v2node/common/userlease"
	"github.com/wyx2685/v2node/core/app/dispatcher"
)

func TestTrafficSwapsDoNotLoseConcurrentIncrements(t *testing.T) {
	const tag = "counter-test"
	const email = "counter-test|credential"
	storage := counter.NewTrafficCounter()
	sample := storage.GetCounter(email)
	core := &V2Core{users: &UserMap{uidMap: map[string]int{email: 7}}, dispatcher: &dispatcher.DefaultDispatcher{}}
	core.dispatcher.Counter.Store(tag, storage)
	var wg sync.WaitGroup
	wg.Add(1)
	done := make(chan struct{})
	go func() {
		defer wg.Done()
		for range 100000 {
			sample.UpCounter.Add(1)
		}
		close(done)
	}()
	total := int64(0)
	for {
		traffic, err := core.GetUserTrafficSlice(tag, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range traffic {
			total += entry.Upload
		}
		select {
		case <-done:
			goto finished
		default:
		}
	}
finished:
	wg.Wait()
	traffic, _ := core.GetUserTrafficSlice(tag, 0)
	for _, entry := range traffic {
		total += entry.Upload
	}
	if total != 100000 {
		t.Fatalf("lost counter increments: %d", total)
	}
}
func TestConsumerCollectorKeepsEnterpriseCountersUntilTheirReport(t *testing.T) {
	const tag = "consumer-counter-test"
	const managed = "consumer-counter-test|consumer"
	const legacy = "consumer-counter-test|enterprise"
	userlease.Set(managed, time.Now().Add(time.Minute), nil)
	storage := counter.NewTrafficCounter()
	storage.GetCounter(managed).UpCounter.Add(1)
	storage.GetCounter(legacy).UpCounter.Add(2)
	core := &V2Core{users: &UserMap{uidMap: map[string]int{managed: 7, legacy: 8}}, dispatcher: &dispatcher.DefaultDispatcher{}}
	core.dispatcher.Counter.Store(tag, storage)
	traffic, err := core.GetConsumerTrafficSlice(tag)
	if err != nil || len(traffic) != 1 || traffic[0].UID != 7 || traffic[0].Upload != 1 {
		t.Fatalf("C collector: %+v %v", traffic, err)
	}
	traffic, err = core.GetUserTrafficSlice(tag, 0)
	if err != nil || len(traffic) != 1 || traffic[0].UID != 8 || traffic[0].Upload != 2 {
		t.Fatalf("enterprise counters consumed early: %+v %v", traffic, err)
	}
}
