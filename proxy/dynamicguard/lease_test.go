package dynamicguard

import (
	"sync"
	"testing"
	"time"
)

func TestLeaseManagerConcurrentStartAndCloseIsIdempotent(t *testing.T) {
	lm := NewLeaseManager(nil, nil, nil, time.Hour)
	start := make(chan struct{})
	var callers sync.WaitGroup
	callers.Add(3)

	go func() {
		defer callers.Done()
		<-start
		lm.Start()
	}()
	for range 2 {
		go func() {
			defer callers.Done()
			<-start
			lm.Close()
		}()
	}
	close(start)

	done := make(chan struct{})
	go func() {
		callers.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("concurrent Start/Close did not finish")
	}

	// Both operations remain safe and no-op after the manager is closed.
	lm.Close()
	lm.Start()
}
