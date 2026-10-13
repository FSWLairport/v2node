package task

import (
	"context"
	"testing"
	"time"
)

func TestWakeCoalescesAndSerializes(t *testing.T) {
	wake := make(chan struct{}, 1)
	entered := make(chan struct{}, 3)
	release := make(chan struct{})
	task := &Task{Interval: time.Hour, Wake: wake, Execute: func(ctx context.Context) error {
		entered <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil
	}}
	if err := task.Start(false); err != nil {
		t.Fatal(err)
	}
	defer task.Close()
	wake <- struct{}{}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("wake ignored")
	}
	for i := 0; i < 100; i++ {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
	select {
	case <-entered:
		t.Fatal("refresh ran concurrently")
	default:
	}
	close(release)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("pending refresh lost")
	}
	select {
	case <-entered:
		t.Fatal("notifications did not coalesce")
	case <-time.After(50 * time.Millisecond):
	}
}
