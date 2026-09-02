package accesslog

import (
	"testing"
	"time"
)

func TestCollectionIsPerInboundTagAndOffByDefault(t *testing.T) {
	t.Cleanup(func() { Disable("node-a"); Disable("node-b") })
	if Enabled("node-a") {
		t.Fatal("a tag collects before it is enabled")
	}
	// Push on a disabled tag still buffers nothing worth keeping, but the
	// dispatcher never calls it without checking, so the guarantee that matters
	// is that a disabled tag is cheap and separate.
	Enable("node-a")
	if !Enabled("node-a") || Enabled("node-b") {
		t.Fatal("enabling one tag affected another")
	}
	Push("node-a", Record{Domain: "a.example.test", At: time.Now()})
	Push("node-b", Record{Domain: "b.example.test", At: time.Now()})
	if drained := Drain("node-a"); len(drained) != 1 || drained[0].Domain != "a.example.test" {
		t.Fatalf("node-a drained=%#v", drained)
	}
	if again := Drain("node-a"); len(again) != 0 {
		t.Fatalf("draining twice returned records: %#v", again)
	}
	// Disabling drops what the tag buffered: a node going away has no reader.
	Disable("node-b")
	if drained := Drain("node-b"); len(drained) != 0 {
		t.Fatalf("node-b kept records after Disable: %#v", drained)
	}
}

func TestPushDropsRatherThanGrowingUnbounded(t *testing.T) {
	t.Cleanup(func() { Disable("flood") })
	Enable("flood")
	for range pendingPerTag + 100 {
		Push("flood", Record{Domain: "x.example.test", At: time.Now()})
	}
	if drained := Drain("flood"); len(drained) != pendingPerTag {
		t.Fatalf("buffered %d, want the %d cap", len(drained), pendingPerTag)
	}
}
