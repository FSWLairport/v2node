package consumertraffic

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	panel "github.com/wyx2685/v2node/api/v2board"
)

func TestSpoolKeepsFrozenBatchesAcrossRestartUntilAck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.json")
	spool, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	batch := panel.ConsumerTrafficBatch{ID: uuid.NewString(), ObservedAt: time.Now().UTC(), Samples: []panel.ConsumerTrafficSample{{LeaseID: uuid.NewString(), Upload: 7}}}
	if err = spool.Add([]panel.ConsumerTrafficBatch{batch}); err != nil {
		t.Fatal(err)
	}
	batch.Samples[0].Upload = 999
	restarted, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	first, ok := restarted.First()
	if !ok || first.ID != batch.ID || first.Samples[0].Upload != 7 || restarted.CanRenew() {
		t.Fatalf("pending batch was changed: %+v", first)
	}
	first.Samples[0].Upload = 1
	again, _ := restarted.First()
	if again.Samples[0].Upload != 7 {
		t.Fatal("caller changed persisted retry")
	}
	if err = restarted.Ack(batch.ID); err != nil {
		t.Fatal(err)
	}
	if !restarted.CanRenew() {
		t.Fatal("acknowledged spool did not become healthy")
	}
	final, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok = final.First(); ok {
		t.Fatal("acknowledged batch reappeared")
	}
	stat, err := os.Stat(path)
	if err != nil || stat.Mode().Perm() != 0600 {
		t.Fatalf("spool mode: %v %v", stat, err)
	}
}
func TestCorruptSpoolIsNotSilentlyDiscarded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.json")
	if err := os.WriteFile(path, []byte("{broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("corrupt accounting state accepted")
	}
	raw, _ := os.ReadFile(path)
	if string(raw) != "{broken" {
		t.Fatal("pending accounting state overwritten")
	}
}
