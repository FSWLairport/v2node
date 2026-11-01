package node

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/common/consumertraffic"
	"github.com/wyx2685/v2node/common/format"
	"github.com/wyx2685/v2node/common/userlease"
	"github.com/wyx2685/v2node/conf"
)

func consumerFixture(t *testing.T, path string) *Controller {
	t.Helper()
	return &Controller{conf: &conf.NodeConfig{ConsumerTrafficFile: path}, info: &panel.NodeInfo{Type: "dynamicguard"}, tag: t.Name(), billingUsers: map[int]panel.UserInfo{}, teardown: map[int]panel.UserInfo{}}
}
func consumerUser() panel.UserInfo {
	return panel.UserInfo{Id: 1, Uuid: uuid.NewString(), ConsumerAccountID: 7, ConsumerLeaseID: uuid.NewString(), EntitlementGeneration: 1, LeaseDeadline: time.Now().Add(45 * time.Second)}
}
func TestConsumerRestartWaitsForDurableBatchAck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.json")
	store, err := consumertraffic.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	batch := panel.ConsumerTrafficBatch{ID: uuid.NewString(), ObservedAt: time.Now().UTC(), Samples: []panel.ConsumerTrafficSample{{LeaseID: uuid.NewString(), Upload: 7}}}
	if err = store.Add([]panel.ConsumerTrafficBatch{batch}); err != nil {
		t.Fatal(err)
	}
	c := consumerFixture(t, path)
	u := consumerUser()
	b := panel.UserInfo{Id: 2, Uuid: uuid.NewString()}
	c.userList = []panel.UserInfo{u, b}
	c.initializeConsumers()
	if len(c.userList) != 1 || c.userList[0].Id != b.Id {
		t.Fatal("pending restart activated C or removed B")
	}
	calls := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var got panel.ConsumerTrafficBatch
		if json.NewDecoder(r.Body).Decode(&got) != nil || got.ID != batch.ID || got.Samples[0].Upload != 7 {
			t.Error("frozen traffic changed")
		}
		if calls == 1 {
			w.WriteHeader(503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"accepted":1}`))
	}))
	defer backend.Close()
	retries := 0
	c.apiClient, err = panel.New(&conf.NodeConfig{APIHost: backend.URL, NodeID: 1, Key: "synthetic", RetryCount: &retries})
	if err != nil {
		t.Fatal(err)
	}
	if err = c.flushConsumerTraffic(context.Background()); err == nil || c.consumerStore.CanRenew() {
		t.Fatal("failed ack permitted renewal")
	}
	if err = c.flushConsumerTraffic(context.Background()); err != nil || !c.consumerStore.CanRenew() {
		t.Fatalf("successful ack: %v", err)
	}
	if got := c.filterConsumerUsersLocked([]panel.UserInfo{u, b}, true); len(got) != 2 {
		t.Fatal("ack did not release renewal")
	}
	restarted, err := consumertraffic.Open(path)
	if err != nil || !restarted.CanRenew() {
		t.Fatalf("ack not persisted: %v", err)
	}
}
func TestConsumerFaultPreservesOldDeadlineAndKeepsB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.json")
	c := consumerFixture(t, path)
	u := consumerUser()
	b := panel.UserInfo{Id: 2}
	c.userList = []panel.UserInfo{u, b}
	c.initializeConsumers()
	next := u
	next.LeaseDeadline = next.LeaseDeadline.Add(time.Minute)
	got := c.filterConsumerUsersLocked([]panel.UserInfo{next, b}, false)
	if len(got) != 2 || !got[0].LeaseDeadline.Equal(u.LeaseDeadline) {
		t.Fatal("failed accounting extended old authorization")
	}
	next.ConsumerLeaseID = uuid.NewString()
	next.EntitlementGeneration++
	if got = c.filterConsumerUsersLocked([]panel.UserInfo{next, b}, false); len(got) != 1 || got[0].Id != 2 {
		t.Fatal("new generation served without accounting acknowledgement")
	}
	c.installConsumerLeasesLocked([]panel.UserInfo{u})
	if !userlease.Allowed(format.UserTag(c.tag, u.Uuid)) {
		t.Fatal("valid C was not installed")
	}
	badPath := filepath.Join(t.TempDir(), "broken.json")
	os.WriteFile(badPath, []byte("corrupt"), 0600)
	broken := consumerFixture(t, badPath)
	broken.userList = []panel.UserInfo{u, b}
	broken.initializeConsumers()
	if len(broken.userList) != 1 || broken.userList[0].Id != 2 {
		t.Fatal("corrupt spool enabled C or blocked B")
	}
	raw, _ := os.ReadFile(badPath)
	if string(raw) != "corrupt" {
		t.Fatal("corrupt accounting was overwritten")
	}
}
