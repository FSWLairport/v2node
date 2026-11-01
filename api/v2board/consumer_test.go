package panel

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func leasedTestUser() UserInfo {
	return UserInfo{Id: 3, Uuid: uuid.NewString(), ConsumerAccountID: 4, ConsumerLeaseID: uuid.NewString(), EntitlementGeneration: 1, LeaseSeconds: 45, DGDeviceID: strings.Repeat("a", 32), WGStaticPub: base64.StdEncoding.EncodeToString(make([]byte, 32))}
}
func TestConsumerLeaseUsesRequestStartAndRejectsMissingPins(t *testing.T) {
	user := leasedTestUser()
	start := time.Now().Add(-5 * time.Second)
	if err := user.validateLease(start); err != nil {
		t.Fatal(err)
	}
	if !user.LeaseDeadline.Equal(start.Add(45 * time.Second)) {
		t.Fatal("network time extended authorization")
	}
	user.LeaseSeconds = 46
	if err := user.validateLease(start); err == nil {
		t.Fatal("unbounded lease accepted")
	}
	user = leasedTestUser()
	user.WGStaticPub = ""
	if err := user.validateLease(start); err == nil {
		t.Fatal("unpinned C device accepted")
	}
	user = leasedTestUser()
	user.LeaseSeconds = 1
	if err := user.validateLease(time.Now().Add(-2 * time.Second)); err == nil {
		t.Fatal("already expired response accepted")
	}
}
func TestUserPullAdvertisesConsumerProtocolAndPreservesLeaseMetadata(t *testing.T) {
	user := leasedTestUser()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Saikyo-Consumer-Leases") != "1" {
			t.Error("missing protocol acknowledgement")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(UserListBody{Users: []UserInfo{user}})
	}))
	defer server.Close()
	client := newPanelTestClient(t, server.URL)
	users, err := client.GetUserList(context.Background())
	if err != nil || len(users) != 1 {
		t.Fatalf("lease decode: %+v %v", users, err)
	}
	if users[0].ConsumerLeaseID != user.ConsumerLeaseID || users[0].LeaseDeadline.IsZero() {
		t.Fatal("lease metadata discarded")
	}
}
func TestConsumerTrafficRetryKeepsPayloadAndRequiresActualAck(t *testing.T) {
	bodies := [][]byte{}
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		bodies = append(bodies, raw)
		calls++
		w.Header().Set("Content-Type", "application/json")
		if calls == 1 {
			w.WriteHeader(500)
			return
		}
		io.WriteString(w, `{"accepted":1,"duplicate":true}`)
	}))
	defer server.Close()
	client := newPanelTestClient(t, server.URL)
	batch := ConsumerTrafficBatch{ID: uuid.NewString(), ObservedAt: time.Now().UTC(), Samples: []ConsumerTrafficSample{{LeaseID: uuid.NewString(), Upload: 12}}}
	if err := client.ReportConsumerTraffic(context.Background(), batch); err == nil {
		t.Fatal("failed response acknowledged")
	}
	if err := client.ReportConsumerTraffic(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 2 || string(bodies[0]) != string(bodies[1]) {
		t.Fatal("retry changed accounting identity")
	}
}
