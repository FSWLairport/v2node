package panel

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func captureReport(t *testing.T, path string, status int, report func(*Client) error) map[string]any {
	t.Helper()
	var body map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			t.Errorf("path = %q, want %q", r.URL.Path, path)
		}
		// Auth rides on the query parameters the client sets once, so a report
		// that lost them would be silently unauthenticated.
		if got := r.URL.Query().Get("node_id"); got != "42" {
			t.Errorf("node_id = %q, want 42", got)
		}
		if got := r.URL.Query().Get("token"); got != "node-secret" {
			t.Errorf("token = %q, want node-secret", got)
		}
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("decode body: %v (%s)", err, raw)
		}
		w.WriteHeader(status)
	}))
	defer server.Close()
	if err := report(newPanelTestClient(t, server.URL)); err != nil {
		t.Fatalf("report: %v", err)
	}
	return body
}

func TestReportDGLeasesSendsSnapshotsIncludingEmptyOnes(t *testing.T) {
	body := captureReport(t, "/api/v1/server/UniProxy/leases", http.StatusOK, func(c *Client) error {
		return c.ReportDGLeases(context.Background(), []DGLease{
			{UID: 7, DeviceID: "00112233445566778899aabbccddeeff", IP: "10.8.0.2", LastSeenAt: "2026-09-01T10:00:00Z"},
		})
	})
	leases, ok := body["leases"].([]any)
	if !ok || len(leases) != 1 {
		t.Fatalf("body=%#v", body)
	}
	lease := leases[0].(map[string]any)
	if lease["uid"] != float64(7) || lease["ip"] != "10.8.0.2" {
		t.Fatalf("lease=%#v", lease)
	}

	// An empty snapshot is the only way to say "this node leases nothing", so
	// it must still be sent rather than skipped as an empty report.
	empty := captureReport(t, "/api/v1/server/UniProxy/leases", http.StatusOK, func(c *Client) error {
		return c.ReportDGLeases(context.Background(), nil)
	})
	if leases, ok = empty["leases"].([]any); !ok || len(leases) != 0 {
		t.Fatalf("empty snapshot body=%#v", empty)
	}
}

func TestReportAccessLogsCarriesTheRecordShape(t *testing.T) {
	body := captureReport(t, "/api/v1/server/UniProxy/logs", http.StatusOK, func(c *Client) error {
		return c.ReportAccessLogs(context.Background(), []AccessLogEntry{
			{UID: 7, Ts: "2026-09-01T10:00:00Z", Protocol: "satls", IPProto: 6, SrcIP: "198.51.100.4", SrcPort: 40001, DstPort: 443, Domain: "www.example.test"},
		})
	})
	logs, ok := body["logs"].([]any)
	if !ok || len(logs) != 1 {
		t.Fatalf("body=%#v", body)
	}
	entry := logs[0].(map[string]any)
	if entry["protocol"] != "satls" || entry["domain"] != "www.example.test" || entry["dst_port"] != float64(443) {
		t.Fatalf("entry=%#v", entry)
	}
	// A SATLS record has no device id and a domain-only destination has no
	// address; both must be omitted rather than sent empty.
	if _, present := entry["device_id"]; present {
		t.Fatalf("device_id leaked into a SATLS record: %#v", entry)
	}
	if _, present := entry["dst_ip"]; present {
		t.Fatalf("empty dst_ip was sent: %#v", entry)
	}
}

// A panel without these routes answers 404. That must not surface as an error
// and stall the push task, and it must not keep the node posting at a panel
// that will never accept it — a DynamicGuard node sends a lease snapshot on
// every tick, so an unlatched 404 is a request per minute forever.
func TestAdditiveReportsStopAfterAPanelRefusesTheRoute(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	client := newPanelTestClient(t, server.URL)

	for range 3 {
		if err := client.ReportDGLeases(context.Background(), nil); err != nil {
			t.Fatalf("a 404 surfaced as an error: %v", err)
		}
		if err := client.ReportAccessLogs(context.Background(), []AccessLogEntry{{UID: 7, Ts: "2026-09-01T10:00:00Z", Protocol: "dg", DstIP: "1.1.1.1"}}); err != nil {
			t.Fatalf("a 404 surfaced as an error: %v", err)
		}
	}
	// One attempt per endpoint, then silence.
	if requests != 2 {
		t.Fatalf("sent %d requests to a panel without the routes, want 2", requests)
	}
}

// The five endpoints every v2board-style panel implements must keep working
// untouched, and a panel that refuses the additive ones must not affect them.
func TestLatchDoesNotAffectTheFrozenReports(t *testing.T) {
	pushes := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/server/UniProxy/push", "/api/v1/server/UniProxy/alive":
			pushes++
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client := newPanelTestClient(t, server.URL)

	for range 2 {
		_ = client.ReportDGLeases(context.Background(), nil)
		if err := client.ReportUserTraffic(context.Background(), []UserTraffic{{UID: 7, Upload: 1, Download: 2}}); err != nil {
			t.Fatalf("traffic report: %v", err)
		}
		online := map[int][]string{7: {"198.51.100.4"}}
		if err := client.ReportNodeOnlineUsers(context.Background(), &online); err != nil {
			t.Fatalf("alive report: %v", err)
		}
	}
	if pushes != 4 {
		t.Fatalf("frozen reports sent %d times, want 4", pushes)
	}
}
