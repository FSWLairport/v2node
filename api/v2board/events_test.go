package panel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestWatchEventsReconnectAndCancel(t *testing.T) {
	var connections atomic.Int32
	upgrader := websocket.Upgrader{}
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/server/UniProxy/events" || r.URL.Query().Get("node_id") != "42" || r.URL.Query().Has("token") || r.Header.Get("Authorization") != "Bearer node-secret" {
			t.Errorf("unexpected event handshake: path=%s query=%s", r.URL.Path, r.URL.RawQuery)
			http.Error(w, "bad handshake", http.StatusUnauthorized)
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		n := connections.Add(1)
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"ignored"}`))
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"refresh"}`))
		if n == 1 {
			return
		}
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer host.Close()
	client := newPanelTestClient(t, host.URL)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wake := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() { defer close(done); client.WatchEvents(ctx, wake) }()
	for i := 0; i < 2; i++ {
		select {
		case <-wake:
		case <-time.After(5 * time.Second):
			t.Fatal("refresh notification missing")
		}
	}
	if connections.Load() < 2 {
		t.Fatal("no reconnect")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancel did not close socket")
	}
}

func TestWatchEventsUnsupportedPanel(t *testing.T) {
	var attempts atomic.Int32
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		http.NotFound(w, r)
	}))
	defer host.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	newPanelTestClient(t, host.URL).WatchEvents(ctx, make(chan struct{}, 1))
	if attempts.Load() != 1 || ctx.Err() != nil {
		t.Fatal("unsupported panel did not disable event attempts")
	}
}
