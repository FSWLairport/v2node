package panel

import (
	"context"
	"encoding/json"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

// WatchEvents only wakes the existing serial refresh task; polling remains the fallback.
func (c *Client) WatchEvents(ctx context.Context, wake chan<- struct{}) {
	u, err := url.Parse(c.APIHost)
	if err != nil {
		return
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/api/v1/server/UniProxy/events"
	u.RawPath = ""
	u.RawQuery = url.Values{"node_id": {strconv.Itoa(c.NodeId)}}.Encode()
	u.Fragment = ""
	dialer := *websocket.DefaultDialer
	dialer.HandshakeTimeout = 15 * time.Second
	if transport, ok := c.client.GetClient().Transport.(*http.Transport); ok {
		dialer.TLSClientConfig = transport.TLSClientConfig
	}
	header := http.Header{"Authorization": {"Bearer " + c.Token}}
	backoff := time.Second
	for ctx.Err() == nil {
		conn, response, dialErr := dialer.DialContext(ctx, u.String(), header)
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		if dialErr == nil {
			backoff = time.Second
			log.WithField("node", c.NodeId).Info("Panel event connection established")
			c.readEvents(ctx, conn, wake)
			_ = conn.Close()
		} else if response != nil && response.StatusCode == http.StatusNotFound {
			return
		}
		if ctx.Err() != nil {
			return
		}
		log.WithField("node", c.NodeId).Debug("Panel event connection lost; polling continues")
		timer := time.NewTimer(backoff + time.Duration(rand.Int64N(int64(backoff/2))))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		backoff = min(30*time.Second, backoff*2)
	}
}

func (c *Client) readEvents(ctx context.Context, conn *websocket.Conn, wake chan<- struct{}) {
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	conn.SetReadLimit(1024)
	_ = conn.SetReadDeadline(time.Now().Add(75 * time.Second))
	conn.SetPingHandler(func(data string) error {
		if err := conn.SetReadDeadline(time.Now().Add(75 * time.Second)); err != nil {
			return err
		}
		return conn.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(5*time.Second))
	})
	for ctx.Err() == nil {
		_, payload, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var event struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(payload, &event) != nil || event.Type != "refresh" {
			continue
		}
		select {
		case wake <- struct{}{}:
		default:
		}
	}
}
