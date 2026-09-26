package panel

import (
	"testing"

	"github.com/wyx2685/v2node/conf"
)

// newPanelTestClient builds a Client pointed at a test server, with retries off
// so a failing request surfaces immediately instead of after a backoff.
func newPanelTestClient(t *testing.T, apiHost string) *Client {
	t.Helper()
	retryCount := 0
	client, err := New(&conf.NodeConfig{
		APIHost: apiHost, NodeID: 42, Key: "node-secret", Timeout: 2, RetryCount: &retryCount,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}
