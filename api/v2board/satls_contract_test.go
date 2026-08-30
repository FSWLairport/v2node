package panel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGetNodeInfoParsesDashboardSATLSCommonNode(t *testing.T) {
	tests := []struct {
		name          string
		body          string
		wantHost      string
		wantMode      string
		wantRejectSNI bool
		wantUpHost    string
		wantUpSNI     string
		wantDownHost  string
		wantDownSNI   string
	}{
		{
			name: "full",
			body: `{
				"protocol":"satls",
				"listen_ip":"0.0.0.0",
				"server_port":443,
				"routes":[],
				"base_config":{"push_interval":60,"pull_interval":"15","device_online_min_traffic":100,"node_report_min_traffic":100},
				"tls":1,
				"tls_settings":{"server_name":"full-tls.edge.example","cert_mode":"file","cert_file":"/run/secrets/full.crt","key_file":"/run/secrets/full.key","reject_unknown_sni":"1"},
				"satls_settings":{"host":"full-cover.edge.example","mode":"full"}
			}`,
			wantHost:      "full-cover.edge.example",
			wantMode:      "full",
			wantRejectSNI: true,
		},
		{
			name: "split",
			body: `{
				"protocol":"satls",
				"listen_ip":"127.0.0.1",
				"server_port":8443,
				"routes":[],
				"base_config":{"push_interval":30,"pull_interval":10,"device_online_min_traffic":100,"node_report_min_traffic":100},
				"tls":1,
				"tls_settings":{"server_name":"split-tls.edge.example","cert_mode":"self","cert_file":"/etc/v2node/split.crt","key_file":"/etc/v2node/split.key","reject_unknown_sni":"1"},
				"satls_settings":{"host":"split-cover.edge.example","mode":"split","split":{"up":{"host":"up-cover.edge.example","tls":{"server_name":"up-tls.edge.example"}},"down":{"host":"down-cover.edge.example","tls":{"server_name":"down-tls.edge.example"}}}}
			}`,
			wantHost:      "split-cover.edge.example",
			wantMode:      "split",
			wantRejectSNI: true,
			wantUpHost:    "up-cover.edge.example",
			wantUpSNI:     "up-tls.edge.example",
			wantDownHost:  "down-cover.edge.example",
			wantDownSNI:   "down-tls.edge.example",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v2/server/config" {
					t.Errorf("path = %q, want /api/v2/server/config", r.URL.Path)
				}
				if got := r.URL.Query().Get("node_type"); got != "v2node" {
					t.Errorf("node_type = %q, want v2node", got)
				}
				if got := r.URL.Query().Get("node_id"); got != "42" {
					t.Errorf("node_id = %q, want 42", got)
				}
				if got := r.Header.Get("X-Node-Version"); got == "" {
					t.Error("X-Node-Version header was not sent")
				}
				if got := r.URL.Query().Get("token"); got != "node-secret" {
					t.Errorf("token = %q, want node-secret", got)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			client := newPanelTestClient(t, server.URL)
			node, err := client.GetNodeInfo(context.Background())
			if err != nil {
				t.Fatalf("GetNodeInfo: %v", err)
			}
			if node.Type != "satls" || node.Security != Tls {
				t.Fatalf("protocol/security = %q/%d, want satls/%d", node.Type, node.Security, Tls)
			}
			if node.PushInterval <= 0 || node.PullInterval <= 0 {
				t.Fatalf("invalid intervals push=%s pull=%s", node.PushInterval, node.PullInterval)
			}
			if tt.name == "full" && (node.PushInterval != time.Minute || node.PullInterval != 15*time.Second) {
				t.Fatalf("full intervals push=%s pull=%s", node.PushInterval, node.PullInterval)
			}
			if node.Common == nil || node.Common.Protocol != "satls" || node.Common.Tls != 1 {
				t.Fatalf("unexpected CommonNode: %+v", node.Common)
			}
			if node.Common.TlsSettings.ServerName == "" || node.Common.CertInfo == nil {
				t.Fatalf("TLS settings were not projected: %+v", node.Common)
			}
			if node.Common.CertInfo.CertFile != node.Common.TlsSettings.CertFile ||
				node.Common.CertInfo.KeyFile != node.Common.TlsSettings.KeyFile ||
				node.Common.CertInfo.CertDomain != node.Common.TlsSettings.ServerName ||
				node.Common.CertInfo.RejectUnknownSni != tt.wantRejectSNI {
				t.Fatalf("unexpected CertInfo: %+v", node.Common.CertInfo)
			}
			settings := node.Common.SatlsSettings
			if settings == nil || settings.Host != tt.wantHost || settings.Mode != tt.wantMode {
				t.Fatalf("unexpected satls_settings: %+v", settings)
			}
			if settings.AllowInsecure != nil {
				t.Fatalf("dashboard server wire unexpectedly includes client allow_insecure: %#v", settings.AllowInsecure)
			}
			if tt.wantMode == "full" {
				if settings.Split != nil {
					t.Fatalf("full mode unexpectedly has split settings: %+v", settings.Split)
				}
			} else {
				if settings.Split == nil || settings.Split.Up == nil || settings.Split.Down == nil {
					t.Fatalf("split settings missing: %+v", settings.Split)
				}
				if settings.Split.Up.Host != tt.wantUpHost || settings.Split.Up.TLS.ServerName != tt.wantUpSNI ||
					settings.Split.Down.Host != tt.wantDownHost || settings.Split.Down.TLS.ServerName != tt.wantDownSNI {
					t.Fatalf("unexpected split settings: %+v", settings.Split)
				}
			}
			// A SATLS node has nothing the five legacy endpoints cannot carry, so
			// the dashboard advertises no extension namespace for it at all.
		})
	}
}
