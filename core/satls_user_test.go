package core

import (
	"testing"

	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/common/format"
	"github.com/wyx2685/v2node/proxy/satls"
	"github.com/xtls/xray-core/app/proxyman"
)

func TestBuildSATLSUserUsesCredentialUUIDAsPasswordPath(t *testing.T) {
	const (
		tag      = "[dashboard.example]-satls:42"
		password = "0198f31d-5228-75f1-bceb-5ee9848f7fd7"
	)

	wireUser := buildSATLSUser(tag, &panel.UserInfo{Id: 73, Uuid: password})
	if wireUser.Email != format.UserTag(tag, password) {
		t.Fatalf("email = %q, want %q", wireUser.Email, format.UserTag(tag, password))
	}
	memoryUser, err := wireUser.ToMemoryUser()
	if err != nil {
		t.Fatalf("ToMemoryUser: %v", err)
	}
	account, ok := memoryUser.Account.(*satls.MemoryAccount)
	if !ok {
		t.Fatalf("account type = %T, want *satls.MemoryAccount", memoryUser.Account)
	}
	// The Dashboard emits the connection credential UUID as sing-box's
	// `password`. SATLS carries that password as the HTTP request path, so the
	// server-side path token must be byte-for-byte identical for canonical UUIDs.
	if account.Path != password {
		t.Fatalf("SATLS path = %q, want credential password %q", account.Path, password)
	}
}

func TestBuildSATLSUserNormalizesPasswordPath(t *testing.T) {
	wireUser := buildSATLSUser("satls-test", &panel.UserInfo{Id: 73, Uuid: " /CrEd-EnTiAl/ "})
	memoryUser, err := wireUser.ToMemoryUser()
	if err != nil {
		t.Fatalf("ToMemoryUser: %v", err)
	}
	account, ok := memoryUser.Account.(*satls.MemoryAccount)
	if !ok {
		t.Fatalf("account type = %T, want *satls.MemoryAccount", memoryUser.Account)
	}
	if account.Path != "cred-ential" {
		t.Fatalf("normalized SATLS path = %q, want cred-ential", account.Path)
	}
}

func TestBuildSATLSInboundUsesOneTLSLayerAndServerSNI(t *testing.T) {
	nodeInfo := &panel.NodeInfo{
		Id:       42,
		Type:     "satls",
		Security: panel.Tls,
		Common: &panel.CommonNode{
			Protocol:    "satls",
			ListenIP:    "127.0.0.1",
			ServerPort:  443,
			TlsSettings: panel.TlsSettings{ServerName: "tls.edge.example"},
			CertInfo: &panel.CertInfo{
				CertMode:         "file",
				CertFile:         "/run/secrets/satls.crt",
				KeyFile:          "/run/secrets/satls.key",
				RejectUnknownSni: true,
			},
			// AllowInsecure is a client-side certificate verification setting.
			// A legacy panel may still send it, but it must never weaken the
			// server-side SNI policy derived from tls_settings.
			SatlsSettings: &panel.SatlsSettings{
				AllowInsecure: true,
				Host:          "cover.edge.example",
				Mode:          "full",
			},
		},
	}

	built, err := buildInbound(nodeInfo, "satls-security-test")
	if err != nil {
		t.Fatalf("buildInbound: %v", err)
	}
	receiverInstance, err := built.ReceiverSettings.GetInstance()
	if err != nil {
		t.Fatalf("decode ReceiverConfig: %v", err)
	}
	receiver, ok := receiverInstance.(*proxyman.ReceiverConfig)
	if !ok {
		t.Fatalf("receiver settings type = %T, want *proxyman.ReceiverConfig", receiverInstance)
	}
	if receiver.StreamSettings == nil {
		t.Fatal("SATLS receiver is missing TCP stream settings")
	}
	if receiver.StreamSettings.SecurityType != "" || len(receiver.StreamSettings.SecuritySettings) != 0 {
		t.Fatalf("SATLS receiver has an outer TLS layer: %+v", receiver.StreamSettings)
	}
	instance, err := built.ProxySettings.GetInstance()
	if err != nil {
		t.Fatalf("decode SATLS ServerConfig: %v", err)
	}
	config, ok := instance.(*satls.ServerConfig)
	if !ok {
		t.Fatalf("proxy settings type = %T, want *satls.ServerConfig", instance)
	}
	if !config.RejectUnknownSni {
		t.Fatal("client allow_insecure disabled server RejectUnknownSni")
	}
	if config.ServerName != nodeInfo.Common.TlsSettings.ServerName {
		t.Fatalf("SATLS SNI allowlist = %q, want TLS server name %q (HTTP host is %q)", config.ServerName, nodeInfo.Common.TlsSettings.ServerName, nodeInfo.Common.SatlsSettings.Host)
	}
	if config.CertFile != nodeInfo.Common.CertInfo.CertFile || config.KeyFile != nodeInfo.Common.CertInfo.KeyFile {
		t.Fatalf("SATLS inner TLS lost certificate paths: %+v", config)
	}
	if config.CertMode != nodeInfo.Common.CertInfo.CertMode {
		t.Fatalf("SATLS certificate mode = %q, want %q", config.CertMode, nodeInfo.Common.CertInfo.CertMode)
	}
}

// Older panels only send satls_settings.host. Dropping that fallback would
// leave the server name empty, which disables SNI validation entirely and
// makes self-signed certificate generation fail at startup.
func TestBuildSATLSInboundFallsBackToSatlsHost(t *testing.T) {
	nodeInfo := &panel.NodeInfo{
		Id:       43,
		Type:     "satls",
		Security: panel.Tls,
		Common: &panel.CommonNode{
			Protocol:   "satls",
			ListenIP:   "127.0.0.1",
			ServerPort: 443,
			CertInfo: &panel.CertInfo{
				CertMode:         "file",
				CertFile:         "/run/secrets/satls.crt",
				KeyFile:          "/run/secrets/satls.key",
				RejectUnknownSni: true,
			},
			SatlsSettings: &panel.SatlsSettings{
				Host: "legacy.edge.example",
				Mode: "full",
				Split: &panel.SatlsSplit{
					Up:   &panel.SatlsSplitHalf{Host: "up.edge.example"},
					Down: &panel.SatlsSplitHalf{TLS: panel.SatlsTLS{ServerName: "down.edge.example"}},
				},
			},
		},
	}

	built, err := buildInbound(nodeInfo, "satls-legacy-test")
	if err != nil {
		t.Fatalf("buildInbound: %v", err)
	}
	instance, err := built.ProxySettings.GetInstance()
	if err != nil {
		t.Fatalf("decode SATLS ServerConfig: %v", err)
	}
	config, ok := instance.(*satls.ServerConfig)
	if !ok {
		t.Fatalf("proxy settings type = %T, want *satls.ServerConfig", instance)
	}
	if config.ServerName != "legacy.edge.example" {
		t.Fatalf("SATLS server name = %q, want the satls host fallback", config.ServerName)
	}
	if config.UpServerName != "up.edge.example" {
		t.Fatalf("SATLS up server name = %q, want the up host fallback", config.UpServerName)
	}
	if config.DownServerName != "down.edge.example" {
		t.Fatalf("SATLS down server name = %q", config.DownServerName)
	}
}
