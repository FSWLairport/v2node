package satls

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	xrayCore "github.com/xtls/xray-core/core"
)

func TestSingleTLSHandshakeAcceptsDistinctHTTPHostAndGeneratesNamedCertificate(t *testing.T) {
	const (
		serverName = "tls.edge.example"
		upServer   = "up-tls.edge.example"
		downServer = "down-tls.edge.example"
		httpHost   = "cover.edge.example"
		password   = "0198f31d-5228-75f1-bceb-5ee9848f7fd7"
	)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "satls.crt")
	keyPath := filepath.Join(dir, "satls.key")
	upCertPath := filepath.Join(dir, "satls-up.crt")
	upKeyPath := filepath.Join(dir, "satls-up.key")
	downCertPath := filepath.Join(dir, "satls-down.crt")
	downKeyPath := filepath.Join(dir, "satls-down.key")

	instance, err := xrayCore.New(&xrayCore.Config{})
	if err != nil {
		t.Fatalf("create Xray instance: %v", err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	raw, err := xrayCore.CreateObject(instance, &ServerConfig{
		Users: []*protocol.User{{
			Email:   "satls-node|" + password,
			Account: serial.ToTypedMessage(&Account{Path: password}),
		}},
		CertMode:         "self",
		CertFile:         certPath,
		KeyFile:          keyPath,
		ServerName:       serverName,
		RejectUnknownSni: true,
		UpServerName:     upServer,
		DownServerName:   downServer,
		UpCertFile:       upCertPath,
		UpKeyFile:        upKeyPath,
		DownCertFile:     downCertPath,
		DownKeyFile:      downKeyPath,
	})
	if err != nil {
		t.Fatalf("create SATLS server: %v", err)
	}
	server, ok := raw.(*Server)
	if !ok {
		t.Fatalf("server type = %T, want *satls.Server", raw)
	}
	t.Cleanup(func() { close(server.stopCh) })

	certPEM := verifyCertificateHostname(t, certPath, serverName)
	verifyCertificateHostname(t, upCertPath, upServer)
	verifyCertificateHostname(t, downCertPath, downServer)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("append generated certificate to root pool")
	}

	serverConn, clientConn := net.Pipe()
	deadline := time.Now().Add(5 * time.Second)
	_ = serverConn.SetDeadline(deadline)
	_ = clientConn.SetDeadline(deadline)
	t.Cleanup(func() {
		_ = serverConn.Close()
		_ = clientConn.Close()
	})
	type handshakeResult struct {
		host string
		info *handshakeRequest
		err  error
	}
	resultCh := make(chan handshakeResult, 1)
	go func() {
		conn, sni, acceptErr := server.acceptTLS(serverConn)
		if acceptErr != nil {
			resultCh <- handshakeResult{err: acceptErr}
			return
		}
		defer conn.Close()
		req, readErr := http.ReadRequest(bufio.NewReader(conn))
		if readErr != nil {
			resultCh <- handshakeResult{err: readErr}
			return
		}
		body, readErr := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if readErr != nil {
			resultCh <- handshakeResult{err: readErr}
			return
		}
		info, validateErr := server.validateRequest(req, len(body), sni)
		resultCh <- handshakeResult{host: req.Host, info: info, err: validateErr}
	}()

	client := tls.Client(clientConn, &tls.Config{
		ServerName: serverName,
		RootCAs:    roots,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"},
	})
	if err := client.Handshake(); err != nil {
		t.Fatalf("single-layer TLS handshake: %v", err)
	}
	if _, err := fmt.Fprintf(client, "SATLS /%s HTTP/1.1\r\nHost: %s\r\nS-Session-ID: %s\r\nS-Link-Mode: FULL\r\nS-Version: 2.0\r\nContent-Length: 0\r\n\r\n", password, httpHost, currentSessionID()); err != nil {
		t.Fatalf("write SATLS request: %v", err)
	}

	select {
	case result := <-resultCh:
		if result.err != nil {
			t.Fatalf("SATLS handshake validation: %v", result.err)
		}
		if result.info == nil || result.info.path != password || result.info.sni != serverName {
			t.Fatalf("unexpected handshake info: %+v", result.info)
		}
		if result.host != httpHost {
			t.Fatalf("HTTP Host = %q, want %q", result.host, httpHost)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SATLS handshake timed out")
	}
}

func TestNewServerRejectsMissingFileCertificateAndUnknownMode(t *testing.T) {
	instance, err := xrayCore.New(&xrayCore.Config{})
	if err != nil {
		t.Fatalf("create Xray instance: %v", err)
	}
	t.Cleanup(func() { _ = instance.Close() })

	tests := []struct {
		name      string
		mode      string
		wantError string
	}{
		{name: "missing file", mode: "file", wantError: "configured certificate file does not exist"},
		{name: "unknown mode", mode: "automatic", wantError: "unsupported certificate mode"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			_, err := xrayCore.CreateObject(instance, &ServerConfig{
				CertMode:   tt.mode,
				CertFile:   filepath.Join(dir, "missing.crt"),
				KeyFile:    filepath.Join(dir, "missing.key"),
				ServerName: "tls.edge.example",
			})
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("NewServer mode %q error = %v, want %q", tt.mode, err, tt.wantError)
			}
		})
	}
}

func TestLegacyEmptyCertificateModeStillGeneratesSelfSigned(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "legacy.crt")
	keyPath := filepath.Join(dir, "legacy.key")
	instance, err := xrayCore.New(&xrayCore.Config{})
	if err != nil {
		t.Fatalf("create Xray instance: %v", err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	raw, err := xrayCore.CreateObject(instance, &ServerConfig{
		CertFile:   certPath,
		KeyFile:    keyPath,
		ServerName: "legacy.edge.example",
	})
	if err != nil {
		t.Fatalf("legacy empty cert_mode: %v", err)
	}
	server := raw.(*Server)
	t.Cleanup(func() { close(server.stopCh) })
	verifyCertificateHostname(t, certPath, "legacy.edge.example")
}

func verifyCertificateHostname(t *testing.T, path, serverName string) []byte {
	t.Helper()
	certPEM, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read generated certificate %s: %v", path, err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatalf("generated certificate %s is not PEM", path)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse generated certificate %s: %v", path, err)
	}
	if err := certificate.VerifyHostname(serverName); err != nil {
		t.Fatalf("generated certificate %s SAN does not contain %q: %v", path, serverName, err)
	}
	return certPEM
}

func currentSessionID() string {
	raw := make([]byte, 16)
	binary.BigEndian.PutUint64(raw[:8], uint64(time.Now().Unix()))
	return hex.EncodeToString(raw)
}
