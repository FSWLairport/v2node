package satls

import (
	"bytes"
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	xrayCore "github.com/xtls/xray-core/core"
)

// A rotated main certificate has to reach clients on the next handshake. The
// alternative is a reload, which tears the node down and drops every live
// connection, so the rotation interval would become the outage interval.
func TestMainCertificateRotatesWithoutRestart(t *testing.T) {
	const serverName = "tls.edge.example"
	dir := t.TempDir()
	certPath := filepath.Join(dir, "satls.crt")
	keyPath := filepath.Join(dir, "satls.key")

	instance, err := xrayCore.New(&xrayCore.Config{})
	if err != nil {
		t.Fatalf("create Xray instance: %v", err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	raw, err := xrayCore.CreateObject(instance, &ServerConfig{
		CertMode:   "self",
		CertFile:   certPath,
		KeyFile:    keyPath,
		ServerName: serverName,
	})
	if err != nil {
		t.Fatalf("create SATLS server: %v", err)
	}
	server := raw.(*Server)
	t.Cleanup(func() { close(server.stopCh) })

	first := servedCertificate(t, server, serverName)

	// An ACME renewal, a panel push in remote mode, or certbot in file mode all
	// land as new bytes at the same paths.
	time.Sleep(10 * time.Millisecond)
	if err := generateSelfSigned(serverName, certPath, keyPath); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	second := servedCertificate(t, server, serverName)
	if bytes.Equal(first, second) {
		t.Fatal("the same certificate was served after rotation")
	}
}

// servedCertificate completes one handshake against the server and reports the
// DER of the certificate it presented. The DER is compared rather than the
// serial number, which self-signed generation derives from the current second
// and so repeats for two certificates issued in the same second.
func servedCertificate(t *testing.T, server *Server, serverName string) []byte {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	deadline := time.Now().Add(5 * time.Second)
	_ = serverConn.SetDeadline(deadline)
	_ = clientConn.SetDeadline(deadline)
	defer serverConn.Close()
	defer clientConn.Close()

	go func() {
		if conn, _, err := server.acceptTLS(serverConn); err == nil {
			conn.Close()
		}
	}()

	client := tls.Client(clientConn, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, // the point under test is which cert is served
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"http/1.1"},
	})
	if err := client.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	certs := client.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		t.Fatal("server presented no certificate")
	}
	return certs[0].Raw
}

// A keypair that cannot be loaded must fail startup, not every handshake.
func TestNewServerStillRejectsUnloadableMainCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "satls.crt")
	keyPath := filepath.Join(dir, "satls.key")
	if err := os.WriteFile(certPath, []byte("not a certificate"), 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("not a key"), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	instance, err := xrayCore.New(&xrayCore.Config{})
	if err != nil {
		t.Fatalf("create Xray instance: %v", err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	if _, err := xrayCore.CreateObject(instance, &ServerConfig{
		CertMode:   "file",
		CertFile:   certPath,
		KeyFile:    keyPath,
		ServerName: "tls.edge.example",
	}); err == nil {
		t.Fatal("NewServer accepted a keypair that cannot be loaded")
	}
}
