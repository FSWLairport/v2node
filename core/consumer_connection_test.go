package core

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sagernet/smux"
	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/common/format"
	"github.com/wyx2685/v2node/common/userlease"
	"github.com/wyx2685/v2node/conf"
	"github.com/wyx2685/v2node/limiter"
)

func TestConsumerSATLSExistingConnectionExpiresWithoutPanel(t *testing.T) {
	duration := time.Second
	if raw := os.Getenv("SAIKYO_TEST_LEASE_SECONDS"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 45 {
			t.Fatal("invalid test lease duration")
		}
		duration = time.Duration(n) * time.Second
	}
	echo, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	reserve, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()
	dir := t.TempDir()
	tag := t.Name()
	users := []panel.UserInfo{{Id: 1, Uuid: uuid.NewString()}, {Id: 2, Uuid: uuid.NewString()}}
	info := &panel.NodeInfo{Id: 1, Tag: tag, Type: "satls", Security: panel.Tls, Common: &panel.CommonNode{Protocol: "satls", ListenIP: "127.0.0.1", ServerPort: port, Network: "tcp", TlsSettings: panel.TlsSettings{ServerName: "lease.example.test"}, CertInfo: &panel.CertInfo{CertMode: "self", CertFile: filepath.Join(dir, "cert.pem"), KeyFile: filepath.Join(dir, "key.pem"), RejectUnknownSni: true}, SatlsSettings: &panel.SatlsSettings{Host: "lease.example.test", Mode: "full"}}}
	engine := New(conf.New())
	if err = engine.Start([]*panel.NodeInfo{info}); err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	limiter.Init()
	limiter.AddLimiter("satls", tag, users, nil)
	defer limiter.DeleteLimiter(tag)
	if err = engine.AddNode(tag, info); err != nil {
		t.Fatal(err)
	}
	if _, err = engine.AddUsers(&AddUsersParams{Tag: tag, NodeInfo: info, Users: users}); err != nil {
		t.Fatal(err)
	}
	// SATLS applies user additions through its existing 200 ms debounce.
	time.Sleep(250 * time.Millisecond)
	key := format.UserTag(tag, users[0].Uuid)
	userlease.Set(key, time.Now().Add(time.Minute), func() { engine.CloseUserConnections(tag, users[0].Uuid) })
	pem, err := os.ReadFile(info.Common.CertInfo.CertFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatal("invalid test certificate")
	}
	dial := func(password string) *smux.Session {
		t.Helper()
		var conn *tls.Conn
		until := time.Now().Add(3 * time.Second)
		for {
			conn, err = tls.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", port), &tls.Config{ServerName: "lease.example.test", RootCAs: roots, MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}})
			if err == nil {
				break
			}
			if time.Now().After(until) {
				t.Fatal(err)
			}
			time.Sleep(20 * time.Millisecond)
		}
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		var id [16]byte
		rand.Read(id[:])
		binary.BigEndian.PutUint64(id[:8], uint64(time.Now().Unix()))
		fmt.Fprintf(conn, "SATLS /%s HTTP/1.1\r\nHost: lease.example.test\r\nS-Session-ID: %s\r\nS-Link-Mode: FULL\r\nS-Version: 2.0\r\nContent-Length: 0\r\n\r\n", password, hex.EncodeToString(id[:]))
		response, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil || response.StatusCode != 101 {
			t.Fatalf("SATLS handshake: %v %+v", err, response)
		}
		conn.SetDeadline(time.Time{})
		cfg := smux.DefaultConfig()
		cfg.Version = 2
		cfg.KeepAliveInterval = 15 * time.Second
		cfg.KeepAliveTimeout = 60 * time.Second
		s, err := smux.Client(conn, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close(); conn.Close() })
		return s
	}
	open := func(s *smux.Session) (*smux.Stream, byte, error) {
		stream, err := s.OpenStream()
		if err != nil {
			return nil, 0, err
		}
		stream.SetDeadline(time.Now().Add(2 * time.Second))
		meta := []byte{3, 0, 0, 0, 4, 127, 0, 0, 1, 0, 0}
		binary.BigEndian.PutUint16(meta[9:], uint16(echo.Addr().(*net.TCPAddr).Port))
		if _, err = stream.Write(meta); err != nil {
			return stream, 0, err
		}
		var ack [1]byte
		_, err = io.ReadFull(stream, ack[:])
		stream.SetDeadline(time.Time{})
		return stream, ack[0], err
	}
	exchange := func(s *smux.Stream) error {
		s.SetDeadline(time.Now().Add(time.Second))
		if _, err := s.Write([]byte("ping")); err != nil {
			return err
		}
		var out [4]byte
		_, err := io.ReadFull(s, out[:])
		if err == nil && string(out[:]) != "ping" {
			return fmt.Errorf("invalid echo")
		}
		return err
	}
	cSession, bSession := dial(users[0].Uuid), dial(users[1].Uuid)
	cStream, ack, err := open(cSession)
	if err != nil || ack != 0 {
		t.Fatalf("C stream: %d %v", ack, err)
	}
	defer cStream.Close()
	bStream, ack, err := open(bSession)
	if err != nil || ack != 0 {
		t.Fatalf("B stream: %d %v", ack, err)
	}
	defer bStream.Close()
	if err = exchange(cStream); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	userlease.Set(key, started.Add(duration), func() { engine.CloseUserConnections(tag, users[0].Uuid) })
	for {
		err = exchange(cStream)
		if err != nil {
			break
		}
		if time.Since(started) > duration+2*time.Second {
			t.Fatal("C continued after authorization expiry")
		}
		time.Sleep(25 * time.Millisecond)
	}
	elapsed := time.Since(started)
	if elapsed < duration-100*time.Millisecond || elapsed > duration+2*time.Second {
		t.Fatalf("unexpected expiry timing %v, expected %v", elapsed, duration)
	}
	if err = exchange(bStream); err != nil {
		t.Fatalf("B connection affected by C expiry: %v", err)
	}
	denied, ack, err := open(cSession)
	if denied != nil {
		defer denied.Close()
	}
	if err == nil && ack == 0 {
		t.Fatal("expired cached SATLS session opened a new stream")
	}
	traffic, err := engine.GetConsumerTrafficSlice(tag)
	if err != nil || len(traffic) != 1 || traffic[0].UID != 1 || traffic[0].Upload < 4 || traffic[0].Download < 4 {
		t.Fatalf("actual C bytes were not metered: %+v %v", traffic, err)
	}
	t.Logf("existing SATLS TCP stream stopped after %v with no panel, B stream remained usable", elapsed)
}
