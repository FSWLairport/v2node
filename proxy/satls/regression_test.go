package satls

import (
	"bytes"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	xrayCore "github.com/xtls/xray-core/core"
)

type recordingConn struct {
	net.Conn
	bytes.Buffer
}

func (c *recordingConn) Read(p []byte) (int, error)  { return c.Buffer.Read(p) }
func (c *recordingConn) Write(p []byte) (int, error) { return c.Buffer.Write(p) }
func TestSATLSRegressionReconnectSends101BeforeBufferedFrames(t *testing.T) {
	s := newSplitSession("id", nil, nil)
	s.state = splitStatePaused
	s.buffer.WriteString("FRAME")
	c := &recordingConn{}
	_, e := s.attachDown(c, true)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.HasPrefix(c.String(), "HTTP/1.1 101") {
		t.Fatalf("wrong wire order: %q", c.String())
	}
}
func TestSATLSRegressionSplitSNIUsesSplitCertificate(t *testing.T) {
	d := t.TempDir()
	i, e := xrayCore.New(&xrayCore.Config{})
	if e != nil {
		t.Fatal(e)
	}
	defer i.Close()
	raw, e := xrayCore.CreateObject(i, &ServerConfig{CertMode: "self", ServerName: "main.test", CertFile: filepath.Join(d, "main.crt"), KeyFile: filepath.Join(d, "main.key"), UpServerName: "up.test", UpCertFile: filepath.Join(d, "up.crt"), UpKeyFile: filepath.Join(d, "up.key")})
	if e != nil {
		t.Fatal(e)
	}
	s := raw.(*Server)
	defer close(s.stopCh)
	cert, e := x509.ParseCertificate(servedCertificate(t, s, "up.test"))
	if e != nil {
		t.Fatal(e)
	}
	if e = cert.VerifyHostname("up.test"); e != nil {
		t.Fatalf("split SNI served wrong certificate: %v", e)
	}
}

func TestSATLSRegressionPaddingLimit(t *testing.T) {
	for _, length := range []int64{-1, maxPaddingSize + 1} {
		source := strings.NewReader(strings.Repeat("x", maxPaddingSize*2))
		_, err := readPadding(&http.Request{ContentLength: length, Body: io.NopCloser(source)})
		if !errors.Is(err, errPaddingTooLarge) {
			t.Fatalf("length %d: %v", length, err)
		}
		if source.Len() < maxPaddingSize-1 {
			t.Fatal("read beyond padding limit")
		}
	}
	body, err := readPadding(&http.Request{ContentLength: 3, Body: io.NopCloser(strings.NewReader("abc"))})
	if err != nil || string(body) != "abc" {
		t.Fatalf("valid padding: %q %v", body, err)
	}
}

func TestSATLSRegressionCloseIsIdempotent(t *testing.T) {
	up, peer := net.Pipe()
	defer peer.Close()
	session := newSplitSession("id", nil, up)
	combined := &splitConn{session: session}
	session.close(io.EOF)
	if err := combined.Close(); err != nil {
		t.Fatal(err)
	}
	if session.Err() != io.EOF {
		t.Fatal("close lost cause")
	}
	if _, err := session.attachDown(&recordingConn{}, false); err == nil {
		t.Fatal("closed session reattached")
	}
}

type partialWriteConn struct{ net.Conn }

func (*partialWriteConn) Write(p []byte) (int, error) { return 2, io.ErrClosedPipe }
func TestSATLSRegressionPartialFlushRetainsOnlyUnsentBytes(t *testing.T) {
	session := newSplitSession("id", nil, nil)
	session.buffer.WriteString("abcdef")
	session.downConn = &partialWriteConn{}
	if err := session.flushBufferLocked(); err != io.ErrClosedPipe {
		t.Fatalf("flush: %v", err)
	}
	if got := session.buffer.String(); got != "cdef" {
		t.Fatalf("remaining=%q", got)
	}
}
