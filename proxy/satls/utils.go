package satls

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
)

const (
	protocolName         = "satls"
	satlsVersion         = "2.0"
	maxPaddingSize       = 64 * 1024
	sessionSkewAllowance = 120 * time.Second
	sessionReplayTTL     = 5 * time.Minute
	splitDownTimeout     = 10 * time.Second
)

type linkMode int

const (
	linkModeFull linkMode = iota
	linkModeUp
	linkModeDown
)

func (m linkMode) String() string {
	switch m {
	case linkModeUp:
		return "UP"
	case linkModeDown:
		return "DOWN"
	default:
		return "FULL"
	}
}

func parseLinkMode(value string) (linkMode, error) {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "", "FULL", "STANDARD":
		return linkModeFull, nil
	case "UP":
		return linkModeUp, nil
	case "DOWN":
		return linkModeDown, nil
	default:
		return linkModeFull, errors.New("satls: invalid link mode")
	}
}

func normalizePathToken(v string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(v), "/"))
}

func fileExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func hashPath(token string) [32]byte {
	return sha256.Sum256([]byte(token))
}

func parseSessionID(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if len(raw) != 32 {
		return "", errors.New("satls: invalid session id length")
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) != 16 {
		return "", errors.New("satls: invalid session id")
	}
	timestamp := int64(binary.BigEndian.Uint64(decoded[:8]))
	now := time.Now().Unix()
	if time.Duration(abs64(now-timestamp))*time.Second > sessionSkewAllowance {
		return "", errors.New("satls: session id skew")
	}
	return strings.ToLower(raw), nil
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

func parseBoolHeader(value string) (bool, bool) {
	value = strings.TrimSpace(strings.ToLower(value))
	switch value {
	case "true", "1", "yes":
		return true, true
	case "false", "0", "no":
		return false, true
	default:
		return false, false
	}
}

type cachedConn struct {
	net.Conn
	reader *bufio.Reader
}

func newCachedConn(conn net.Conn, reader *bufio.Reader) net.Conn {
	if reader == nil || reader.Buffered() == 0 {
		return conn
	}
	return &cachedConn{Conn: conn, reader: reader}
}

func (c *cachedConn) Read(p []byte) (int, error) {
	if c.reader != nil {
		if c.reader.Buffered() > 0 {
			return c.reader.Read(p)
		}
		c.reader = nil
	}
	return c.Conn.Read(p)
}

func readDestinationMetadata(r io.Reader) (xnet.Destination, error) {
	head := make([]byte, 5)
	if _, err := io.ReadFull(r, head); err != nil {
		return xnet.Destination{}, err
	}
	atyp := head[0]
	addrLen := binary.BigEndian.Uint32(head[1:5])
	if addrLen == 0 || addrLen > 8<<10 {
		return xnet.Destination{}, errors.New("satls: invalid address length")
	}
	addr := make([]byte, addrLen)
	if _, err := io.ReadFull(r, addr); err != nil {
		return xnet.Destination{}, err
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return xnet.Destination{}, err
	}
	port := binary.BigEndian.Uint16(portBuf)
	var address xnet.Address
	switch atyp {
	case 0x01:
		address = xnet.ParseAddress(string(addr))
	case 0x03:
		if len(addr) != 4 {
			return xnet.Destination{}, errors.New("satls: invalid ipv4 length")
		}
		address = xnet.IPAddress(addr)
	case 0x04:
		if len(addr) != 16 {
			return xnet.Destination{}, errors.New("satls: invalid ipv6 length")
		}
		address = xnet.IPAddress(addr)
	default:
		return xnet.Destination{}, errors.New("satls: unknown address type")
	}
	return xnet.TCPDestination(address, xnet.Port(port)), nil
}
