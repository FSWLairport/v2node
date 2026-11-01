package dynamicguard

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun"
	"github.com/wyx2685/v2node/common/userlease"
)

// The server uses a real kernel TUN. Only the clients' application packet sources
// are in memory; all traffic crosses real UDP, AmneziaWG encryption and the kernel.
type consumerClientTUN struct {
	input, output chan []byte
	done          chan struct{}
	once          sync.Once
}

func newConsumerClientTUN() *consumerClientTUN {
	return &consumerClientTUN{input: make(chan []byte, 16), output: make(chan []byte, 16), done: make(chan struct{})}
}
func (c *consumerClientTUN) File() *os.File           { return nil }
func (c *consumerClientTUN) Name() (string, error)    { return "consumer-test-client", nil }
func (c *consumerClientTUN) MTU() (int, error)        { return 1408, nil }
func (c *consumerClientTUN) Events() <-chan tun.Event { return nil }
func (c *consumerClientTUN) BatchSize() int           { return 1 }
func (c *consumerClientTUN) Close() error             { c.once.Do(func() { close(c.done) }); return nil }
func (c *consumerClientTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case packet := <-c.input:
		sizes[0] = copy(bufs[0][offset:], packet)
		return 1, nil
	case <-c.done:
		return 0, io.EOF
	}
}
func (c *consumerClientTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		select {
		case c.output <- bytes.Clone(b[offset:]):
		case <-c.done:
			return 0, io.EOF
		}
	}
	return len(bufs), nil
}
func consumerUDPPacket(src, dst netip.Addr, sourcePort, destinationPort uint16, payload []byte) []byte {
	p := make([]byte, 28+len(payload))
	p[0] = 0x45
	p[8] = 64
	p[9] = 17
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	copy(p[12:16], src.AsSlice())
	copy(p[16:20], dst.AsSlice())
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(p[10:12], ^uint16(sum))
	binary.BigEndian.PutUint16(p[20:22], sourcePort)
	binary.BigEndian.PutUint16(p[22:24], destinationPort)
	binary.BigEndian.PutUint16(p[24:26], uint16(8+len(payload)))
	copy(p[28:], payload)
	return p
}
func TestConsumerKernelTUNEncryptedTrafficExpires(t *testing.T) {
	if os.Getenv("SAIKYO_DG_TUN_INTEGRATION") != "1" {
		t.Skip("requires an isolated network namespace, /dev/net/tun and CAP_NET_ADMIN")
	}
	serverIP := netip.MustParseAddr("10.77.91.1")
	consumerIP := netip.MustParseAddr("10.77.91.2")
	businessIP := netip.MustParseAddr("10.77.91.3")
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	var private [32]byte
	if _, err = rand.Read(private[:]); err != nil {
		t.Fatal(err)
	}
	public, err := derivePublicKey(private)
	if err != nil {
		t.Fatal(err)
	}
	params, err := GenerateAmneziaParams()
	if err != nil {
		t.Fatal(err)
	}
	users := NewUserKeyMap()
	tag := t.Name()
	userlease.Set(tag, time.Now().Add(time.Minute), nil)
	defer userlease.Revoke(tag)
	users.Update([]*UserEntry{{UserID: 1, UserKey: [32]byte{1}, LeaseTag: tag}, {UserID: 2, UserKey: [32]byte{2}}})
	table := NewDeviceTable()
	server, err := NewWGDevice(&WGDeviceConfig{PrivateKey: private, MTU: 1408, UDPConn: udp, TunnelAddrs: []netip.Addr{serverIP}, Prefixes: []netip.Prefix{netip.MustParsePrefix("10.77.91.0/24")}, Params: params, DeviceTable: table, UserKeys: users, ACL: newACLPolicy(nil, nil, nil, nil)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	server.SetDeviceTable(table)
	demux := &DGServer{udpConn: udp, wgDevice: server, stopCh: make(chan struct{})}
	demux.readLoopDone.Add(1)
	go demux.readLoop()
	defer func() { close(demux.stopCh); udp.Close(); demux.readLoopDone.Wait() }()
	client := func(uid int, ip netip.Addr) *consumerClientTUN {
		t.Helper()
		var key [32]byte
		if _, err := rand.Read(key[:]); err != nil {
			t.Fatal(err)
		}
		pub, err := derivePublicKey(key)
		if err != nil {
			t.Fatal(err)
		}
		if err = table.Register(&DeviceEntry{UserID: uid, DeviceID: [16]byte{byte(uid)}, WGStaticPub: pub, AssignedIP: ip, Status: DeviceStatusActive}); err != nil {
			t.Fatal(err)
		}
		if err = server.AddPeer(pub, ip); err != nil {
			t.Fatal(err)
		}
		source := newConsumerClientTUN()
		dev := device.NewDevice(source, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "client: "))
		t.Cleanup(dev.Close)
		ipc := fmt.Sprintf("private_key=%s\n%spublic_key=%s\nendpoint=%s\nallowed_ip=%s/32\n", hex.EncodeToString(key[:]), params.IpcLines(), hex.EncodeToString(public[:]), udp.LocalAddr(), serverIP)
		if err = dev.IpcSet(ipc); err != nil {
			t.Fatal(err)
		}
		if err = dev.Up(); err != nil {
			t.Fatal(err)
		}
		return source
	}
	customer := client(1, consumerIP)
	business := client(2, businessIP)
	app, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IP(serverIP.AsSlice())})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	port := uint16(app.LocalAddr().(*net.UDPAddr).Port)
	send := func(c *consumerClientTUN, ip netip.Addr, message string) {
		c.input <- consumerUDPPacket(ip, serverIP, 40000, port, []byte(message))
	}
	receiveApp := func(message string) *net.UDPAddr {
		t.Helper()
		app.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 1500)
		n, peer, e := app.ReadFromUDP(buf)
		if e != nil || string(buf[:n]) != message {
			t.Fatalf("kernel application receive: %q %v", buf[:n], e)
		}
		return peer
	}
	receiveClient := func(c *consumerClientTUN, message string) {
		t.Helper()
		select {
		case p := <-c.output:
			if len(p) < 28 || string(p[28:]) != message {
				t.Fatalf("decrypted response: %x", p)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("no encrypted downlink response")
		}
	}
	send(customer, consumerIP, "customer-up")
	customerPeer := receiveApp("customer-up")
	if _, err = app.WriteToUDP([]byte("customer-down"), customerPeer); err != nil {
		t.Fatal(err)
	}
	receiveClient(customer, "customer-down")
	send(business, businessIP, "business-up")
	businessPeer := receiveApp("business-up")
	if _, err = app.WriteToUDP([]byte("business-down"), businessPeer); err != nil {
		t.Fatal(err)
	}
	receiveClient(business, "business-down")
	usage := server.aclDev.collectConsumerTraffic()
	if len(usage) != 1 || usage[0].Upload != int64(28+len("customer-up")) || usage[0].Download != int64(28+len("customer-down")) {
		t.Fatalf("accepted IP-byte accounting: %+v", usage)
	}
	// Retain the authenticated WG peer and encryption session after expiry. The
	// data plane must reject both directions even before background peer removal.
	userlease.Set(tag, time.Now().Add(150*time.Millisecond), nil)
	time.Sleep(200 * time.Millisecond)
	send(customer, consumerIP, "expired-up")
	app.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 1500)
	if n, _, e := app.ReadFromUDP(buf); e == nil {
		t.Fatalf("expired upload reached kernel: %q", buf[:n])
	}
	if _, err = app.WriteToUDP([]byte("expired-down"), customerPeer); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-customer.output:
		t.Fatalf("expired downlink delivered: %x", p)
	case <-time.After(300 * time.Millisecond):
	}
	send(business, businessIP, "business-still-up")
	receiveApp("business-still-up")
	if _, err = app.WriteToUDP([]byte("business-still-down"), businessPeer); err != nil {
		t.Fatal(err)
	}
	receiveClient(business, "business-still-down")
	if usage = server.aclDev.collectConsumerTraffic(); len(usage) != 0 {
		t.Fatalf("denied or enterprise packets billed to customer: %+v", usage)
	}
	t.Log("real UDP + AmneziaWG + kernel TUN: C bidirectional expiry, exact IP bytes, enterprise unaffected")
}
