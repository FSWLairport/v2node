package dynamicguard

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

// tcpPacket builds an IPv4 TCP packet with ports, on the same offset convention
// as the ACL tests.
func tcpPacket(src, dst string, srcPort, dstPort uint16, proto uint8) []byte {
	buf := make([]byte, testOffset+24)
	pkt := buf[testOffset:]
	pkt[0] = 4<<4 | 5 // version 4, 5-word header
	pkt[9] = proto
	copy(pkt[12:16], netip.MustParseAddr(src).AsSlice())
	copy(pkt[16:20], netip.MustParseAddr(dst).AsSlice())
	binary.BigEndian.PutUint16(pkt[20:], srcPort)
	binary.BigEndian.PutUint16(pkt[22:], dstPort)
	return buf
}

func TestPacketPortsReadsTransportHeaders(t *testing.T) {
	proto, srcPort, dstPort := packetPorts(tcpPacket("10.0.0.2", "1.1.1.1", 51544, 443, 6)[testOffset:])
	if proto != 6 || srcPort != 51544 || dstPort != 443 {
		t.Fatalf("tcp proto=%d src=%d dst=%d", proto, srcPort, dstPort)
	}
	if proto, _, dstPort = packetPorts(tcpPacket("10.0.0.2", "1.1.1.1", 1, 53, 17)[testOffset:]); proto != 17 || dstPort != 53 {
		t.Fatalf("udp proto=%d dst=%d", proto, dstPort)
	}

	// A longer header must not be read as if it were the minimum one.
	long := make([]byte, 40)
	long[0] = 4<<4 | 6 // 6 words = 24 bytes of header
	long[9] = 6
	binary.BigEndian.PutUint16(long[24:], 8080)
	binary.BigEndian.PutUint16(long[26:], 9090)
	if proto, srcPort, dstPort = packetPorts(long); proto != 6 || srcPort != 8080 || dstPort != 9090 {
		t.Fatalf("options header proto=%d src=%d dst=%d", proto, srcPort, dstPort)
	}

	// A later fragment carries no transport header, so reading one would report
	// two bytes of payload as ports.
	fragment := tcpPacket("10.0.0.2", "1.1.1.1", 51544, 443, 6)[testOffset:]
	fragment[7] = 0x10
	if proto, srcPort, dstPort = packetPorts(fragment); proto != 0 || srcPort != 0 || dstPort != 0 {
		t.Fatalf("fragment proto=%d src=%d dst=%d", proto, srcPort, dstPort)
	}

	// ICMP keeps its number and reports no ports, so the panel can tell a ping
	// from an ESP tunnel instead of filing both as "other". The bytes where the
	// ports would be must not be read as ports.
	for _, other := range []uint8{1, 50, 47} {
		if proto, srcPort, dstPort = packetPorts(tcpPacket("10.0.0.2", "1.1.1.1", 51544, 443, other)[testOffset:]); proto != other || srcPort != 0 || dstPort != 0 {
			t.Fatalf("proto %d read as proto=%d src=%d dst=%d", other, proto, srcPort, dstPort)
		}
	}

	// A header this short is unreadable rather than a protocol: v4Packet leaves
	// the header length at zero.
	if proto, srcPort, dstPort = packetPorts(v4Packet("10.0.0.2", "1.1.1.1")[testOffset:]); proto != 0 || srcPort != 0 || dstPort != 0 {
		t.Fatalf("unreadable header proto=%d src=%d dst=%d", proto, srcPort, dstPort)
	}
}

func TestFlowLogRecordsEachFlowOncePerTTL(t *testing.T) {
	devices := leaseTable(t, map[string]int{"10.0.0.2": 7})
	flows := newFlowLog(true)
	at := time.Now()
	packet := tcpPacket("10.0.0.2", "1.1.1.1", 51544, 443, 6)[testOffset:]

	flows.observe(packet, devices, at)
	flows.observe(packet, devices, at.Add(time.Second))
	// A different port is a different connection.
	flows.observe(tcpPacket("10.0.0.2", "1.1.1.1", 51545, 443, 6)[testOffset:], devices, at.Add(time.Second))

	records := flows.drain(at.Add(2 * time.Second))
	if len(records) != 2 {
		t.Fatalf("records=%d, want 2", len(records))
	}
	if records[0].UserID == 0 || records[0].DstPort != 443 || records[0].Proto != 6 {
		t.Fatalf("record=%#v", records[0])
	}

	// Past the TTL the same connection is reported again, which is how a session
	// that outlives the window stays visible.
	flows.observe(packet, devices, at.Add(flowTTL+time.Minute))
	if again := flows.drain(at.Add(flowTTL + 2*time.Minute)); len(again) != 1 {
		t.Fatalf("after TTL records=%d, want 1", len(again))
	}
}

// ICMP has no ports, so the protocol number is the only thing that separates a
// ping from the TCP session to the same address. A flood still costs one record
// per TTL rather than one per packet.
func TestFlowLogRecordsICMPAsItsOwnFlow(t *testing.T) {
	devices := leaseTable(t, map[string]int{"10.0.0.2": 7})
	flows := newFlowLog(true)
	at := time.Now()
	icmp := tcpPacket("10.0.0.2", "1.1.1.1", 51544, 443, 1)[testOffset:]

	// ICMP carries no ports, so every packet of a flood hashes to the same key
	// and the whole flood is one record: a ping is a flow, not a per-packet
	// event, and the panel must never be asked to store it as one.
	for i := range 1000 {
		flows.observe(icmp, devices, at.Add(time.Duration(i)*time.Millisecond))
	}
	flows.observe(tcpPacket("10.0.0.2", "1.1.1.1", 51544, 443, 6)[testOffset:], devices, at.Add(time.Second))

	records := flows.drain(at.Add(2 * time.Second))
	if len(records) != 2 {
		t.Fatalf("records=%d, want 2 (one ICMP flow, one TCP flow)", len(records))
	}
	if records[0].Proto != 1 || records[0].SrcPort != 0 || records[0].DstPort != 0 {
		t.Fatalf("icmp record=%#v", records[0])
	}
}

func TestFlowLogDropsRatherThanGrowing(t *testing.T) {
	devices := leaseTable(t, map[string]int{"10.0.0.2": 7})
	flows := newFlowLog(true)
	at := time.Now()
	for i := range flowMaxPending + 500 {
		flows.observe(tcpPacket("10.0.0.2", "1.1.1.1", uint16(1+i%60000), uint16(1+i/60000), 6)[testOffset:], devices, at)
	}
	records := flows.drain(at)
	if len(records) > flowMaxPending {
		t.Fatalf("pending grew past its bound: %d", len(records))
	}
	if flows.dropped.Load() == 0 {
		t.Fatal("overflow was silent")
	}
}

func TestFlowLogIgnoresUnleasedSources(t *testing.T) {
	flows := newFlowLog(true)
	at := time.Now()
	// The ACL denies an unleased source, so one only reaches here in the window
	// between a lease expiring and the peer going away.
	flows.observe(tcpPacket("10.0.0.9", "1.1.1.1", 1, 443, 6)[testOffset:], NewDeviceTable(), at)
	if records := flows.drain(at); len(records) != 0 {
		t.Fatalf("records=%#v, want none", records)
	}
}

// Logging off must leave the forwarding path exactly as it was.
func TestACLWriteWithoutAccessLogStaysAllocationFree(t *testing.T) {
	inner := &fakeTUN{countOnly: true}
	dt := leaseTable(t, map[string]int{"10.0.0.2": 7})
	a := newACLTUN(inner, dt, nil, false)
	bufs := [][]byte{tcpPacket("10.0.0.2", "1.1.1.1", 51544, 443, 6)}
	if allocs := testing.AllocsPerRun(100, func() {
		if _, err := a.Write(bufs, testOffset); err != nil {
			t.Fatalf("write: %v", err)
		}
	}); allocs != 0 {
		t.Fatalf("allocs=%v, want 0", allocs)
	}
	if len(a.flows.drain(time.Now())) != 0 {
		t.Fatal("a disabled flow log recorded something")
	}
}

// With no ACL policy at all, logging still has to see forwarded packets: the
// two features share the hook but not the reason to run.
func TestACLWriteRecordsFlowsWithoutAPolicy(t *testing.T) {
	inner := &fakeTUN{}
	dt := leaseTable(t, map[string]int{"10.0.0.2": 7})
	a := newACLTUN(inner, dt, nil, true)
	writeAll(t, a, tcpPacket("10.0.0.2", "1.1.1.1", 51544, 443, 6))
	if len(inner.written) != 1 {
		t.Fatalf("forwarded %d packets, want 1", len(inner.written))
	}
	if records := a.flows.drain(time.Now()); len(records) != 1 {
		t.Fatalf("records=%d, want 1", len(records))
	}
}

// A denied packet reached nothing, so recording it would describe a connection
// that never happened.
func TestACLWriteDoesNotRecordDeniedPackets(t *testing.T) {
	inner := &fakeTUN{}
	dt := leaseTable(t, map[string]int{"10.0.0.2": 7})
	a := newACLTUN(inner, dt, newACLPolicy(map[string]DGACL{
		"7": {Default: "deny"},
	}), true)
	writeAll(t, a, tcpPacket("10.0.0.2", "1.1.1.1", 51544, 443, 6))
	if len(inner.written) != 0 {
		t.Fatal("a denied packet was forwarded")
	}
	if records := a.flows.drain(time.Now()); len(records) != 0 {
		t.Fatalf("denied packet recorded: %#v", records)
	}
}
