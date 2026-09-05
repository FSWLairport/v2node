package dynamicguard

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

// A DynamicGuard node forwards packets through a kernel TUN, so the only place
// it can observe a connection is the ACL hook every decapsulated packet already
// passes. That makes the flow table a packet-path structure: it has to be cheap
// when logging is off, bounded when it is on, and it must never turn a busy
// tunnel into an unbounded queue.
const (
	// flowTTL is how long a flow stays "already reported". A connection that
	// outlives it is recorded again, which is what keeps a long-lived session
	// visible without recording every packet of it.
	flowTTL = 5 * time.Minute
	// flowMaxSeen bounds the dedupe table. Reaching it means the node is seeing
	// more distinct flows per TTL than the panel could usefully store anyway.
	flowMaxSeen = 65536
	// flowMaxPending bounds what one push interval may accumulate.
	flowMaxPending    = 16384
	flowDropLogPeriod = 30 * time.Second
)

type flowKey struct {
	src, dst         netip.Addr
	srcPort, dstPort uint16
	proto            uint8
}

// FlowRecord is one observed connection, already resolved to the credential and
// device that owns the source address.
type FlowRecord struct {
	UserID           int
	DeviceID         [16]byte
	At               time.Time
	Proto            uint8
	Src, Dst         netip.Addr
	SrcPort, DstPort uint16
}

type flowLog struct {
	enabled atomic.Bool
	// ponytail: one mutex for the whole table. Shard by flowKey hash if the
	// packet path ever shows contention on it.
	mu      sync.Mutex
	seen    map[flowKey]time.Time
	pending []FlowRecord
	dropped atomic.Uint64
	lastLog atomic.Int64
}

func newFlowLog(enabled bool) *flowLog {
	f := &flowLog{seen: make(map[flowKey]time.Time)}
	f.enabled.Store(enabled)
	return f
}

// observe records a packet's flow the first time it is seen in a TTL window.
// It is called from the TUN write path, so everything past the dedupe check has
// to stay off the common path.
func (f *flowLog) observe(pkt []byte, devices *DeviceTable, now time.Time) {
	src, dst, ok := packetAddrs(pkt)
	if !ok {
		return
	}
	proto, srcPort, dstPort := packetPorts(pkt)
	key := flowKey{src: src, dst: dst, srcPort: srcPort, dstPort: dstPort, proto: proto}

	f.mu.Lock()
	if last, seen := f.seen[key]; seen && now.Sub(last) < flowTTL {
		f.mu.Unlock()
		return
	}
	if len(f.pending) >= flowMaxPending {
		f.mu.Unlock()
		f.noteDropped(1, now)
		return
	}
	if len(f.seen) >= flowMaxSeen {
		f.sweepLocked(now)
		if len(f.seen) >= flowMaxSeen {
			// Recording without remembering would report the same flow on every
			// packet, which is worse than losing it.
			f.mu.Unlock()
			f.noteDropped(1, now)
			return
		}
	}
	f.seen[key] = now
	f.mu.Unlock()

	// The owner lookup takes the device table's own lock, so it stays outside
	// this one: the two are never held together anywhere else either.
	userID, deviceID, known := devices.OwnerByIP(src)
	if !known {
		return
	}
	record := FlowRecord{UserID: userID, DeviceID: deviceID, At: now, Proto: proto, Src: src, Dst: dst, SrcPort: srcPort, DstPort: dstPort}
	f.mu.Lock()
	f.pending = append(f.pending, record)
	f.mu.Unlock()
}

// drain hands over what accumulated and expires the dedupe table. It runs on
// the report tick, which is the only periodic work this structure gets.
func (f *flowLog) drain(now time.Time) []FlowRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sweepLocked(now)
	out := f.pending
	f.pending = nil
	return out
}

func (f *flowLog) sweepLocked(now time.Time) {
	for key, at := range f.seen {
		if now.Sub(at) >= flowTTL {
			delete(f.seen, key)
		}
	}
}

// noteDropped counts every lost record but logs at most once per period, the
// same shape as the ACL's drop counter.
func (f *flowLog) noteDropped(n int, now time.Time) {
	total := f.dropped.Add(uint64(n))
	last := f.lastLog.Load()
	if now.UnixNano()-last < int64(flowDropLogPeriod) {
		return
	}
	if !f.lastLog.CompareAndSwap(last, now.UnixNano()) {
		return
	}
	log.WithField("dropped_total", total).Info("[DynamicGuard] access log records dropped")
}

// packetPorts reads the IP protocol number and, for TCP and UDP, the ports.
// Every other protocol keeps its number and reports no ports: ICMP, and the
// encapsulations an audit cares about most because the log goes blind inside
// them (ESP, AH, GRE), are then distinguishable rather than all "other".
// Protocol 0 means the header could not be read at all.
func packetPorts(pkt []byte) (proto uint8, srcPort, dstPort uint16) {
	if len(pkt) < 1 {
		return 0, 0, 0
	}
	var offset int
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return 0, 0, 0
		}
		// A later fragment carries no transport header; the first fragment
		// already reported the flow.
		if pkt[6]&0x1f != 0 || pkt[7] != 0 {
			return 0, 0, 0
		}
		headerLen := int(pkt[0]&0x0f) * 4
		if headerLen < 20 {
			return 0, 0, 0
		}
		proto, offset = pkt[9], headerLen
	case 6:
		if len(pkt) < 40 {
			return 0, 0, 0
		}
		// ponytail: no extension-header walk, so a chained packet reports the
		// first next-header value (0 for hop-by-hop, 43 for routing) instead of
		// the protocol behind it. Walk the chain if these show up in the log
		// often enough to mislead.
		proto, offset = pkt[6], 40
	default:
		return 0, 0, 0
	}
	if (proto != 6 && proto != 17) || len(pkt) < offset+4 {
		return proto, 0, 0
	}
	return proto, binary.BigEndian.Uint16(pkt[offset:]), binary.BigEndian.Uint16(pkt[offset+2:])
}
