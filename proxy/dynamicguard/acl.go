package dynamicguard

import (
	"net/netip"
	"strconv"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/amnezia-vpn/amneziawg-go/tun"
)

// DGACL is the server-enforced egress policy of one network. It is unrelated to
// dg_settings.routes: routes only tell the client what to send into the tunnel,
// while the ACL decides what the node is willing to forward once it arrives.
type DGACL struct {
	Default string      `json:"default"`
	Rules   []DGACLRule `json:"rules"`
}

// DGACLRule is one ordered match. The first rule whose CIDR contains the
// packet destination decides; later rules are not consulted.
type DGACLRule struct {
	Action string `json:"action"`
	CIDR   string `json:"cidr"`
}

const (
	aclActionAllow = "allow"
	aclActionDeny  = "deny"
)

type aclRule struct {
	prefix netip.Prefix
	allow  bool
}

type networkACL struct {
	rules        []aclRule
	defaultAllow bool
}

// aclPolicy holds the compiled per-network policies. A nil *aclPolicy means
// "nothing to enforce" and skips the whole check.
type aclPolicy struct {
	networks map[int]networkACL
}

// newACLPolicy compiles the panel payload. It returns nil when no network
// restricts anything, so an absent or all-allow ACL costs nothing on the data
// path and behaves exactly like a node without ACL support.
func newACLPolicy(acl map[string]DGACL) *aclPolicy {
	networks := make(map[int]networkACL, len(acl))
	restricts := false

	for groupStr, cfg := range acl {
		groupID, err := strconv.Atoi(groupStr)
		if err != nil {
			log.Warnf("[DynamicGuard] ACL: skipping non-numeric network key %q", groupStr)
			continue
		}

		// Anything other than "allow" is treated as deny: an unrecognised value
		// must never silently widen access.
		defaultAllow := cfg.Default == aclActionAllow
		if cfg.Default != aclActionAllow && cfg.Default != aclActionDeny {
			log.Warnf("[DynamicGuard] ACL network=%d: unknown default %q, treating as deny", groupID, cfg.Default)
		}

		rules := make([]aclRule, 0, len(cfg.Rules))
		for _, r := range cfg.Rules {
			prefix, err := netip.ParsePrefix(r.CIDR)
			if err != nil {
				// The panel validates CIDRs, so this only happens on a
				// corrupted payload. Skipping the rule is loud enough here.
				log.Errorf("[DynamicGuard] ACL network=%d: invalid CIDR %q, rule ignored: %v", groupID, r.CIDR, err)
				continue
			}
			allow := r.Action == aclActionAllow
			if r.Action != aclActionAllow && r.Action != aclActionDeny {
				log.Warnf("[DynamicGuard] ACL network=%d: unknown action %q for %s, treating as deny", groupID, r.Action, r.CIDR)
			}
			rules = append(rules, aclRule{prefix: prefix.Masked(), allow: allow})
		}

		networks[groupID] = networkACL{rules: rules, defaultAllow: defaultAllow}
		if !defaultAllow || len(rules) > 0 {
			restricts = true
		}
		log.Infof("[DynamicGuard] ACL network=%d default=%s rules=%d", groupID, cfg.Default, len(rules))
	}

	if !restricts {
		return nil
	}
	return &aclPolicy{networks: networks}
}

// allows reports whether a client of the given network may reach dst.
// A network the panel did not send an ACL for is unfiltered, which keeps the
// upgrade window behaving like today.
func (p *aclPolicy) allows(groupID int, dst netip.Addr) bool {
	n, ok := p.networks[groupID]
	if !ok {
		return true
	}
	for i := range n.rules {
		if n.rules[i].prefix.Contains(dst) {
			return n.rules[i].allow
		}
	}
	return n.defaultAllow
}

// aclTUN wraps the kernel TUN device and enforces the per-network ACL on the
// Write() direction, i.e. packets decapsulated from a peer on their way into
// the kernel. That is the only path a tunnel client can use to reach anything,
// so it is the only direction that needs filtering: the Read() direction
// (return traffic and traffic other peers originate) is already constrained by
// each peer's WireGuard allowed_ip, which is that peer's own /32 or /128.
type aclTUN struct {
	tun.Device
	devices *DeviceTable
	policy  atomic.Pointer[aclPolicy]
	dropped atomic.Uint64
	lastLog atomic.Int64 // unix nano of the last drop log, rate limits the hot path
}

const aclDropLogInterval = 30 * time.Second

func newACLTUN(inner tun.Device, devices *DeviceTable, policy *aclPolicy) *aclTUN {
	a := &aclTUN{Device: inner, devices: devices}
	a.SetPolicy(policy)
	return a
}

// SetPolicy swaps the whole policy atomically; the data path never locks.
func (a *aclTUN) SetPolicy(p *aclPolicy) { a.policy.Store(p) }

// Dropped returns the number of packets denied so far.
func (a *aclTUN) Dropped() uint64 { return a.dropped.Load() }

func (a *aclTUN) Write(bufs [][]byte, offset int) (int, error) {
	policy := a.policy.Load()
	if policy == nil {
		return a.Device.Write(bufs, offset)
	}

	// filtered stays nil while everything passes, which is the common case and
	// keeps this path allocation free.
	var filtered [][]byte
	drops := 0
	for i, buf := range bufs {
		if a.permit(policy, buf, offset) {
			if filtered != nil {
				filtered = append(filtered, buf)
			}
			continue
		}
		if filtered == nil {
			filtered = make([][]byte, i, len(bufs))
			copy(filtered, bufs[:i])
		}
		drops++
	}
	if drops > 0 {
		a.noteDrops(drops)
	}
	if filtered == nil {
		return a.Device.Write(bufs, offset)
	}
	if len(filtered) == 0 {
		// Everything was denied. Reporting success is correct: the packets were
		// consumed as intended, the device only inspects the error.
		return 0, nil
	}
	return a.Device.Write(filtered, offset)
}

func (a *aclTUN) permit(policy *aclPolicy, buf []byte, offset int) bool {
	if offset > len(buf) {
		return false
	}
	src, dst, ok := packetAddrs(buf[offset:])
	if !ok {
		return false
	}
	// The source address is the peer's tunnel IP, so its lease tells us which
	// network the packet belongs to. An address with no lease has no network
	// and is denied rather than sent through unfiltered.
	groupID, known := a.devices.GroupIDByIP(src)
	if !known {
		return false
	}
	return policy.allows(groupID, dst)
}

// packetAddrs extracts the source and destination address of an IPv4 or IPv6
// packet. Truncated packets and unknown versions report false.
func packetAddrs(pkt []byte) (src, dst netip.Addr, ok bool) {
	if len(pkt) < 1 {
		return src, dst, false
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return src, dst, false
		}
		return netip.AddrFrom4([4]byte(pkt[12:16])), netip.AddrFrom4([4]byte(pkt[16:20])), true
	case 6:
		if len(pkt) < 40 {
			return src, dst, false
		}
		return netip.AddrFrom16([16]byte(pkt[8:24])), netip.AddrFrom16([16]byte(pkt[24:40])), true
	default:
		return src, dst, false
	}
}

// noteDrops counts every denied packet but logs at most once per interval, so a
// blocked scan cannot turn into a log flood.
func (a *aclTUN) noteDrops(n int) {
	total := a.dropped.Add(uint64(n))
	now := time.Now().UnixNano()
	last := a.lastLog.Load()
	if now-last < int64(aclDropLogInterval) {
		return
	}
	if !a.lastLog.CompareAndSwap(last, now) {
		return
	}
	log.WithField("dropped_total", total).Info("[DynamicGuard] ACL denied packets")
}
