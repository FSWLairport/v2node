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

// aclPolicy holds the compiled per-network policies. The zero value fails
// closed; customer isolation applies even to allow-all networks.
type aclPolicy struct {
	networks map[int]networkACL
	// node is the node's own table, checked on its own; nil means none.
	node         *networkACL
	orgs         map[int]int // network -> customer, from network_orgs
	reservations map[int]netip.Prefix
	// singleTenant is a panel without customers (stock v2board): every network
	// is one customer and a network without an ACL entry is unfiltered.
	singleTenant bool
}

// newACLPolicy compiles the panel's ACL; see isSingleTenant for panels
// without customers. nodeACL, when present, is the node's own policy and is
// checked separately from every network's.
func newACLPolicy(acl map[string]DGACL, nodeACL *DGACL, networkOrgs map[string]int, tenantPools map[string]string) *aclPolicy {
	networks := make(map[int]networkACL, len(acl))
	for groupStr, cfg := range acl {
		groupID, err := strconv.Atoi(groupStr)
		if err != nil {
			log.Warnf("[DynamicGuard] ACL: skipping non-numeric network key %q", groupStr)
			continue
		}
		networks[groupID] = compileACL("network="+groupStr, cfg)
	}
	p := &aclPolicy{networks: networks, orgs: map[int]int{}, reservations: map[int]netip.Prefix{}, singleTenant: isSingleTenant(networkOrgs, tenantPools)}
	if nodeACL != nil {
		node := compileACL("node", *nodeACL)
		p.node = &node
	}
	for group, org := range networkOrgs {
		if id, err := strconv.Atoi(group); err == nil && org > 0 {
			p.orgs[id] = org
		}
	}
	for org, cidr := range tenantPools {
		id, err := strconv.Atoi(org)
		prefix, pe := netip.ParsePrefix(cidr)
		if err != nil || pe != nil || id <= 0 {
			return &aclPolicy{}
		}
		p.reservations[id] = prefix.Masked()
	}
	return p
}

// compileACL turns one panel ACL into its matcher. Anything other than
// "allow" is treated as deny, and an invalid CIDR denies the whole table: an
// unrecognised or corrupted value must never silently widen access.
func compileACL(label string, cfg DGACL) networkACL {
	defaultAllow := cfg.Default == aclActionAllow
	if cfg.Default != aclActionAllow && cfg.Default != aclActionDeny {
		log.Warnf("[DynamicGuard] ACL %s: unknown default %q, treating as deny", label, cfg.Default)
	}
	rules := make([]aclRule, 0, len(cfg.Rules))
	for _, r := range cfg.Rules {
		prefix, err := netip.ParsePrefix(r.CIDR)
		if err != nil {
			// The panel validates CIDRs, so this only happens on a corrupted
			// payload. Deny the whole table rather than dropping a deny rule.
			log.Errorf("[DynamicGuard] ACL %s: invalid CIDR %q, denied: %v", label, r.CIDR, err)
			return networkACL{}
		}
		allow := r.Action == aclActionAllow
		if r.Action != aclActionAllow && r.Action != aclActionDeny {
			log.Warnf("[DynamicGuard] ACL %s: unknown action %q for %s, treating as deny", label, r.Action, r.CIDR)
		}
		rules = append(rules, aclRule{prefix: prefix.Masked(), allow: allow})
	}
	log.Infof("[DynamicGuard] ACL %s default=%s rules=%d", label, cfg.Default, len(rules))
	return networkACL{rules: rules, defaultAllow: defaultAllow}
}

// permits is one table's verdict: the first rule containing dst decides.
func (n networkACL) permits(dst netip.Addr) bool {
	for i := range n.rules {
		if n.rules[i].prefix.Contains(dst) {
			return n.rules[i].allow
		}
	}
	return n.defaultAllow
}

// allows reports whether a client of the given network may reach dst: the
// node's own table, when there is one, and the network's must both allow it.
// Missing network policy denies access unless the panel has no customers.
func (p *aclPolicy) allows(groupID int, dst netip.Addr) bool {
	if p.node != nil && !p.node.permits(dst) {
		return false
	}
	n, ok := p.networks[groupID]
	if !ok {
		return p.singleTenant
	}
	return n.permits(dst)
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
	// flows observes what this device forwards. It shares the Write path with
	// the ACL because that is the only place a decapsulated packet exists.
	flows   *flowLog
	dropped atomic.Uint64
	lastLog atomic.Int64 // unix nano of the last drop log, rate limits the hot path
}

const aclDropLogInterval = 30 * time.Second

func newACLTUN(inner tun.Device, devices *DeviceTable, policy *aclPolicy, accessLog bool) *aclTUN {
	a := &aclTUN{Device: inner, devices: devices, flows: newFlowLog(accessLog)}
	a.SetPolicy(policy)
	return a
}

// SetPolicy swaps the whole policy atomically; the data path never locks.
func (a *aclTUN) SetPolicy(p *aclPolicy) {
	if p == nil {
		p = &aclPolicy{}
	}
	a.policy.Store(p)
}

// Dropped returns the number of packets denied so far.
func (a *aclTUN) Dropped() uint64 { return a.dropped.Load() }

func (a *aclTUN) Write(bufs [][]byte, offset int) (int, error) {
	policy := a.policy.Load()
	logging := a.flows.enabled.Load()

	// filtered stays nil while everything passes, which is the common case and
	// keeps this path allocation free.
	var filtered [][]byte
	drops := 0
	var now time.Time
	if logging {
		now = time.Now()
	}
	for i, buf := range bufs {
		if policy != nil && a.permit(policy, buf, offset) {
			// Only forwarded packets are recorded: a denied one never reached
			// anything, and logging it would describe a connection that did not
			// happen.
			if logging && offset <= len(buf) {
				a.flows.observe(buf[offset:], a.devices, now)
			}
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
	if offset < 0 || offset > len(buf) {
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
	// The customer follows from the leased network, never from the packet.
	org, owned := policy.orgs[groupID]
	if !owned && !policy.singleTenant {
		return false
	}
	if targetGroup, known := a.devices.GroupIDByIP(dst); known && policy.orgs[targetGroup] != org {
		return false
	}
	for owner, prefix := range policy.reservations {
		if owner != org && prefix.Contains(dst) {
			return false
		}
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
