package dynamicguard

import (
	"net/netip"
	"strconv"
	"sync/atomic"

	"github.com/amnezia-vpn/amneziawg-go/tun"
	"github.com/wyx2685/v2node/common/rate"
)

type userBandwidth struct {
	mbps   int
	bucket *rate.DynamicBucket
}
type bandwidthTUN struct {
	tun.Device
	devices       *DeviceTable
	orgs          map[int]int
	organizations *rate.OrganizationLimiter
	hasOrgLimits  bool
	users         atomic.Pointer[map[int]userBandwidth]
}

func newBandwidthTUN(inner tun.Device, devices *DeviceTable, orgs map[string]int, limits map[int]rate.BandwidthLimit) *bandwidthTUN {
	b := &bandwidthTUN{Device: inner, devices: devices, orgs: make(map[int]int, len(orgs)), organizations: rate.NewOrganizationLimiter(limits)}
	for group, org := range orgs {
		if id, err := strconv.Atoi(group); err == nil {
			b.orgs[id] = org
		}
	}
	for _, limit := range limits {
		if limit.UpMbps > 0 || limit.DownMbps > 0 {
			b.hasOrgLimits = true
		}
	}
	empty := make(map[int]userBandwidth)
	b.users.Store(&empty)
	return b
}

func (b *bandwidthTUN) updateUsers(users []*UserEntry) {
	old := *b.users.Load()
	next := make(map[int]userBandwidth)
	for _, user := range users {
		if user.SpeedLimit <= 0 {
			continue
		}
		limit, exists := old[user.UserID]
		if !exists || limit.mbps != user.SpeedLimit {
			limit = userBandwidth{mbps: user.SpeedLimit, bucket: rate.NewBandwidthBucket(user.SpeedLimit)}
		}
		next[user.UserID] = limit
	}
	b.users.Store(&next)
}

func (b *bandwidthTUN) allow(packet []byte, upload bool) bool {
	users := *b.users.Load()
	if !b.hasOrgLimits && len(users) == 0 {
		return true
	}
	src, dst, ok := packetAddrs(packet)
	if !ok {
		return false
	}
	ip := src
	if !upload {
		ip = dst
	}
	user, group, ok := b.devices.bandwidthScopeByIP(ip)
	if !ok {
		return false
	}
	org, owned := b.orgs[group]
	if b.hasOrgLimits && !owned {
		return false
	}
	up, down := b.organizations.Buckets(org)
	bucket := down
	if upload {
		bucket = up
	}
	return rate.AllowBytes(bucket, len(packet)) && rate.AllowBytes(users[user].bucket, len(packet))
}

func (b *bandwidthTUN) Write(bufs [][]byte, offset int) (int, error) {
	var filtered [][]byte
	for i, packet := range bufs {
		if offset >= 0 && offset <= len(packet) && b.allow(packet[offset:], true) {
			if filtered != nil {
				filtered = append(filtered, packet)
			}
		} else if filtered == nil {
			filtered = append(make([][]byte, 0, len(bufs)), bufs[:i]...)
		}
	}
	if filtered == nil {
		return b.Device.Write(bufs, offset)
	}
	if len(filtered) == 0 {
		return 0, nil
	}
	return b.Device.Write(filtered, offset)
}

func (b *bandwidthTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := b.Device.Read(bufs, sizes, offset)
	kept := 0
	for i := 0; i < n; i++ {
		if b.allow(bufs[i][offset:offset+sizes[i]], false) {
			if kept != i {
				copy(bufs[kept][offset:], bufs[i][offset:offset+sizes[i]])
			}
			sizes[kept] = sizes[i]
			kept++
		}
	}
	return kept, err
}

// The lease table owns scope; a packet cannot choose its organization.
func (dt *DeviceTable) bandwidthScopeByIP(ip netip.Addr) (user, group int, ok bool) {
	dt.mu.RLock()
	defer dt.mu.RUnlock()
	entry, ok := dt.byIP[ip]
	if !ok || entry.Status != DeviceStatusActive {
		return 0, 0, false
	}
	return entry.UserID, entry.GroupID, true
}
