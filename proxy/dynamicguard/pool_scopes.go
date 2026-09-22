package dynamicguard

import (
	"fmt"
	"net/netip"
	"strconv"
	"sync"
)

func buildIPPools(settings *DGSettings) (map[int]*IPPool, map[string]*IPPool, error) {
	pools := map[int]*IPPool{}
	roots := map[string]*IPPool{}
	used := map[netip.Addr]*IPPool{}
	mu := &sync.Mutex{}
	reservations := map[int]netip.Prefix{}
	for org, cidr := range settings.TenantPools {
		id, err := strconv.Atoi(org)
		prefix, parseErr := netip.ParsePrefix(cidr)
		if err != nil || id <= 0 || parseErr != nil {
			return nil, nil, fmt.Errorf("invalid tenant pool %q: %q", org, cidr)
		}
		for _, other := range reservations {
			if prefix.Overlaps(other) {
				return nil, nil, fmt.Errorf("overlapping tenant pools")
			}
		}
		reservations[id] = prefix.Masked()
	}
	for group, cidr := range settings.IPPools {
		id, err := strconv.Atoi(group)
		cfg, ok := settings.ACL[group]
		if err != nil || id <= 0 || !ok || cfg.OrgID <= 0 {
			return nil, nil, fmt.Errorf("missing trusted owner for network %q", group)
		}
		pool, err := NewIPPool(cidr)
		if err != nil {
			return nil, nil, err
		}
		pool.mu, pool.used = mu, used
		if own, ok := reservations[cfg.OrgID]; ok && (!own.Contains(pool.network.Addr()) || pool.network.Bits() < own.Bits()) {
			return nil, nil, fmt.Errorf("network %s outside tenant pool", group)
		}
		for org, prefix := range reservations {
			if org != cfg.OrgID {
				pool.ReservePrefix(prefix)
			}
		}
		pools[id] = pool
		roots[pool.network.String()] = pool
	}
	return pools, roots, nil
}
