package dynamicguard

import (
	"fmt"
	"net/netip"
	"strconv"
	"sync"
)

// isSingleTenant reports a panel without customers (stock v2board): it sends
// neither network_orgs nor tenant_pools, and the node is then one customer.
// Anything customer-shaped keeps the strict mode.
func isSingleTenant(networkOrgs map[string]int, tenantPools map[string]string) bool {
	return len(networkOrgs) == 0 && len(tenantPools) == 0
}

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
	singleTenant := isSingleTenant(settings.NetworkOrgs, settings.TenantPools)
	for group, cidr := range settings.IPPools {
		id, err := strconv.Atoi(group)
		org := settings.NetworkOrgs[group]
		if err != nil || id <= 0 || (!singleTenant && org <= 0) {
			return nil, nil, fmt.Errorf("missing network_orgs owner for network %q", group)
		}
		pool, err := NewIPPool(cidr)
		if err != nil {
			return nil, nil, err
		}
		pool.mu, pool.used = mu, used
		if own, ok := reservations[org]; ok && (!own.Contains(pool.network.Addr()) || pool.network.Bits() < own.Bits()) {
			return nil, nil, fmt.Errorf("network %s outside tenant pool", group)
		}
		for owner, prefix := range reservations {
			if owner != org {
				pool.ReservePrefix(prefix)
			}
		}
		pools[id] = pool
		roots[pool.network.String()] = pool
	}
	return pools, roots, nil
}
