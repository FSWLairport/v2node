package dynamicguard

import (
	"net/netip"
	"sync"
)

// IPPool 管理一个 CIDR 范围内的 IP 地址分配
type IPPool struct {
	network netip.Prefix
	base    netip.Addr // 网络地址 + 1 (跳过网络地址)
	size    uint32     // 可用地址数
	bitmap  []uint64   // 位图追踪已分配地址
	mu      sync.Mutex
}

// NewIPPool 从 CIDR 字符串创建 IP 地址池
func NewIPPool(cidr string) (*IPPool, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, err
	}
	prefix = prefix.Masked() // 规范化

	var size uint32
	bits := prefix.Bits()
	if prefix.Addr().Is4() {
		if bits >= 31 {
			return nil, errIPPoolExhausted
		}
		// /24 = 256 - 2 = 254 可用 (去掉网络地址和广播地址)
		size = (1 << (32 - bits)) - 2
	} else {
		hostBits := 128 - bits
		if hostBits > 24 {
			// 限制 IPv6 池大小以避免内存爆炸
			size = 1 << 24
		} else if hostBits <= 1 {
			return nil, errIPPoolExhausted
		} else {
			size = (1 << hostBits) - 2
		}
	}

	// 位图: 每个 uint64 追踪 64 个地址
	bitmapLen := (size + 63) / 64

	// base = 网络地址 + 1
	base := prefix.Addr().Next()

	return &IPPool{
		network: prefix,
		base:    base,
		size:    size,
		bitmap:  make([]uint64, bitmapLen),
	}, nil
}

// Allocate 分配最低可用 IP 地址
func (p *IPPool) Allocate() (netip.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for i := range p.bitmap {
		if p.bitmap[i] == ^uint64(0) {
			continue // 全部已分配
		}
		// 找到第一个为 0 的 bit
		for bit := 0; bit < 64; bit++ {
			idx := uint32(i*64 + bit)
			if idx >= p.size {
				return netip.Addr{}, errIPPoolExhausted
			}
			if p.bitmap[i]&(1<<bit) == 0 {
				p.bitmap[i] |= 1 << bit
				return p.addrAtIndex(idx), nil
			}
		}
	}
	return netip.Addr{}, errIPPoolExhausted
}

// Reserve 预留指定 IP 地址（老设备复用）
func (p *IPPool) Reserve(ip netip.Addr) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	idx, ok := p.indexOf(ip)
	if !ok {
		return false
	}
	word := idx / 64
	bit := idx % 64
	if p.bitmap[word]&(1<<bit) != 0 {
		return false // 已被占用
	}
	p.bitmap[word] |= 1 << bit
	return true
}

// Release 释放 IP 地址
func (p *IPPool) Release(ip netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()

	idx, ok := p.indexOf(ip)
	if !ok {
		return
	}
	word := idx / 64
	bit := idx % 64
	p.bitmap[word] &^= 1 << bit
}

// Contains 检查 IP 是否在池范围内
func (p *IPPool) Contains(ip netip.Addr) bool {
	return p.network.Contains(ip) && ip != p.network.Addr()
}

// PrefixBits 返回网段的前缀长度
func (p *IPPool) PrefixBits() int {
	return p.network.Bits()
}

// addrAtIndex 返回指定索引处的 IP 地址（O(1) 算术计算）
func (p *IPPool) addrAtIndex(idx uint32) netip.Addr {
	if p.base.Is4() {
		b := p.base.As4()
		baseInt := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		result := baseInt + idx
		return netip.AddrFrom4([4]byte{
			byte(result >> 24),
			byte(result >> 16),
			byte(result >> 8),
			byte(result),
		})
	}
	// IPv6: 仅偏移低 4 字节
	b := p.base.As16()
	low := uint32(b[12])<<24 | uint32(b[13])<<16 | uint32(b[14])<<8 | uint32(b[15])
	result := low + idx
	var out [16]byte
	copy(out[:12], b[:12])
	out[12] = byte(result >> 24)
	out[13] = byte(result >> 16)
	out[14] = byte(result >> 8)
	out[15] = byte(result)
	return netip.AddrFrom16(out)
}

// indexOf 返回 IP 地址在位图中的索引
func (p *IPPool) indexOf(ip netip.Addr) (uint32, bool) {
	if !p.network.Contains(ip) {
		return 0, false
	}

	// 计算偏移量
	if ip.Is4() {
		baseBytes := p.base.As4()
		ipBytes := ip.As4()
		baseInt := uint32(baseBytes[0])<<24 | uint32(baseBytes[1])<<16 | uint32(baseBytes[2])<<8 | uint32(baseBytes[3])
		ipInt := uint32(ipBytes[0])<<24 | uint32(ipBytes[1])<<16 | uint32(ipBytes[2])<<8 | uint32(ipBytes[3])
		if ipInt < baseInt {
			return 0, false
		}
		idx := ipInt - baseInt
		if idx >= p.size {
			return 0, false
		}
		return idx, true
	}

	// IPv6: 只支持低 32 位偏移
	baseBytes := p.base.As16()
	ipBytes := ip.As16()
	// 比较前 12 字节必须相同
	for i := 0; i < 12; i++ {
		if baseBytes[i] != ipBytes[i] {
			return 0, false
		}
	}
	baseInt := uint32(baseBytes[12])<<24 | uint32(baseBytes[13])<<16 | uint32(baseBytes[14])<<8 | uint32(baseBytes[15])
	ipInt := uint32(ipBytes[12])<<24 | uint32(ipBytes[13])<<16 | uint32(ipBytes[14])<<8 | uint32(ipBytes[15])
	if ipInt < baseInt {
		return 0, false
	}
	idx := ipInt - baseInt
	if idx >= p.size {
		return 0, false
	}
	return idx, true
}
