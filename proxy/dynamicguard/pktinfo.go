package dynamicguard

import (
	"net"
	"net/netip"
	"sync"

	"golang.org/x/net/ipv4"
)

// srcOOBCache 缓存已构建的 OOB 数据，避免每包重复 Marshal。
// 服务器通常只有少量本地 IP，entry 数量极少，永不淘汰。
var srcOOBCache sync.Map // netip.Addr -> []byte

// pktInfoOOBSize 是 ipv4 ControlMessage（含 FlagDst）所需的 OOB 缓冲区大小
var pktInfoOOBSize = len(ipv4.NewControlMessage(ipv4.FlagDst))

// enablePktInfo 在 UDP socket 上启用 IP_PKTINFO，使 ReadMsgUDP 的 OOB 中包含本地目的 IP。
// 这是实现源进源出的前提：收包时获取客户端连入的本机 IP，回包时指定同一 IP 作为源地址。
func enablePktInfo(udpConn *net.UDPConn) error {
	p := ipv4.NewPacketConn(udpConn)
	return p.SetControlMessage(ipv4.FlagDst, true)
}

// parseLocalAddr 从 ReadMsgUDP 返回的 OOB 数据中解析本地目的 IP（客户端连入时到达的本机 IP）
func parseLocalAddr(oob []byte, oobn int) netip.Addr {
	if oobn == 0 {
		return netip.Addr{}
	}
	cm := &ipv4.ControlMessage{}
	if err := cm.Parse(oob[:oobn]); err != nil {
		return netip.Addr{}
	}
	if cm.Dst == nil {
		return netip.Addr{}
	}
	if ip4 := cm.Dst.To4(); ip4 != nil {
		addr, ok := netip.AddrFromSlice(ip4)
		if ok {
			return addr
		}
	}
	addr, ok := netip.AddrFromSlice(cm.Dst)
	if ok {
		return addr
	}
	return netip.Addr{}
}

// buildSrcOOB 构造指定源 IP 的 OOB 数据（用于 WriteMsgUDP/WriteMsgUDPAddrPort）。
// 当 src 无效或为全零地址时返回 nil，让内核自行选择源 IP。
// 结果按 IP 地址缓存，消除热路径上的逐包堆分配。
func buildSrcOOB(src netip.Addr) []byte {
	if !src.IsValid() || src.IsUnspecified() {
		return nil
	}
	if cached, ok := srcOOBCache.Load(src); ok {
		return cached.([]byte)
	}
	cm := &ipv4.ControlMessage{
		Src: src.AsSlice(),
	}
	oob := cm.Marshal()
	srcOOBCache.Store(src, oob)
	return oob
}

// writeUDPWithSrc 使用指定源 IP 发送 UDP 数据。
// 如果 localAddr 无效则回退到普通 WriteToUDP。
func writeUDPWithSrc(udpConn *net.UDPConn, data []byte, dst *net.UDPAddr, localAddr netip.Addr) (int, error) {
	oob := buildSrcOOB(localAddr)
	if oob != nil {
		n, _, err := udpConn.WriteMsgUDP(data, oob, dst)
		return n, err
	}
	return udpConn.WriteToUDP(data, dst)
}
