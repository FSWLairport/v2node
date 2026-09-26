package dynamicguard

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
)

// AmneziaParams 是 per-node 生成的 AmneziaWG 抗 DPI 参数。
//
// 服务端启动时随机生成一组，用途有二：
//  1. 配置本机 amneziawg-go 设备（IpcSet），使其按这组 magic header / junk
//     规则收发握手包；
//  2. 通过 DG01 ServerReply 加密下发给客户端，客户端据此配置自己的 amnezia
//     设备后再发起 WireGuard 握手。
//
// 之所以只能 per-node（每个服务端实例一组、进程生命周期内恒定），是因为
// amneziawg-go 把 MessageInitiationType 等 magic header 实现为「包级全局
// 变量」（device.go handlePostConfig 把配置赋给全局 var），同一进程内多
// 个 device 无法各自持有不同的 magic header。per-link 须 patch amnezia 内
// 核，不在本方案范围。
type AmneziaParams struct {
	Jc   int    // junk_packet_count
	Jmin int    // junk_packet_min_size
	Jmax int    // junk_packet_max_size
	S1   int    // init_packet_junk_size
	S2   int    // response_packet_junk_size
	H1   uint32 // init_packet_magic_header
	H2   uint32 // response_packet_magic_header
	H3   uint32 // underload_packet_magic_header
	H4   uint32 // transport_packet_magic_header
}

const (
	// amnezia 握手包头部固定大小（device.go: MessageInitiationSize=148,
	// MessageResponseSize=92）。s1/s2 是分别 prepend 到 init/response 包前
	// 的 junk 字节数，约束为 148+s1 != 92+s2（见 handlePostConfig L744）。
	wgInitHeaderSize     = 148
	wgResponseHeaderSize = 92

	// "DG01" 魔数（{0x44,0x47,0x30,0x31}）作为 uint32 的两种字节序解读。
	// amneziawg-go 按「小端」写握手包首 4 字节（send.go: binary.LittleEndian
	// .PutUint32 / binary.Write(LittleEndian)），故 H1-H4 必须避开这两个值，
	// 否则该 amnezia 握手包首 4 字节会等于 "DG01"，被 readLoop 的
	// IsDynamicGuardPacket 误判为 DG01 控制包而错误分流。
	dgMagicLEUint32 uint32 = 0x31304744 // 小端解读 = 825257796（真正会碰撞的值）
	dgMagicBEUint32 uint32 = 0x44473031 // 大端解读 = 1145389873（一并规避，零成本）

	// 参数生成区间（远小于 MTU 预算，确保 148+s1 / 92+s2 / jmax 均 << MTU）。
	paramJunkMinFloor = 16
	paramJunkMaxCeil  = 150
	paramJcMin        = 4
	paramJcMax        = 12
	paramJminMin      = 8
	paramJminMax      = 64
	paramJmaxExtraMin = 16
	paramJmaxExtraMax = 128
)

var (
	sharedParamsOnce sync.Once
	sharedParams     AmneziaParams
	sharedParamsErr  error
)

// SharedAmneziaParams 返回「进程级唯一」的一组 AmneziaWG 参数（首次调用时生成，
// 之后复用）。
//
// 必须进程级共享而非每个 DGServer 各自生成：amneziawg-go 把 magic header
// （MessageInitiationType 等）与 packetSizeToMsgType 实现为「包级全局变量」
// （device.go handlePostConfig 赋值给全局 var）。同一进程内若启动多个
// dynamicguard 节点，后启动者的 IpcSet 会覆盖全局 magic，而先启动节点的
// handler 仍按构造时复制的旧参数下发给客户端，造成「服务端按新全局解包、
// 客户端按旧参数发包」的不一致，数据面握手必然失败。
//
// 共享同一组后，变量性仍为 per-process（不同部署/进程拥有不同签名），满足
// 「校园网计费网关静态签名匹配」的威胁模型。
func SharedAmneziaParams() (AmneziaParams, error) {
	sharedParamsOnce.Do(func() {
		sharedParams, sharedParamsErr = GenerateAmneziaParams()
	})
	return sharedParams, sharedParamsErr
}

// GenerateAmneziaParams 生成一组满足 amneziawg-go handlePostConfig 全部校验
// 约束的随机参数：
//   - H1-H4：均 > 4（否则 amnezia 回退默认 1/2/3/4）、四者互异（否则
//     handlePostConfig 报 "magic headers should differ"）、避开 DG01 魔数；
//   - s1/s2：满足 148+s1 != 92+s2（init/response 包尺寸必须可区分）；
//   - jmin <= jmax；
//   - 所有尺寸远小于 MaxSegmentSize 与路径 MTU。
//
// 注意：这些值是「混淆参数」而非密钥材料，randIntRange 的取模偏差对其安全
// 目标无影响。真正的前向保密由 WireGuard 数据面握手提供。
func GenerateAmneziaParams() (AmneziaParams, error) {
	var p AmneziaParams

	// H1-H4：4 个互异、>4、避开 DG01 的随机 uint32。
	headers := make([]uint32, 0, 4)
	seen := make(map[uint32]struct{}, 4)
	for len(headers) < 4 {
		h, err := randUint32()
		if err != nil {
			return p, err
		}
		if h <= 4 || h == dgMagicLEUint32 || h == dgMagicBEUint32 {
			continue
		}
		if _, dup := seen[h]; dup {
			continue
		}
		seen[h] = struct{}{}
		headers = append(headers, h)
	}
	p.H1, p.H2, p.H3, p.H4 = headers[0], headers[1], headers[2], headers[3]

	var err error

	// s1：init 包 junk 前缀。
	if p.S1, err = randIntRange(paramJunkMinFloor, paramJunkMaxCeil); err != nil {
		return p, err
	}
	// s2：response 包 junk 前缀，强制 148+s1 != 92+s2。
	for {
		if p.S2, err = randIntRange(paramJunkMinFloor, paramJunkMaxCeil); err != nil {
			return p, err
		}
		if wgInitHeaderSize+p.S1 != wgResponseHeaderSize+p.S2 {
			break
		}
	}

	// jc / jmin / jmax（保证 jmin <= jmax）。
	if p.Jc, err = randIntRange(paramJcMin, paramJcMax); err != nil {
		return p, err
	}
	if p.Jmin, err = randIntRange(paramJminMin, paramJminMax); err != nil {
		return p, err
	}
	extra, err := randIntRange(paramJmaxExtraMin, paramJmaxExtraMax)
	if err != nil {
		return p, err
	}
	p.Jmax = p.Jmin + extra

	return p, nil
}

// IpcLines 返回 amneziawg-go IpcSet 所需的参数配置块（不含 private_key，由
// 调用方拼接）。字段顺序与 UAPI 解析无关，逐行 key=value。
func (p AmneziaParams) IpcLines() string {
	return fmt.Sprintf(
		"jc=%d\njmin=%d\njmax=%d\ns1=%d\ns2=%d\nh1=%d\nh2=%d\nh3=%d\nh4=%d\n",
		p.Jc, p.Jmin, p.Jmax, p.S1, p.S2, p.H1, p.H2, p.H3, p.H4,
	)
}

// randUint32 返回一个加密随机 uint32。
func randUint32() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b[:]), nil
}

// randIntRange 返回 [min, max] 闭区间内的随机整数。
func randIntRange(min, max int) (int, error) {
	if max < min {
		min, max = max, min
	}
	span := uint32(max - min + 1)
	v, err := randUint32()
	if err != nil {
		return 0, err
	}
	return min + int(v%span), nil
}
