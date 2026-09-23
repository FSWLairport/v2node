# DynamicGuard：DG01 控制面与 AmneziaWG 数据面

本文是 sing-box 客户端和 v2node 服务端共同维护的实现约定。控制报文使用 magic `DG01`、
版本字节 `0x01`，本文不改变报文格式或凭据设计。数据面使用 AmneziaWG，不是无混淆的原版
WireGuard。两份仓库中的本文保持一致。

## 1. 配置与身份

客户端需要服务端 UDP 地址、32 字节 `user_key` 和服务端 WireGuard 公钥。首次启动生成
16 字节 `device_id` 和 32 字节 WireGuard 私钥，使用 X25519 基点计算设备公钥。
每次 DG 握手另外生成一对临时 X25519 密钥和 16 字节 `client_nonce`。

服务端按用户密钥查用户，按 `(user_id, device_id)` 查设备。同一设备的 WireGuard 公钥
不可在线替换；设备状态丢失后应通过管理端处理旧记录。v2node 当前从凭据 UUID 字符串的
SHA-256 派生 `user_key`；客户端配置接收已经派生的 32 字节值，而不是直接填写 UUID。

面板用户列表可为一条凭据带上 `dg_device_id` + `wg_static_pub`，把它钉在唯一一台设备上
（App 注册的那台，或云端给盒子签发的身份）：ClientInit 的 `device_id`/`wg_static_pub`
对不上就静默丢弃，泄露的 `user_key` 也注册不了新设备。两个字段都缺是没钉，任何设备都能
以新设备注册（只受 `device_limit` 约束）；给了但解析不了则这条凭据拒绝所有设备。

客户端 `state_path` 保存设备 ID 和私钥，JSON 格式如下，写入权限为 0600：

```json
{"device_id":"<16-byte-hex>","private_key":"<32-byte-base64>"}
```

显式配置值优先于状态文件。两项都显式配置时不读取文件；未配置持久化也未显式指定的字段
每次启动重新生成，会被服务端视为新的设备身份。设备 metadata 不在 DG 握手内传输，若业务
需要，应在隧道建立后通过业务通道上报。

## 2. ClientInit

```text
偏移       长度     字段
0          4        magic = DG01
4          1        version = 1
5          32       user_key
37         16       device_id
53         32       client_eph_pub
85         32       wg_static_pub
117        16       client_nonce
133        1        cookie_len = 0 或 32
134        0/32     cookie
134/166    1        pow_nonce_len = 0 或 8
135/167    0/8      pow_nonce
末尾       32       mac
```

无 Cookie/PoW 时共 167 字节，有 Cookie 且无 PoW 时为 199 字节，两者都有时为 207 字节。
解析器验证每个长度及报文末尾位置，不允许任意尾随字节。

```text
mac_key = HKDF-SHA256(user_key, client_nonce, "dynamicguard-mac-v1", 32)
mac = HMAC-SHA256(mac_key, 从 magic 到 pow_nonce 末尾的全部字节)
```

`user_key` 在当前 ClientInit 和 ClientPing 中是明文携带的认证材料。这项现有设计没有在
纯实现修复中改变，不能把附加 MAC 描述为防止观察者获得用户凭据的保护，也不能把它当成
公开标识符记录到日志。

## 3. ServerReply

```text
magic(4) | version(1) | server_nonce(16) | ciphertext(变长，包含 16 字节 AEAD tag)
```

密钥派生：

```text
dh = X25519(client_eph_priv, server_wg_pub)
   = X25519(server_wg_priv, client_eph_pub)
ikm = dh || user_key
salt = client_nonce || server_nonce
reply_key = HKDF-SHA256(ikm, salt, "dynamicguard-reply-v1", 32)
```

使用 ChaCha20-Poly1305，nonce 为 12 字节零，AAD 为前 21 字节报文头。每个新响应使用随机
`server_nonce`；重传命中幂等缓存时重发原响应。

解密后的载荷按以下顺序排列：

| 字段 | 长度 | 编码 |
| --- | --- | --- |
| address_family | 1 | 4 或 6 |
| assigned_ip | 4 或 16 | 原始地址字节 |
| prefix_len | 1 | 前缀长度 |
| lease_ttl | 4 | uint32 小端，秒 |
| h1、h2、h3、h4 | 16 | 四个 uint32 小端 |
| s1、s2 | 4 | 两个 uint16 小端 |
| jc、jmin、jmax | 6 | 三个 uint16 小端 |

包含 26 字节混淆参数后的 ServerReply 大小：IPv4 为 73 字节，IPv6 为 85 字节。
客户端必须先成功解密配置参数，再创建 AmneziaWG 设备并发起数据面握手。

## 4. Cookie 与 PoW

CookieReply：

```text
magic(4) | version(1) | type=0xFE(1) | cookie(32) | pow_difficulty(1)
```

共 39 字节，未加密。服务端在 Cookie 保护启用、并发 ClientInit 超过阈值 1000 且请求没有
Cookie 时发挑战；带 Cookie 的请求按当前策略验证。失败静默丢弃。

服务端 Cookie 使用 HMAC-SHA256，输入为规范化的源 IP 和 uint16 大端源端口；密钥约每
120 秒轮换一次，验证接受当前及前一个密钥。IPv4-mapped IPv6 规范化成四字节 IPv4。

**客户端必须在整个 DG 握手中复用同一个 UDP socket**，包括普通重传和 Cookie 后的重传。
关闭原 socket 后重拨通常改变源端口，使已经收到的 Cookie 失效。

PoW 要求：

```text
SHA256(cookie || pow_nonce) 的前 difficulty 个比特为零
```

`pow_nonce` 为 8 字节。实现的资源边界如下：

| 项目 | 限制 |
| --- | --- |
| 服务端可配置 difficulty | 0..24，超过范围启动失败 |
| 客户端接受 difficulty | 0..24，超过范围中止握手 |
| 单次 PoW 计算 | 最多 8 秒，调用方取消优先 |
| 检查取消 | 计算开始时及每 4096 次尝试 |
| 单次 DG 握手总时限 | 30 秒，调用方更早的 deadline 优先 |
| 总发送次数 | 最多 5 次，Cookie 挑战也占用次数 |
| 初始收发超时 | 500 ms |
| 收发失败后的退避 | 乘 2，单次最多 8 秒 |

difficulty=0 时只回传 Cookie，不发送 PoW nonce。没有 Cookie 挑战且持续收包超时时，五次
等待合计约 15.5 秒。收到挑战不会递归重置重试次数或总时限；最后一次发送后收到挑战直接
失败。取消通过关闭握手 socket 终止网络等待。

## 5. 服务端处理与幂等

1. 校验报文格式、版本和长度，按 `user_key` 查用户。
2. 必要时校验 Cookie、PoW，或者发送挑战。
3. 校验 ClientInit MAC。
4. 凭据钉了设备的，核对 `device_id` 与 `wg_static_pub`。
5. 查询幂等缓存。
6. 持有设备锁重新检查用户凭据，查设备、分配或复用 IP、注册 WireGuard peer。
7. 派生响应密钥，加密并发送分配结果与混淆参数。
8. 缓存已发送的响应。

缓存键为：

```text
SHA256(user_key || device_id || client_eph_pub || wg_static_pub || client_nonce)
```

缓存保留 60 秒；相同请求重发原响应。缓存绑定上述完整字段，不等同于永久设备授权。
无效凭据、MAC、Cookie、PoW、非钉住设备、撤销设备、公钥不匹配、设备超限或地址池耗尽均静默丢弃。

设备记录包含用户、设备 ID、WireGuard 公钥、分配地址、权限组、最后活跃时间以及
`active` / `disconnected` / `revoked` 状态。设备公钥和分配地址有唯一约束。活动设备重连
复用地址；已回收地址的设备重连时重新分配。

## 6. 地址池、路由与访问控制

### 6.1 面板下发字段

v2node 从节点配置 `dg_settings` 与用户名单取得以下信息，全部以面板为可信来源：

| 字段 | 键 | 值 | 必需 |
| --- | --- | --- | --- |
| `ip_pools` | Network ID（`group_id`） | CIDR | 是 |
| `network_orgs` | Network ID | 客户 `org_id` | 多租户面板必需 |
| `tenant_pools` | 客户 `org_id` | 保留 CIDR | 否，仅多租户 |
| `acl` | Network ID | `default` 与有序 `rules` | 否 |
| 用户名单 | 用户 | `group_id`、凭据、设备 pin | 是 |

Network 的客户归属只由 `network_orgs` 声明；`acl` 只描述出网策略，用户名单不携带客户。
租约属于哪个客户，由该租约所在 Network 查 `network_orgs` 得出。

### 6.2 地址池

每个 Network 是一份池视图，所有视图在当前 DG 节点内共用地址占用记录和分配锁，因此
相等、包含或部分重叠的范围都不会重复发地址；同客户 Network 段允许重叠，共享容量而非
独占配额。只有根池在隧道接口上绑定 `网络地址+1` 网关，该地址在共享占用记录中保留。
独立 DG 进程不共享租约；多个 DG 服务同一 Network 时应规划各自地址段，切换节点不保证
IP 不变。

`tenant_pools` 携带该节点全部客户保留段，包含未挂载 Network 的客户；保留段在客户之间
必须互不重叠。客户有保留段时，自己的 Network 池必须在段内；没有保留段时继承节点池，
不能自行切段。每个视图排除其他客户的保留段，即使保留段等于整个节点池，也不能给其他
客户发地址。

### 6.3 客户隔离与 ACL

节点按 `network_orgs` 与 `tenant_pools` 是否都为空区分两种面板：

- **多租户面板**（saikyo-connect-dashboard，两者至少一项非空）：`ip_pools` 的每个
  Network 都必须在 `network_orgs` 中有正数客户，否则节点启动失败。转发时，其他客户的
  活跃租约地址和保留段先行拒绝，随后才匹配本 Network 的有序目标 CIDR 规则；允许全部
  目标也不会关闭这层客户隔离。未知来源、无归属 Network、缺少 `acl` 条目全部拒绝。
- **单租户面板**（原版 v2board，两者都不下发）：整个节点视为一个客户，没有跨客户隔离。
  有 `acl` 条目的 Network 照常执行规则，没有条目的 Network 不过滤，未知来源仍然拒绝。

多租户面板若把两项都漏发，节点会按单租户运行，这一点由面板侧契约测试保证。

转发包的身份来自已认证租约，WireGuard 的源地址约束把包绑定到设备；客户端不能通过包
内容选择客户或 Network。`default` 与 `action` 只认 `allow`/`deny`，其他值按 deny 处理；
格式损坏的 CIDR 规则使该 Network 拒绝转发。ACL 仅在节点执行，不下发客户端，也不把
不同 Network 的规则合并。客户 LAN 若共享相同目标前缀及主机路由表，仍需主机侧独立
路由域；这层隔离不替代 VRF/namespace。

### 6.4 客户端路由

客户端 `routes` 控制入口流量的目标范围、系统路由及路由偏好，不是服务端授权策略。
内部 WireGuard peer 的 AllowedIPs 固定覆盖 IPv4/IPv6 默认路由，使 sing-box 显式选择该
endpoint 作为下一跳时可以访问任意目标，能否到达由节点 ACL 决定。

`system` 模式下的路由分两层，照搬 wg-quick 与上游 sing-box 各自的做法：

- 系统路由只来自 `routes`，逐条安装，等同 wg-quick 对每条非 `/0` AllowedIP 的处理：
  Linux 写入 main 表，macOS 写入非 scoped 路由，Windows 写入 metric 0 的接口路由。
  内核已有路由的前缀（本机 WAN/LAN、握手分配地址所在网段）跳过并告警，不替换；
  Windows 上别的接口已有同前缀也视为已有路由。
  `routes` 为空则不安装任何系统路由；`/0` 前缀不会被安装，整机全隧道应由 `tun` 入站的
  `auto_route` 配合路由规则完成。
- 下一跳能力不依赖系统路由：AllowedIPs 的默认路由只放在绑定到该接口的 socket 才会选中的
  位置（Linux 私有路由表，macOS IFSCOPE 路由，Windows metric 9999 的接口默认路由），
  所以路由规则可以把任意域名或地址指向该 endpoint，系统自己的默认路由不受影响。
- system 模式请开启 `route.auto_detect_interface`，或给 endpoint 配 `bind_interface` /
  `detour`，把外层 UDP socket 钉在物理网卡上。否则服务器地址若落在 `routes` 内，外层
  流量会被路由进隧道自身；启动时两者都没配会打告警，不做静默兜底。

`allowed_ips` 不是 sing-box DynamicGuard JSON 字段，旧配置应迁移到 `routes`，不能将两者
理解为相同的授权含义。

### 6.5 变更与限制

多租户部署先更新面板投影，再更新节点。配置变化触发节点重载，内存租约随之重建；用户
名单中的 Network 或设备 pin 变化会先拆除旧 peer。VIP 准入由面板过滤凭据名单，节点不从
客户端接收“VIP”声明。

目前同一设备在多个 Network 中仍使用一个 WireGuard 公钥；同一 DG 的唯一公钥约束禁止
该公钥同时注册到多个凭据。多 Network 并行场景应使用不同设备身份，同一设备的并行接入
需要后续身份协议改造，不能通过放宽公钥 pin 解决。

## 7. 租约、断开与恢复

服务端默认 `lease_ttl` 为 3600 秒，每 30 秒检查过期设备。流量统计采集时根据 WireGuard
收发增量更新 `last_seen`；过期则移除 peer、释放地址并保留 disconnected 设备记录。
ClientPing 不更新租约。建议配置客户端 PersistentKeepalive=25 秒，并让 TTL 至少覆盖三倍
保活间隔及服务端统计采集延迟。

客户端主动断开直接关闭隧道，不发送额外 Bye 消息。服务端重启会丢失内存设备表，进程级
混淆参数也可能改变；旧客户端不能仅靠重新绑定 UDP socket 恢复这些配置。

客户端恢复使用现有 ClientInit，不引入新控制消息：

- 每 5 秒读取单 peer 的 WireGuard RX/TX 与最后成功握手时间；仅业务静默不算失败。
- 已经尝试发送但没有收到认证响应时，首次握手给 45 秒，曾成功建立的 peer 给 3 分钟，
  以避开正常重密钥周期。收到认证流量或新的成功握手会恢复健康证据。
- 到达上述观察窗口后，主动请求一次普通 WireGuard 握手，再给 15 秒确认期。正常的单向
  keepalive 后接长时间空闲不会因此直接拆掉健康隧道。
- 确认无响应后，取消待完成拨号，撤下旧隧道，使用原 device_id 和私钥重新执行 DG 握手。
  新地址和混淆参数应用到新隧道，原回程绑定迁移过去。已有业务连接可能中断，由上层重连。
- DG 建立失败后自动重试，重试启动间隔至少 15 秒；关闭 endpoint 取消后台任务。

`ready` 表示本地隧道已配置，可接受业务，不保证每次远端握手已经成功；认证收发统计用于
后续故障检测。单地址和多地址 endpoint 都运行恢复检查。

本机换网时，Ready 隧道先重绑 socket，使用正常 WireGuard 漫游学习新的客户端地址；Failed
状态则立即重新尝试建立。选择入口和关闭操作与重建过程串行，重建期间禁止新业务访问已被
撤下的设备。

## 8. ClientPing 与 ServerPong

```text
ClientPing = magic(4) | version(1) | user_key(32) | nonce(16) | mac(32)
ServerPong = magic(4) | version(1) | type=0xFC(1) | nonce(16)
```

ClientPing 为 85 字节，ServerPong 为 22 字节。Ping 的 MAC 用与 ClientInit 相同的 HKDF
标签，salt 为本次 nonce，覆盖前 53 字节。Pong 明文回显 nonce，客户端匹配后计算 RTT。
Ping 按长度与 ClientInit 区分；旧服务端可直接丢弃不认识的短报文。

探测不做 DH、不分配 IP、不注册设备、不续租。服务端用有界 Ping 队列处理，过载时丢弃。
Pong 可达仅表示控制入口可达，不是 WireGuard peer 或隧道数据面的健康证明。

## 9. 多地址与运行时选择

`server`/`server_port` 和 `servers` 组成同一节点的候选列表：默认地址在前，随后按配置顺序
去重。候选必须指向同一服务端设备状态与密钥，不能借此在不同节点之间共享会话。

候选不少于两个时：

- 建立 DG 连接前并发 Ping，单轮最多 500 ms，取最快应答者；无人应答则按默认顺序选择。
- 稳态按 `probe_interval` 探测，默认 10 分钟，仅更新 RTT。
- 当前入口连续三轮不应答且有其他入口应答时，重新绑定到其他入口；不会只因 RTT 稍低切换。
- 正常入口切换保留 WireGuard 会话，独立的数据面故障恢复则会重建隧道。

手动选择入口后仍探测，但不自动切走；恢复 auto 时立即择优一次。接口变更会触发额外探测。

## 10. sing-box 配置

构建需要 `with_wireguard`；用户态网络栈通常还需 `with_gvisor`。

```json
{
  "endpoints": [{
    "type": "dynamicguard",
    "tag": "dg",
    "server": "vpn.example.com",
    "server_port": 51820,
    "servers": [{"server": "backup.example.com", "server_port": 51820}],
    "probe_interval": "10m",
    "user_key": "<32-byte-base64>",
    "server_public_key": "<32-byte-base64>",
    "routes": ["0.0.0.0/0", "::/0"],
    "state_path": "/var/lib/sing-box/dg-state.json",
    "persistent_keepalive_interval": 25,
    "mtu": 1408
  }]
}
```

| 配置 | 说明 |
| --- | --- |
| server/server_port、servers | 至少提供一种；地址需要非零 UDP 端口 |
| user_key、server_public_key | Base64 编码的 32 字节值 |
| routes | 可选 CIDR 列表，默认空；system 模式下逐条装为系统路由，`/0` 不装 |
| state_path | 可选设备状态 JSON 路径 |
| private_key、device_id | 显式身份覆盖，分别为 Base64 与十六进制 |
| system、name | 系统 TUN 模式及接口名；移动端强制用户态模式，路由行为见 6.4 节 |
| mtu | 默认 1408 |
| workers | 工作线程数；移动端有平台默认上限 |
| persistent_keepalive_interval | 秒，默认 0，建议 25 |
| udp_timeout | 默认 5 分钟 |
| 通用拨号选项 | 支持 detour、bind_interface、routing_mark 等 |

## 11. API 服务

`SubscribeEndpoints` 返回连接状态、错误、分配地址、实际入口 `endpoint`、完整 `servers`、
`selectedServer` 及 `serverRttMs`。手选为空表示 auto；探测无应答为 -1。

`StartedService.SelectDynamicGuardEntrypoint`：

```json
{"endpointTag":"dg","server":"backup.example.com:51820"}
```

server 为空或省略恢复 auto；只能选择已配置候选。选择在当前 endpoint 生命周期内有效。
成功表示选择已应用，连接结果由订阅状态提供。未配置地址、endpoint 不存在、实例已关闭、
缺少构建支持分别返回 InvalidArgument、NotFound、Unavailable、Unimplemented。

`ProbeDynamicGuard` 接受 Base64 `userKey` 与非空 host:port 列表，单次最多 64 个地址；
通过默认 dialer 对每个地址发两轮探测并取最低 RTT，不修改现有 endpoint。未启用
`with_wireguard` 时返回 Unimplemented。跨节点选择由调用方决定。

## 12. AmneziaWG 实现与构建

| 参数 | 含义 |
| --- | --- |
| h1..h4 | Initiation、Response、CookieReply、Transport 的 uint32 magic |
| s1、s2 | Initiation、Response 前缀 junk 长度 |
| jc | 握手前 junk 包数量 |
| jmin、jmax | junk 包大小范围 |

v2node 在进程内共享一组随机参数，因为其 amneziawg-go 的消息类型是包级变量。h1..h4
互异、均大于 4，并避开 DG01 字节解释；`148+s1` 与 `92+s2` 必须不同；`jmin<=jmax`。
不同进程重新生成参数，客户端通过加密 ServerReply 获取。

sing-box 的 `third_party/wireguard-go` 保留 sagernet 模块路径，移植 AmneziaWG 并把参数和
消息类型映射改为每设备独立，以支持多个 endpoint。客户端 bind 在锁内发布和读取 socket，避免接收线程与主动握手同时拨号时的数据竞争。
两个 bind 对 DG 数据面纯透传；旧的
方向位、reserved HMAC、SKY XOR 和尾部 padding 方案不再使用。控制面 DG01 本身不做这种
混淆。

```text
replace github.com/sagernet/wireguard-go => ./third_party/wireguard-go
```

克隆 sing-box 时初始化该 submodule。未应用 fork 的上游 WireGuard 不认识 Amnezia UAPI
参数，会在设备配置时报错。fork 使用原模块路径以保持 sing-tun 等调用者的类型一致。

## 13. 验证范围

两端协议编码检查涵盖 ClientInit MAC、Cookie/PoW、IPv4/IPv6 ServerReply 参数和 Ping/Pong。
客户端回归测试另外覆盖同 socket Cookie 往返、挑战次数、取消、PoW 上限、故障观察及
隧道重建。服务端检查配置中的 PoW 难度上限，并回归共享出口保留段、同客户重叠 Network
分配、多节点独立租约、allow-all 下的客户隔离及单租户面板的放行与拒绝边界。

这些检查不替代真实网络环境中的路由、MTU、NAT、ACL、系统 TUN 和吞吐测试。当前凭据
明文传输等协议设计边界沿用原行为；WireGuard 数据面加密与控制面的凭据设计应分别评估。
