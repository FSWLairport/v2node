# DynamicGuard 协议规范

**版本**：2.2  
**传输层**：UDP  
**隧道层**：标准 WireGuard（用户态实现）

---

## 1. 简介

DynamicGuard 是一个运行在 WireGuard 握手之前的轻量接入协议。它用两条 UDP 消息完成用户认证、设备登记和隧道地址分配，随后交由标准 WireGuard 建立加密隧道。

完整连接建立需要 2 个 RTT：1 个 RTT 用于 DynamicGuard，1 个 RTT 用于 WireGuard 握手。当服务端启用 Cookie + PoW 保护时，DynamicGuard 阶段增加为 2 个 RTT，总计 3 个 RTT。

DynamicGuard 不修改 WireGuard 协议。

除握手外，协议还定义了一对无状态的 ClientPing / ServerPong 控制消息（第 19 节），供客户端探测入口延迟。

---

## 2. 预设条件

### 2.1 客户端配置（外部下发，定期更新）

| 字段 | 长度 | 说明 |
|------|------|------|
| `server_addr` | 变长 | 服务端 UDP 地址（IP + 端口） |
| `user_key` | 32 字节 | 用户级共享对称密钥。同一用户下所有设备持有相同值 |
| `server_wg_pub` | 32 字节 | 服务端 WireGuard 静态公钥 |
| `allowed_ips` | 变长 | WireGuard 路由规则（CIDR 列表） |
| `dns` | 变长 | DNS 服务器列表 |

`user_key` 是 32 字节随机密钥，不是标识符。实现方不得将其记入普通日志，不得以明文形式存储于非安全存储中。

### 2.2 客户端本地状态（首次启动生成，持久化）

| 字段 | 长度 | 说明 |
|------|------|------|
| `device_id` | 16 字节 | 随机生成的设备标识，可公开传输 |
| `wg_static_priv` | 32 字节 | 随机生成的 WireGuard 私钥 |

由 `wg_static_priv` 计算：

```
wg_static_pub = X25519_Base(wg_static_priv)
```

`wg_static_priv` 应使用平台安全存储保存（Android Keystore / iOS Keychain / Windows DPAPI / Linux 0600 文件权限）。

### 2.3 服务端状态

服务端维护 `user_key` 到用户的映射表，以及一张设备表（见第 12 节）。服务端不需要在连接之前知道任何设备信息。

---

## 3. 算法

| 用途 | 算法 |
|------|------|
| 密钥交换 | X25519 (RFC 7748) |
| 密钥派生 | HKDF-SHA256 (RFC 5869) |
| 消息认证 | HMAC-SHA256 |
| 对称加密 | ChaCha20-Poly1305 (RFC 8439) |
| 幂等键 / PoW | SHA256 |

---

## 4. 端口复用

DynamicGuard 与 WireGuard 共享同一个 UDP 端口。服务端按以下规则分流：

1. 若报文长度不足 5 字节，丢弃
2. 若首 4 字节为 `0x44 0x47 0x30 0x31`（ASCII `"DG01"`）且第 5 字节为 `0x01`，交给 DynamicGuard 控制面，再按长度分流：
   - 长度恰为 **85 字节** → ClientPing（第 19 节）
   - 其他长度 → ClientInit（167..207 字节，第 6 节）；长度不在范围内的丢弃
3. 若首字节为 `0x01`-`0x04` 或 `0x81`-`0x84`，交给 WireGuard（`0x81`-`0x84` 为经混淆层方向标记的 WireGuard 报文，详见第 26 节）
4. 其他情况丢弃

ClientPing 与 ClientInit 长度区间不重叠，控制面无需 msg_type 字段即可区分；客户端发出的报文中只有这两种以 `"DG01"` 开头。

---

## 5. 协议流程

### 5.1 正常流程（2 RTT）

```
Client                                        Server
  │                                              │
  │  生成 eph_priv, eph_pub                       │
  │                                              │
  │  ClientInit (明文 + MAC)                      │
  │ ──────────────────────────────────────────>   │
  │                                              │  验证 MAC → DH → 分配 IP
  │                                              │  注册 WG peer
  │  ServerReply (AEAD 加密)                      │
  │ <──────────────────────────────────────────   │
  │                                              │
  │  解密 → 配置 WG 接口                           │
  │                                              │
  │  WG Handshake Initiation ==================> │
  │  WG Handshake Response  <================== │
  │                                              │
  │  ~~~~ 加密隧道流量 ~~~~~~~~~~~~~~~~~~~~~~~~>  │
  │                                              │
  │  隧道内上报 metadata（业务层）                   │
  │ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~>  │
```

### 5.2 Cookie + PoW 流程（3 RTT）

当服务端处于高负载时，在正常流程前插入一轮 Cookie + PoW 交换：

```
Client                                        Server
  │                                              │
  │  ClientInit (无 cookie)                       │
  │ ──────────────────────────────────────────>   │
  │                                              │  高负载，不处理
  │  CookieReply { cookie, pow_difficulty }       │
  │ <──────────────────────────────────────────   │
  │                                              │
  │  计算 PoW：找 pow_nonce 使                     │
  │  SHA256(cookie || pow_nonce)                  │
  │  前 pow_difficulty 位为零                      │
  │                                              │
  │  ClientInit (带 cookie + pow_nonce)            │
  │ ──────────────────────────────────────────>   │
  │                                              │  校验 cookie
  │                                              │  校验 PoW（一次 SHA256）
  │                                              │  正常处理
  │  ServerReply                                  │
  │ <──────────────────────────────────────────   │
  │                                              │
  │  WG 握手 + 隧道建立（同 5.1）                   │
```

---

## 6. ClientInit

### 6.1 Wire Format

```
偏移   长度      字段
────────────────────────────────
  0     4       magic ("DG01")
  4     1       version (0x01)
  5    32       user_key
 37    16       device_id
 53    32       client_eph_pub
 85    32       wg_static_pub
117    16       client_nonce
133     1       cookie_len (0 或 32)
134   0|32      cookie
  ?     1       pow_nonce_len (0 或 8)
  ?   0|8       pow_nonce
  ?    32       mac
```

无 cookie 时总大小：**167 字节**。
有 cookie + PoW 时总大小：**207 字节**。

### 6.2 MAC 计算

```
mac_key = HKDF-SHA256(
    ikm  = user_key,
    salt = client_nonce,
    info = "dynamicguard-mac-v1"
)

mac = HMAC-SHA256(mac_key, 从 magic 到 pow_nonce 末尾的全部字节)
```

MAC 覆盖所有前置字段，包括 cookie 和 pow_nonce（如有）。

---

## 7. ServerReply

### 7.1 会话密钥派生

```
dh = X25519(server_wg_priv, client_eph_pub)
   = X25519(client_eph_priv, server_wg_pub)   // 客户端侧等价计算

reply_key = HKDF-SHA256(
    ikm  = dh || user_key,
    salt = client_nonce || server_nonce,
    info = "dynamicguard-reply-v1"
)
```

### 7.2 Wire Format

```
偏移   长度      字段
────────────────────────────────
  0     4       magic ("DG01")
  4     1       version (0x01)
  5    16       server_nonce
 21   var       AEAD ciphertext (payload + 16 字节 auth tag)
```

### 7.3 AEAD Payload（加密前明文）

```
偏移   长度      字段
────────────────────────────────
  0     1       address_family (4 = IPv4, 6 = IPv6)
  1   4|16      assigned_ip (4 字节 IPv4 或 16 字节 IPv6，network byte order)
  ?     1       prefix_len
  ?     4       lease_ttl (u32 LE, 秒)
  ?     4       h1 (u32 LE)   ┐
  ?     4       h2 (u32 LE)   │ AmneziaWG magic headers（见 §26）
  ?     4       h3 (u32 LE)   │
  ?     4       h4 (u32 LE)   ┘
  ?     2       s1 (u16 LE)   ┐ init/response junk 前缀字节数
  ?     2       s2 (u16 LE)   ┘
  ?     2       jc (u16 LE)   ┐
  ?     2       jmin (u16 LE) │ junk 包数量 / 大小区间
  ?     2       jmax (u16 LE) ┘
```

基础字段后 append **26 字节** AmneziaWG per-node 参数（h1-h4 各 u32 + s1/s2/jc/jmin/jmax 各 u16，全部小端），供客户端配置数据面 amnezia 设备（见 §26）。

IPv4 payload：36 字节。IPv6 payload：48 字节。
加上 auth tag（16 字节）：IPv4 ciphertext 52 字节，IPv6 ciphertext 64 字节。

IPv4 总大小（含 21 字节头部）：**73 字节**。IPv6 总大小：**85 字节**。

### 7.4 AEAD 构造

```
nonce = 0x000000000000000000000000 (12 字节全零)
aad   = magic || version || server_nonce (前 21 字节)

ciphertext || tag = ChaCha20-Poly1305(reply_key, nonce, aad, payload)
```

`reply_key` 是一次性密钥（每次握手 `client_eph_priv` 和 `server_nonce` 都不同），AEAD nonce 固定全零。

---

## 8. CookieReply

### 8.1 触发条件

服务端在以下情况返回 CookieReply 而非正常处理 ClientInit：

- 当前 pending 连接数超过阈值
- 来自同一源地址的请求速率超过阈值
- 来自同一 user_key 的请求速率超过阈值

### 8.2 Wire Format

```
偏移   长度      字段
────────────────────────────────
  0     4       magic ("DG01")
  4     1       version (0x01)
  5     1       msg_type (0xFE)
  6    32       cookie
 38     1       pow_difficulty
```

总大小：**39 字节**。

CookieReply 始终明文发送。

### 8.3 Cookie 生成

```
cookie = HMAC-SHA256(
    key     = server_cookie_secret,
    message = src_ip || src_port || time_slot
)
```

- `server_cookie_secret`：服务端本地密钥，定期轮换（建议每 120 秒）
- `time_slot = unix_time / 120`（2 分钟窗口）
- 服务端校验时接受当前和上一个 time_slot 的 cookie

Cookie 绑定了源地址，证明客户端能在其声称的地址收包。

### 8.4 PoW 机制

客户端收到 CookieReply 后，如果 `pow_difficulty > 0`，需要找到一个 8 字节的 `pow_nonce` 使得：

```
SHA256(cookie || pow_nonce) 的前 pow_difficulty 个比特为零
```

服务端验证成本：一次 SHA256。

### 8.5 Difficulty 参考值

| pow_difficulty | 平均尝试次数 | 普通设备耗时 | 适用场景 |
|---------------|------------|------------|---------|
| 0 | 0 | 0 | 仅 cookie，不要求 PoW |
| 12 | ~4,096 | ~3ms | 轻度防护 |
| 16 | ~65,536 | ~50ms | 中等负载 |
| 20 | ~1,048,576 | ~500ms | 高负载 |
| 24 | ~16,777,216 | ~8s | 极端负载 |

服务端应根据当前负载动态调整 `pow_difficulty`。正常负载下不发送 CookieReply。

---

## 9. 服务端处理 ClientInit

收到 ClientInit 后，服务端按以下顺序处理：

1. 校验 magic 和 version
2. 读取 user_key，查用户映射表。**未命中 → 静默丢弃**
3. 若启用 cookie 且 `cookie_len > 0`：校验 cookie（当前和上一个 time_slot）。**失败 → 静默丢弃**
4. 若启用 cookie 且 `pow_difficulty > 0`：校验 PoW。**失败 → 静默丢弃**
5. 若启用 cookie 且 `cookie_len = 0` 且当前处于高负载：发送 CookieReply，不继续处理
6. 用 user_key 和 client_nonce 派生 mac_key，校验 mac。**失败 → 静默丢弃**
7. 计算幂等键 `idem_key = SHA256(user_key || device_id || client_eph_pub || wg_static_pub || client_nonce)`。若命中缓存 → 重发缓存的 ServerReply
8. 计算 `dh = X25519(server_wg_priv, client_eph_pub)`
9. 查设备表（见第 12 节）
10. 分配或复用 IP（见第 13 节）。此步骤必须与步骤 9 在同一原子操作内完成
11. 在用户态 WireGuard 实例中注册 peer
12. 生成 server_nonce，派生 reply_key
13. 加密并发送 ServerReply
14. 将 ServerReply 写入幂等缓存，关联 `idem_key`，TTL 60 秒

所有认证失败（步骤 2、3、4、6）均静默丢弃，不返回任何响应。攻击者无法区分 user_key 无效、MAC 错误还是 cookie 错误。

X25519 运算（步骤 8）在 MAC 校验（步骤 6）之后执行，确保无效请求不消耗椭圆曲线运算。如果启用了 cookie + PoW，还需在步骤 3-4 通过后才会到达步骤 6，进一步提高攻击成本。

---

## 10. 客户端处理 ServerReply

1. 读取 server_nonce
2. 用 `dh || user_key` 和 `client_nonce || server_nonce` 派生 reply_key
3. AEAD 解密。失败 → 重传 ClientInit 或中止
4. 读取 address_family、assigned_ip、prefix_len、lease_ttl
5. 配置本地 WireGuard 接口：
   - 私钥：`wg_static_priv`
   - 地址：`assigned_ip/prefix_len`
   - 对端公钥：`server_wg_pub`（来自配置）
   - 对端端点：`server_addr`（来自配置）
   - AllowedIPs：来自配置
   - DNS：来自配置
6. 发起标准 WireGuard 握手
7. 隧道建立后，通过隧道内的业务通道上报 metadata（设备信息）

---

## 11. 设备信息上报

设备信息（操作系统、客户端版本、架构等）不在 DynamicGuard 握手中传输。

客户端应在 WireGuard 隧道建立后，通过隧道内的业务通道（例如 HTTP API 或自定义 UDP 协议）上报设备信息。此时数据已在 WireGuard 加密保护之下，不存在明文泄露风险。

上报内容和格式由业务层定义，不属于 DynamicGuard 协议范围。

---

## 12. 设备表

### 12.1 Schema

```
devices {
    user_id        : uint32           // 由 user_key 查得
    device_id      : bytes(16)
    wg_static_pub  : bytes(32)
    assigned_ip    : IPv4 或 IPv6
    last_seen      : timestamp
    status         : enum { active, disconnected, revoked }

    PRIMARY KEY (user_id, device_id)
    UNIQUE (wg_static_pub)
    UNIQUE (assigned_ip)
}
```

### 12.2 设备识别

收到 ClientInit 时，服务端按 `(user_id, device_id)` 查表：

**记录存在且 wg_static_pub 一致：**
老设备重连。复用原 IP（如可用）。更新 last_seen。

**记录存在但 wg_static_pub 不一致：**
拒绝接入，静默丢弃。已注册设备的 `wg_static_pub` 不可在线替换。设备本地状态重置后需由管理员在后台删除旧设备记录，设备下次连接将作为新设备注册。

**记录存在但 status = revoked：**
拒绝接入，静默丢弃。

**记录不存在：**
新设备。检查该用户设备数是否超限。未超限则创建记录并分配 IP。超限则静默丢弃。

### 12.3 并发要求

对 `(user_id, device_id)` 的设备查找、IP 分配和 peer 注册必须在同一原子操作内完成。实现方应对 `(user_id, device_id)` 加互斥锁或使用数据库事务，防止并发 ClientInit 导致双重分配或幽灵 peer。

`assigned_ip` 和 `wg_static_pub` 必须有唯一约束。

---

## 13. IP 地址分配

### 13.1 地址池

每个用户绑定一个地址池。示例：

```
User A → 10.80.1.0/24      (254 可用 IPv4)
User B → fd80::1:0/112      (65534 可用 IPv6)
```

服务端用位图或等效结构追踪已分配地址。

### 13.2 分配策略

| 场景 | 动作 |
|------|------|
| 老设备，原 IP 可用 | 复用原 IP |
| 老设备，原 IP 已被占用 | 分配新 IP |
| 新设备 | 分配最低可用 IP |
| 地址池耗尽 | 静默丢弃（同认证失败处理） |

---

## 14. 租约管理

服务端不使用显式续租协议。租约通过 WireGuard 隧道活跃度隐式维护：

1. 每次收到某个 peer 的有效 WireGuard 数据包时，更新该设备的 `last_seen`
2. 定期扫描设备表，`now - last_seen > lease_ttl` 的设备执行清理：
   - 从用户态 WireGuard 实例中移除 peer
   - 释放 IP 回地址池
   - 设备状态设为 `disconnected`（保留记录，允许重连）

### 14.1 lease_ttl 约束

- `lease_ttl` 由服务端决定，在 ServerReply 中下发
- `lease_ttl` 必须 ≥ `3 × PersistentKeepalive`
- 建议最小值：90 秒
- 建议默认值：3600 秒
- 客户端不得将 `lease_ttl` 解释为"IP 永久有效"

客户端应配置 WireGuard `PersistentKeepalive`（建议 25 秒），确保即使无业务流量也能保持隧道活跃。

---

## 15. 重传与幂等

### 15.1 客户端重传

| 参数 | 值 |
|------|-----|
| 初始超时 | 500ms |
| 退避倍数 | 2x |
| 最大重试 | 5 次 |
| 最大单次超时 | 16 秒 |

### 15.2 服务端幂等

服务端通过幂等缓存避免重复处理。缓存键绑定完整请求内容：

```
idem_key = SHA256(user_key || device_id || client_eph_pub || wg_static_pub || client_nonce)
```

规则：

- `idem_key` 命中缓存 → 重发缓存的 ServerReply，不重复分配资源
- `client_nonce` 相同但其他字段不同 → 视为异常，静默丢弃
- 缓存 TTL：60 秒

---

## 16. 防重放

1. 幂等缓存兼做 nonce 去重（60 秒窗口）
2. `server_nonce` 每次随机生成，使 `reply_key` 不可预测
3. WireGuard 握手自身包含时间戳防重放

---

## 17. 抗 DoS

服务端处理 ClientInit 的开销分级：

| 步骤 | 开销 | 条件 |
|------|------|------|
| 校验 magic / version | 极低 | 始终 |
| 查 user_key | 低（哈希表） | 始终 |
| 校验 cookie | 低（一次 HMAC） | 启用 cookie 时 |
| 校验 PoW | 低（一次 SHA256） | 启用 PoW 时 |
| 校验 MAC | 中（HKDF + HMAC） | cookie/PoW 通过后 |
| 计算 X25519 | 高 | MAC 通过后 |

三层防护叠加：

1. **Cookie**：证明客户端能在声称的源地址收包，拦截源地址伪造的放大攻击
2. **PoW**：提高每个请求的计算成本，拦截大规模自动化攻击
3. **MAC-before-DH**：无效 user_key 不触发椭圆曲线运算

额外建议：

- 按源地址限速
- 按 user_key 限速
- 设置最大并发 pending 数

ClientPing 的处理开销止于「校验 MAC」一级（第 19 节），不触发 DH，不计入 pending 数；若实现了按源地址 / user_key 限速，同样适用于 ClientPing。

---

## 18. 断开与清理

客户端关闭 WireGuard 接口即可断开。无需显式 Bye 消息。

服务端在 `lease_ttl` 到期后自动移除 peer 并释放 IP。设备记录保留，允许重连。

---

## 19. ClientPing / ServerPong

一对无状态控制消息，用于客户端**探测入口延迟**（选线、显示 RTT、判断入口是否可达）。它不是租约保活：不刷新 `last_seen`，不延长租约，不注册设备，也不建立任何会话状态；保活仍由 WireGuard 数据面流量完成（第 14 节）。

### 19.1 ClientPing Wire Format

```
偏移   长度      字段
────────────────────────────────
  0     4       magic ("DG01")
  4     1       version (0x01)
  5    32       user_key
 37    16       nonce（客户端随机生成）
 53    32       mac
```

总大小：**85 字节**，固定。

### 19.2 MAC 计算

与 ClientInit 完全相同的构造（第 6.2 节），salt 换为本报文的 nonce：

```
mac_key = HKDF-SHA256(ikm = user_key, salt = nonce, info = "dynamicguard-mac-v1")
mac     = HMAC-SHA256(mac_key, bytes[0:53])
```

### 19.3 ServerPong Wire Format

```
偏移   长度      字段
────────────────────────────────
  0     4       magic ("DG01")
  4     1       version (0x01)
  5     1       msg_type (0xFC)
  6    16       nonce（原样回显 ClientPing 的 nonce）
```

总大小：**22 字节**，明文。客户端按 nonce 匹配发出的 Ping 并计算 RTT；nonce 不匹配的 Pong 丢弃。

### 19.4 服务端处理

1. 校验长度 == 85、magic、version
2. 查 `user_key`；未找到 → 静默丢弃
3. 校验 MAC；失败 → 静默丢弃
4. 发送 ServerPong，源 IP 与收包的本机 IP 一致（源进源出）

不做 X25519、不查设备表、不写幂等缓存、不走 Cookie / PoW、不计入 pending 连接数。每个 Ping 独立处理，重复的 Ping 各自得到一个 Pong。

**过载保护**。Ping 是唯一绕过 Cookie / PoW 就会触发 HMAC 的路径，所以服务端对它另有两道闸，客户端都感知为"这轮无应答"：

- pending 的 ClientInit 数超过高负载阈值时，Ping 在计算任何哈希之前静默丢弃——此时 ClientInit 会被 CookieReply 顶回，Ping 没有 cookie 可顶，只能不理。
- Ping 由单个 worker 串行处理，前面有一个有界队列（实现值 1024）；队列满即丢，不记日志。这样 Ping 洪水最多占满一个核，不会拖慢同一 socket 上的 WireGuard 数据面，也不会每包起一个 goroutine。

客户端因此**不得**把单轮无应答当作入口不可达；判定切换要求连续多轮无应答（sing-box 实现为 3 轮）。

### 19.5 安全性

- **无放大**：Pong（22B）短于 Ping（85B），伪造源地址的攻击者拿不到放大倍数
- **静默丢弃**：所有失败路径无响应，与第 20.6 节一致，无法用 Ping 枚举 `user_key`
- **不可重放利用**：Pong 不携带任何服务端状态，重放旧 Ping 只会得到同一个 nonce 的回显
- Pong 明文回显 nonce，不泄露 `user_key`；被动观察者可知某地址在探测该入口，与其能观察到握手本身无差别

---

## 20. 安全分析

### 20.1 控制层认证

ClientInit 的 MAC 证明客户端持有 `user_key`。ServerReply 的 AEAD 解密成功证明服务端持有 `server_wg_priv`（因为 `reply_key` 依赖 `DH(client_eph, server_static)`）。双向认证在一个 RTT 内完成。

### 20.2 前向安全

控制层具备客户端侧前向安全：每次连接使用随机 `client_eph_priv`，握手完成后丢弃。事后泄露 `user_key` 不影响历史会话。

控制层不具备服务端侧前向安全：若攻击者事后同时获得 `server_wg_priv` 和 `user_key`，且保存了历史 ClientInit 和 ServerReply，则可恢复历史控制层明文。控制层传输的内容仅为 IP 分配信息，敏感度低。WireGuard 隧道自身的 Noise IK 模式提供完整的双向前向安全，业务数据不受影响。

### 20.3 user_key 泄露影响

攻击者可以注册新设备并获取隧道地址。不能冒充已有设备（不知道其 `wg_static_priv`，且服务端拒绝在线替换公钥）。不能解密已有设备的 WireGuard 隧道流量。

响应措施：轮换 `user_key` 并重新下发配置，审计设备表中的异常记录。

### 20.4 设备身份

已注册设备的 `wg_static_pub` 不可在线替换。这确保了即使 `user_key` 泄露，攻击者也无法接管现有设备的身份或 IP。设备重置需要管理员介入。

### 20.5 信任边界

系统的根信任单位是用户（`user_key`），不是设备。这是预设条件决定的。如需收紧到设备级信任，需引入带外的单设备凭据机制。

### 20.6 错误处理

所有认证失败（user_key 无效、MAC 错误、设备被撤销、公钥不匹配、设备数超限、地址池耗尽）均静默丢弃，ClientPing 亦然。攻击者无法通过错误响应区分失败原因，无法枚举有效 user_key 或探测设备状态。

---

## 21. 客户端状态机

```
IDLE
  ├─ 用户请求连接 ──────────────────> CONNECTING

CONNECTING
  ├─ 生成 eph_key，发送 ClientInit
  ├─ 收到 CookieReply ────────────> SOLVING_POW
  ├─ 收到 ServerReply，解密成功 ────> CONFIGURING
  ├─ 超时且有重试次数 ─────────────> CONNECTING（重传）
  ├─ 超时且无重试次数 ─────────────> FAILED

SOLVING_POW
  ├─ 计算 PoW 完成 ────────────────> CONNECTING（带 cookie + pow_nonce 重发）
  ├─ PoW 计算超时 ─────────────────> FAILED

CONFIGURING
  ├─ 配置 WG 接口，发起 WG 握手
  ├─ WG 握手成功 ──────────────────> CONNECTED
  ├─ WG 握手失败 ──────────────────> FAILED

CONNECTED
  ├─ 隧道故障 ─────────────────────> IDLE（重新开始）
  ├─ 用户断开 ─────────────────────> IDLE
  ├─ 本机网络接口变更 ─────────────> CONNECTED（仅重开 UDP socket，见下）

FAILED
  ├─ 指数退避后 ───────────────────> IDLE
  ├─ 达到最大重试 ─────────────────> ERROR（提示用户）
  ├─ 本机网络接口变更 ─────────────> CONNECTING（重新握手）
```

### 21.1 本机网络接口变更（换网漫游）

客户端换网（WiFi ↔ 蜂窝、WAN 重拨、默认路由切换）不需要重新执行 DynamicGuard 握手：

- **CONNECTED**：只重开 UDP socket。WireGuard 会话密钥仍在内存中，服务端从下一个合法
  WireGuard 报文的来源地址学到新 endpoint（标准 WireGuard 漫游，服务端无需改动）。
- **FAILED**：重新进入 CONNECTING。典型场景是设备在 WAN 就绪前启动，握手重试耗尽后停在
  FAILED；没有这条边，FAILED 会一直持续到进程重启。

以上只处理**本机**地址的漂移，不切换服务端地址。

---

## 22. 服务端处理模型

服务端为无状态请求-响应模型 + 幂等缓存：

```
收到 UDP 包
  ├─ 首 4 字节 = "DG01"，长度 = 85（ClientPing）
  │    ├─ user_key 未找到            → 静默丢弃
  │    ├─ MAC 校验失败              → 静默丢弃
  │    └─ 正常                      → 发送 ServerPong
  │
  ├─ 首 4 字节 = "DG01"，其他长度（ClientInit）
  │    ├─ magic/version/长度错误     → 丢弃
  │    ├─ user_key 未找到            → 静默丢弃
  │    ├─ 高负载且无 cookie          → 发送 CookieReply
  │    ├─ cookie 校验失败            → 静默丢弃
  │    ├─ PoW 校验失败              → 静默丢弃
  │    ├─ MAC 校验失败              → 静默丢弃
  │    ├─ idem_key 命中缓存          → 重发缓存的 ServerReply
  │    ├─ 设备被撤销 / 公钥不匹配     → 静默丢弃
  │    ├─ 设备数超限 / 地址池耗尽     → 静默丢弃
  │    └─ 正常                      → 分配 IP，注册 peer，发送 ServerReply
  │
  ├─ 首字节 = 0x01-0x04             → 交给 WireGuard
  └─ 其他                           → 丢弃

后台定时任务
  └─ 扫描设备表，清理过期租约
```

---

## 23. HKDF 标签注册表

| info 字符串 | 用途 | ikm | salt |
|-------------|------|-----|------|
| `"dynamicguard-mac-v1"` | ClientInit / ClientPing MAC key | user_key | client_nonce / ping nonce |
| `"dynamicguard-reply-v1"` | ServerReply AEAD key | dh \|\| user_key | client_nonce \|\| server_nonce |

---

## 24. 报文大小汇总

| 报文 | 大小 | 加密 |
|------|------|------|
| ClientInit（无 cookie） | 167 字节 | 明文 + MAC |
| ClientInit（有 cookie + PoW） | 207 字节 | 明文 + MAC |
| ServerReply（IPv4） | 73 字节 | AEAD（含 26B AmneziaWG 参数）|
| ServerReply（IPv6） | 85 字节 | AEAD（含 26B AmneziaWG 参数）|
| CookieReply | 39 字节 | 明文 |
| ClientPing | 85 字节 | 明文 + MAC |
| ServerPong | 22 字节 | 明文 |

完整握手开销（DynamicGuard + WireGuard，IPv4，不含 IP/UDP 头，不含重传）：约 **460 字节**。

---

## 25. sing-box 客户端配置

DynamicGuard 在 sing-box 中作为 **endpoint** 类型实现，类型名为 `dynamicguard`。它在内部包装了标准 WireGuard endpoint：启动时先完成 DynamicGuard 握手获取隧道地址，然后自动创建 WireGuard 隧道。

需要 build tag：`with_wireguard`。

### 25.1 配置格式

```jsonc
{
  "endpoints": [
    {
      "type": "dynamicguard",
      "tag": "dg-ep",

      // === DynamicGuard 服务端地址 ===
      "server": "vpn.example.com",       // 默认地址（IP 或域名）
      "server_port": 51820,              // 服务端 UDP 端口
      "servers": [                       // 同一节点的其他地址（可选，见 §25.5）
        {"server": "203.0.113.7", "server_port": 51820}
      ],
      "probe_interval": "10m",           // 多地址时的稳态探测间隔（可选）
      "user_key": "BASE64...",           // 用户级共享密钥（Base64，32 字节）
      "server_public_key": "BASE64...",  // 服务端 WireGuard 公钥（Base64，32 字节）

      // === 路由规则 ===
      "allowed_ips": [                   // WireGuard AllowedIPs，同标准 WireGuard
        "0.0.0.0/0",
        "::/0"
      ],

      // === 持久化状态（可选） ===
      "state_path": "/var/lib/sing-box/dg-state.json",
      // 存储自动生成的 device_id 和 WireGuard 私钥
      // 不指定时每次启动重新生成（将被服务端视为新设备）

      // 也可直接配置而非自动生成：
      // "private_key": "BASE64...",      // WireGuard 私钥（Base64，32 字节）
      // "device_id": "HEX...",           // 设备 ID（Hex，16 字节）

      // === WireGuard 隧道参数（可选） ===
      "system": false,                   // 使用系统 TUN 或用户态协议栈
      "name": "wg0",                     // 接口名称
      "mtu": 1408,                       // MTU（默认 1408）
      "workers": 0,                      // WireGuard 工作线程数（0 = 自动）
      "persistent_keepalive_interval": 25, // 建议 25 秒
      "udp_timeout": "5m",              // UDP 会话超时

      // === 拨号选项（可选，继承自 DialerOptions） ===
      "detour": "",
      "bind_interface": "",
      "routing_mark": 0
      // ... 其他 DialerOptions 字段
    }
  ]
}
```

### 25.2 字段说明

| 字段 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `server` | string | 与 `servers` 二选一 | — | 默认服务端地址（IP 或域名） |
| `server_port` | uint16 | 随 `server` | — | 服务端 UDP 端口 |
| `servers` | \[object\] | 与 `server` 二选一 | `[]` | 同一节点的其他地址，每项 `{server, server_port}`，见 §25.5 |
| `probe_interval` | duration | — | `10m` | 候选 ≥2 时稳态探测的间隔 |
| `user_key` | string | ✅ | — | Base64 编码的 32 字节用户密钥 |
| `server_public_key` | string | ✅ | — | Base64 编码的服务端 WireGuard 公钥 |
| `allowed_ips` | \[string\] | — | `[]` | CIDR 列表，同 WireGuard AllowedIPs |
| `state_path` | string | — | `""` | 设备状态文件路径（JSON）。为空时不持久化 |
| `private_key` | string | — | 自动生成 | Base64 编码的 WireGuard 私钥。优先于 state_path 中的值 |
| `device_id` | string | — | 自动生成 | Hex 编码的 16 字节设备 ID。优先于 state_path 中的值 |
| `system` | bool | — | `false` | `true` 使用系统 TUN，`false` 使用用户态协议栈 |
| `name` | string | — | `""` | 网络接口名称 |
| `mtu` | uint32 | — | `1408` | 隧道 MTU |
| `workers` | int | — | `0` | WireGuard 工作线程数 |
| `persistent_keepalive_interval` | uint16 | — | `0` | PersistentKeepalive 间隔（秒），建议设为 25 |
| `udp_timeout` | duration | — | `5m` | UDP 会话超时时间 |

### 25.3 状态文件格式

`state_path` 指定的文件使用 JSON 格式存储：

```json
{
  "device_id": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
  "private_key": "BASE64..."
}
```

- `device_id`：Hex 编码，16 字节
- `private_key`：Base64 编码，32 字节

首次启动时自动生成并写入，后续启动自动加载。文件权限为 `0600`。

### 25.4 最小配置示例

```json
{
  "endpoints": [
    {
      "type": "dynamicguard",
      "tag": "dg",
      "server": "1.2.3.4",
      "server_port": 51820,
      "user_key": "dGhpcyBpcyBhIDMyIGJ5dGUga2V5IGZvciBkZw==",
      "server_public_key": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
      "allowed_ips": ["0.0.0.0/0"],
      "state_path": "/var/lib/sing-box/dg-state.json",
      "persistent_keepalive_interval": 25
    }
  ]
}
```

---

### 25.5 多地址：候选列表、探测与切换

`server`/`server_port` 与 `servers` 合成一个**候选列表**：默认地址排首位，`servers` 按写入
顺序跟在后面，重复的 host:port 去重。只写其中一种即可；候选只有一个时行为与单地址完全一致，
不探测、不切换。优先级分层（备用地址）不在协议层：控制面只下发当前层的地址，客户端在拿到的
候选里择优，不自行跨层。

候选 ≥2 时：

| 时刻 | 动作 |
|------|------|
| 启动 / 从 FAILED 重试 | 并发向全部候选发 ClientPing（一轮 ≤ 500ms），取 RTT 最低者做 ClientInit；无人应答（旧服务端不认 Ping）则按列表顺序 |
| 稳态，每 `probe_interval` | 再探一轮，只更新 RTT 快照。**当前地址连续 3 轮无 Pong 且有其他候选应答**时切换 |
| 本机接口变更 | §20.1 的 rebind 之后立刻补探一轮 |

切换不重新握手：客户端把 UDP socket 重新 connect 到新地址，再把 WireGuard peer 的 endpoint
改过去。会话密钥仍在内存，服务端从下一个报文的来源地址学到新 endpoint（与 §20.1 同一机制），
服务端无需任何改动。从不因为"另一个地址快几十毫秒"而切换：切换会让服务端重学 endpoint、
NAT 重建映射，不值。

状态快照（api service `SubscribeEndpoints`）暴露 `endpoint`（当前拨的 host:port，按配置原样）
和 `serverRttMs`（上一轮每个候选的毫秒数，-1 = 无应答；单候选时为空）。

跨节点的择优不在内核里：控制面把候选节点连同各自的地址交给客户端（固件 agent / App），
由客户端决定把哪个节点写进配置。内核只提供探针——api service 的 `ProbeDynamicGuard`（单次最多 64 个地址，超出拒绝；api service 在 loopback 无鉴权，这是对本机进程的上限）
RPC（请求 `userKey` = base64 的 32 字节 user_key，`servers` = 任意 host:port 列表，非空；
响应 `rttMs` 为每个请求地址的毫秒数，-1 = 无应答）。它对每个地址连发两轮 ClientPing
（每轮 ≤ 500ms）取最低值，无状态，不碰任何端点；报文经内核的默认 dialer 发出，与不带
dialer 选项的 DynamicGuard 端点握手走同一条路（bind_interface / protect / 扩展进程），
所以不会被 tun 自己吞掉。仅 `with_wireguard` 构建实现，否则返回 `Unimplemented`。

## 26. 数据面抗 DPI 混淆层（AmneziaWG）

DynamicGuard 握手完成后承载的是 WireGuard 数据面流量。为消除 WireGuard 握手报文固定的首 4 字节 `type` 指纹与固定包长，数据面采用 **AmneziaWG**（WireGuard 的抗 DPI 变体）替代标准 WireGuard。

> **历史**：早期版本在 bind 层对 WireGuard 报文做对称混淆（`type|0x80` 方向位、reserved 字段 HMAC 掩码、尾部 padding、`"SKY"` XOR）。该方案已废弃——它在跨包/跨节点维度是零熵固定指纹，且 mac2 偏移固定可被静态规则识别。现已整体迁移到 AmneziaWG，bind 层退化为纯透传。

### 26.1 混淆机制

AmneziaWG 在 WireGuard 协议层（而非 bind 层）施加三类变换，全部由设备参数驱动：

| 参数 | 含义 |
|------|------|
| `h1` / `h2` / `h3` / `h4` | 四类消息（Initiation / Response / CookieReply / Transport）的 **magic header**（uint32），替换标准 WireGuard 报文首 4 字节的 `type` 字段 |
| `s1` / `s2` | 分别 prepend 到 Initiation / Response 握手包前缀的 **junk 字节数** |
| `jc` / `jmin` / `jmax` | 握手前发送的 **junk 包数量**及每包大小区间 `[jmin, jmax]` |

magic header 在协议层写入并**参与 MAC1 计算**，因此必须在握手报文构造时即就位——这是它无法在 bind 层事后替换的根本原因。

### 26.2 per-node 参数

参数**按节点（per-node）**生成，而非全局硬编码：

- 服务端启动时随机生成一组（进程级 `sync.Once` singleton），满足 AmneziaWG `handlePostConfig` 全部约束：
  - `h1`-`h4` 互异、均 `> 4`、避开 DG01 magic 的小端解读 `0x31304744`（825257796）
  - `148 + s1 ≠ 92 + s2`（Init / Response 包尺寸必须可区分）
  - `jmin ≤ jmax`，所有尺寸远小于 MTU
- 不同节点 / 不同部署拥有不同参数，跨节点不再是恒定指纹——这是抗"校园网计费网关静态签名匹配"威胁模型的核心。
- 进程级共享（非 per-link）：AmneziaWG 的 magic header 在服务端为包级全局，同进程多个 DGServer 必须共用一组。

### 26.3 参数下发

客户端通过 **DG01 ServerReply** 获取该节点的参数（见 §7.3，加密载荷尾部追加 26 字节）：

1. 客户端发 ClientInit → 服务端回 ServerReply，其中携带 per-node 参数（h1-h4 / s1 / s2 / jc / jmin / jmax）
2. 客户端解密 ServerReply，提取参数，配置本地 AmneziaWG 设备（UAPI `IpcSet`：`jc/jmin/jmax/s1/s2/h1/h2/h3/h4`）
3. 随后发起 WireGuard 握手，此时 magic header 等已就位

DG01 控制报文自身不参与 AmneziaWG 混淆（首 4 字节仍是 `DG01` magic + version）。

### 26.4 实现

两端均使用 AmneziaWG 的 ASec 实现：

- **服务端**：`github.com/amnezia-vpn/amneziawg-go`，per-node 参数经 `IpcSet` 配置设备
- **客户端**：`github.com/sagernet/wireguard-go` 的 amnezia-ASec fork（submodule `libcore/third_party/wireguard-go`，`git.sky.wf/airport/wireguard-go`）。在 sagernet fork 上移植了 amnezia 的 magic header / junk 机制，并将 magic 类型与 size→type 映射改为 **per-device**（非包级全局），以支持同进程多个 DG 端点各持不同参数

bind 层（客户端 `ClientBind`、服务端 `DGBind`）对 WireGuard 报文**纯透传**，不做任何字节变换；标准（非 DG）WireGuard 端点仍保留原有 reserved 清零行为。
