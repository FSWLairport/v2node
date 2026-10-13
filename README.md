# v2node

基于修改版 Xray 内核的 V2board 节点服务端，需要搭配[对应的 V2board](https://github.com/wyx2685/v2board)。

## 安装

```bash
wget -N https://raw.githubusercontent.com/FSWLairport/v2node/dev/script/install.sh && bash install.sh
```

## 构建

```bash
GOEXPERIMENT=jsonv2 go build -v -o build_assets/v2node -trimpath -ldflags "-X 'github.com/wyx2685/v2node/cmd.version=$version' -s -w -buildid="
```

## SATLS 与 DynamicGuard

SATLS 在服务端终止一层 TLS，支持 FULL 和 Split，业务通过 SMUX v2 和 UoT v2 转发。
HTTP Host 可与 TLS SNI 不同；Split 独立 SNI 使用各自证书，证书缓存支持文件轮换。
Split 配对和重连先发送 HTTP 101，再开放 SMUX 写入并刷新缓存；部分写失败仅保留未发送字节。
SATLS padding 上限为 64 KiB，读取时就限制内存；超限返回 413。普通 HTTP 回落请求流式转发。
Session ID 仍按现有 ±120 秒新鲜度规则校验，本次实现修复没有改变长期重连的协议约束。

DynamicGuard 的配置、DG01 报文、Cookie/PoW、租约与客户端恢复约定见 [DynamicGuard.md](DynamicGuard.md)。
客户端需要复用握手 UDP socket；服务端只接受 0..24 的 PoW 难度配置。数据面使用 AmneziaWG。

节点配置可带 `org_bandwidth_limits`，按组织 ID 配置独立的 `up_mbps` / `down_mbps`；
单位 Mbps，0 表示该方向不限速，同一节点上该组织的所有凭据共享额度，其他节点独立计算。
SATLS 从面板用户列表的 `org_id` 找共享桶，与原有 UUID `speed_limit` 同时执行；
未提供新字段的 V2board 继续使用原有 UUID 限速。DynamicGuard 从已认证租约的
`group_id` 和 `network_orgs` 确定组织，在 TUN 上传和下载两个方向丢弃超额包；
保留按凭据共享上下行的 `speed_limit`，用户名单刷新不重置未变额度。组织桶连续补充令牌，
允许最多一秒额度的短时突发，数据包路径不等待，不拖慢其他组织。
带宽字段限制速度，变更沿用配置重载，会中断节点现有连接。面板另外按 node grant 统计
客户设置的 UTC 月度账期上传加下载额度，首期额度由面板按服务天数折算（限速不折算），超额后从用户列表移除该组织的凭据；DG 删除 peer，SATLS
关闭对应活动连接，其他客户继续服务。提高额度或进入下一客户账期后，下一次用户刷新会恢复。
流量停服存在上报与拉取周期延迟，节点收到的用户列表为空时也必须清空授权。

相关回归测试：

```bash
GOEXPERIMENT=jsonv2 go test ./common/rate ./core/app/dispatcher ./proxy/satls ./proxy/dynamicguard
GOEXPERIMENT=jsonv2 go test -race ./common/rate ./core/app/dispatcher ./proxy/satls ./proxy/dynamicguard
```

## 面板 WS 通知

支持 `base_config.node_events=true` 的面板会启用 WS 通知。v2node 使用当前节点 API key
通过 Bearer header 连接 `/api/v1/server/UniProxy/events?node_id=<id>`，不在 URL 中携带密钥。
收到 `{"type":"refresh"}` 后唤醒原有串行刷新任务，拉取配置与用户列表；用户变更沿用热更新，
配置变更仍会重载。无需修改本地 config.json，旧面板未声明能力时继续轮询。

连接使用原有 TLS 验证设置，响应服务端 Ping，断线后按带随机抖动的指数退避重连；
退避基数最多 30 秒。404 会停止本轮运行的 WS 尝试，节点重载后可再次启用。
原有拉取和上报周期继续运行；WS 是刷新提示，没有“已应用凭据”的确认消息。
控制器关闭时取消连接与重连。面板重连后应立即发送一次 refresh，补齐断线期间的变更。

相关检查：

```bash
GOEXPERIMENT=jsonv2 go test ./api/v2board ./common/task ./node
```

## 用量采样

面板声明 `base_config.usage_sampling=true` 时，SATLS 不再等到最低流量阈值才上报，
DG 和 SATLS 都按原有上报周期发送空流量记录，供面板识别在线空闲时段。
未声明该字段的面板保持原有上报行为。面板把收到的增量归入 UTC 的 5 分钟桶，
零流量样本参与 95 分位，离线或缺失上报的区间不伪造为零；统计页显示采样覆盖率。
这些记录用于用量统计，不保证网络故障或进程退出时无损计费。

## Stars

[![Stargazers over time](https://starchart.cc/wyx2685/v2node.svg?variant=adaptive)](https://starchart.cc/wyx2685/v2node)
