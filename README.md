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

## 接入授权带宽

面板用户名单可带 `grant_bandwidth_limits: [{"id":123,"up_mbps":50,"down_mbps":100}]`。
同一授权 ID 在同一节点上的全部设备共享上下行独立令牌桶，0 表示该方向不限速；命中多个授权时每条上限同时生效。SATLS 转发等待令牌，DynamicGuard 双向 TUN 路径丢弃超额包；与既有凭据及商业账号限速同时执行。不同节点独立计速，不保证跨节点总带宽，令牌桶允许短时突发。

用户名单刷新保留未变更的令牌桶；授权变化在后续数据传输生效，无需重载整个节点。须先部署本版节点再配置面板授权限速，旧节点会忽略新字段。

## SATLS 与 DynamicGuard

SATLS 在服务端终止一层 TLS，支持 FULL 和 Split，业务通过 SMUX v2 和 UoT v2 转发。
HTTP Host 可与 TLS SNI 不同；Split 独立 SNI 使用各自证书，证书缓存支持文件轮换。
Split 配对和重连先发送 HTTP 101，再开放 SMUX 写入并刷新缓存；部分写失败仅保留未发送字节。
SATLS padding 上限为 64 KiB，读取时就限制内存；超限返回 413。普通 HTTP 回落请求流式转发。
Session ID 仍按现有 ±120 秒新鲜度规则校验，本次实现修复没有改变长期重连的协议约束。

DynamicGuard 的配置、DG01 报文、Cookie/PoW、租约与客户端恢复约定见 [DynamicGuard.md](DynamicGuard.md)。
客户端需要复用握手 UDP socket；服务端只接受 0..24 的 PoW 难度配置。数据面使用 AmneziaWG。

相关回归测试：

```bash
go test ./proxy/satls ./proxy/dynamicguard
go test -race ./proxy/satls ./proxy/dynamicguard
```

## Saikyo C 端节点授权与计量

节点通过 `X-Saikyo-Consumer-Leases: 1` 声明支持 C 端短期授权。C 端授权从拉取请求开始计时，最长 45 秒；用户列表刷新不能使用 304 延长授权。既有连接由独立计时器关闭，DynamicGuard 上下行数据路径逐包检查授权，不依赖面板请求超时或 WireGuard peer 清理成功。企业及盒子继续使用既有授权协议。

C 端流量每 5 秒采集并通过 `/api/v1/server/UniProxy/consumer-traffic` 上报。批次 ID、授权 ID、观察时间及原始字节持久化后保持不变；面板确认后才移除。未确认批次、磁盘故障或损坏的队列会阻止 C 端续权；正常停止保留未上报记录，重启先补报。不会将 C 端计量降级到旧流量接口。

必须为每个节点保留可写的独立队列文件。默认路径为 `/var/lib/v2node/consumer-traffic/<面板与节点摘要>.json`，可在该节点配置中设置 `ConsumerTrafficFile`；容器部署应将 `/var/lib/v2node/consumer-traffic` 挂载到持久卷。队列损坏时应先保留文件并处理故障，不得通过删除未确认记录恢复服务。突然断电可能丢失最后一次采集之后、仍在内存中的少量流量。

速率按同一节点上的账号聚合，多个设备共享上传/下载预算；不跨节点协调带宽。SATLS 记录代理传输字节，DynamicGuard C 端记录通过策略与授权检查的 IP 字节，企业/盒子的既有 WireGuard 计量不变。面板按授权冻结的倍率计费，节点只提交原始字节。

测试使用项目指定的 Go 1.26.1：

```bash
GOTOOLCHAIN=go1.26.1 GOEXPERIMENT=jsonv2 go test ./...
GOTOOLCHAIN=go1.26.1 GOEXPERIMENT=jsonv2 go test -race ./common/... ./api/v2board ./core/... ./node ./proxy/dynamicguard
```

## Stars

[![Stargazers over time](https://starchart.cc/wyx2685/v2node.svg?variant=adaptive)](https://starchart.cc/wyx2685/v2node)


### Consumer kernel TUN verification

`TestConsumerKernelTUNEncryptedTrafficExpires` is an opt-in Linux integration test. It sends real encrypted AmneziaWG packets through the production UDP demultiplexer and a kernel TUN into a local UDP application. It checks both traffic directions after the consumer lease expires, exact accepted IP-byte counters, and an unaffected enterprise peer. Client application packet sources are in memory; DG01 control-plane authorization remains covered by separate protocol tests.

Run only in a disposable network namespace with `/dev/net/tun` and `CAP_NET_ADMIN`; the production TUN constructor configures interface addresses/routes. A local container can run the precompiled test without an external network:

```sh
GOTOOLCHAIN=go1.26.1 GOEXPERIMENT=jsonv2 CGO_ENABLED=0 go test -c -o /tmp/consumer-tun.test ./proxy/dynamicguard
docker run --rm --network none --cap-add NET_ADMIN --cap-add MKNOD --device-cgroup-rule 'c 10:200 rwm' -v /tmp/consumer-tun.test:/consumer-tun.test:ro -e SAIKYO_DG_TUN_INTEGRATION=1 golang:1.25-alpine sh -ec 'mkdir -p /dev/net
mknod /dev/net/tun c 10 200
/consumer-tun.test -test.run TestConsumerKernelTUNEncryptedTrafficExpires -test.v -test.timeout 30s'
```

The ordinary test suite skips this test unless explicitly enabled. This verifies the Linux data path, not Android/iOS or a deployed customer connection.
