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

相关回归测试：

```bash
go test ./proxy/satls ./proxy/dynamicguard
go test -race ./proxy/satls ./proxy/dynamicguard
```

## Stars

[![Stargazers over time](https://starchart.cc/wyx2685/v2node.svg?variant=adaptive)](https://starchart.cc/wyx2685/v2node)
