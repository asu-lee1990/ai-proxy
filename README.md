# ai-proxy

一个功能强大的 TypeScript 代理服务器，支持 HTTP/HTTPS/SOCKS5 协议、透明代理、TUN 模式以及 MITM HTTPS 解密。

## 功能特性

- **HTTP/HTTPS/SOCKS5 代理** - 标准代理协议支持
- **透明代理模式** - 无需客户端配置，通过 iptables 重定向流量
- **TUN 模式（高级功能）** - 内核级虚拟网络接口，捕获所有 IP 层流量
- **MITM HTTPS 解密** - 支持中间人攻击方式解密 HTTPS 流量（需配置 CA 证书）
- **状态监控页面** - 实时查看代理状态、连接信息
- **完整日志系统** - 自动记录请求/响应，支持大文件持久化
- **可编程配置** - JSON 配置文件 + 命令行参数双重支持

## 安装

```bash
# 克隆项目
git clone <repository-url>
cd ai-proxy

# 安装依赖
npm install

# 编译 TypeScript
npm run build
```

## 使用方法

### 基本 HTTP 代理

```bash
# 启动 HTTP 代理服务器（默认监听 127.0.0.1:8080）
npm start

# 自定义端口和主机
npm start -- --host 0.0.0.0 --port 3128
```

### HTTPS 代理

```bash
# 使用自签名证书启动 HTTPS 代理
npm start -- --protocol https --tls-key ./ssl/server.key.pem --tls-cert ./ssl/server.cert.pem

# 客户端需要配置信任自签名证书，或使用 --insecure 选项
```

### SOCKS5 代理

```bash
npm start -- --protocol socks5 --host 0.0.0.0 --port 1080

# 配置用户名密码认证
npm start -- --protocol socks5 --auth-user admin --auth-pass secret
```

### TUN 模式（需要 root 权限）

TUN 模式创建一个虚拟网络接口，捕获操作系统发出的所有 IP 层流量。

```bash
# 方法1: 使用 tun-run.sh 脚本（推荐）
sudo ./scripts/tun-run.sh --iface ai0 -- npm start -- --protocol tun --host 127.0.0.1 --port 8080

# 方法2: 手动配置 TUN 设备后启动
# 1. 创建 TUN 设备
sudo ip tuntap add dev tun0 mode tun user $(whoami)
sudo ip link set tun0 up

# 2. 获取文件描述符并启动代理（需要特殊处理）
# 参考 scripts/tun-helper.c 获取 TUN 文件描述符

# 参数说明
--tun-fd <fd>           # 传入已打开的 TUN 文件描述符
--tun-buffer-size <bytes>  # TUN 数据包读取缓冲区大小（默认 65535）
```

### 透明代理

透明代理模式通过 iptables 规则将系统流量重定向到代理服务器，无需在应用程序中配置代理设置。

```bash
# 1. 配置 iptables 规则（需要 root 权限）
sudo ./scripts/tun-deploy.sh

# 默认使用 OUTPUT 模式（本机流量）
# 如需代理局域网内其他设备流量，使用 PREROUTING 模式：
PROXY_PORT=8080 MODE=prerouting sudo ./scripts/tun-deploy.sh

# 2. 启动透明代理服务器
npm start -- --protocol transparent --host 127.0.0.1 --port 8080

# 可选: 启用 MITM HTTPS 解密
npm start -- --protocol transparent --host 127.0.0.1 --port 8080 --mitm \
  --mitm-ca-key ./ssl/ca.key.pem \
  --mitm-ca-cert ./ssl/ca.cert.pem \
  --mitm-cache-dir ./ssl/mitm-cache
```

**清理 iptables 规则：**
```bash
# 透明代理会创建一个名为 AI_PROXY_TUN 的 iptables chain
# 清理规则：
sudo iptables -t nat -F AI_PROXY_TUN
sudo iptables -t nat -D OUTPUT -j AI_PROXY_TUN 2>/dev/null || true
sudo iptables -t nat -X AI_PROXY_TUN 2>/dev/null || true
```

## 配置

### 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-c, --config <path>` | 配置文件路径 | - |
| `--host <host>` | 监听主机 | 127.0.0.1 |
| `--port <port>` | 监听端口 | 8080 |
| `--protocol <protocol>` | 协议: http, https, socks5, transparent, tun | http |
| `--log-dir <path>` | 日志目录 | ./log |
| `--auth-user <user>` | 认证用户名 | - |
| `--auth-pass <pass>` | 认证密码 | - |
| `--tls-key <path>` | TLS 私钥路径 (HTTPS) | - |
| `--tls-cert <path>` | TLS 证书路径 (HTTPS) | - |
| `--mitm` | 启用 HTTPS MITM 解密 | false |
| `--mitm-insecure-upstream` | MITM 时禁用上游证书验证 | false |
| `--mitm-ca-key <path>` | MITM CA 私钥路径 | - |
| `--mitm-ca-cert <path>` | MITM CA 证书路径 | - |
| `--mitm-cache-dir <path>` | MITM 证书缓存目录 | ./ssl/mitm-cache |
| `--transparent-http-port <port>` | 透明代理 HTTP 回退端口 | 80 |
| `--transparent-tls-port <port>` | 透明代理 TLS 回退端口 | 443 |
| `--tun-fd <fd>` | TUN 文件描述符 | - |
| `--tun-buffer-size <bytes>` | TUN 读取缓冲区大小 | 65535 |
| `--request-header <header>` | 添加上游请求头 (key=value) | - |
| `--response-header <header>` | 注入响应头 (key=value) | - |
| `--timeout-ms <ms>` | 上游超时时间(毫秒) | 30000 |
| `--log-body-max-bytes <bytes>` | 请求/响应体最大日志字节数 | 262144 |
| `--quiet` | 禁用控制台日志 | false |

### 配置文件

配置文件支持 JSON 格式：

```json
{
  "host": "0.0.0.0",
  "port": 8080,
  "protocol": "http",
  "logDir": "./log",
  "authUser": "admin",
  "authPass": "secret",
  "mitmEnabled": true,
  "mitmCaKeyPath": "./ssl/ca.key.pem",
  "mitmCaCertPath": "./ssl/ca.cert.pem",
  "requestHeaders": ["X-Custom-Header=value"],
  "timeoutMs": 30000
}
```

使用配置文件启动：
```bash
npm start -- --config ./proxy.config.json
```

## 架构设计

ai-proxy 采用模块化设计，核心组件包括：

### ProxyServer

`ProxyServer` 是主入口类，负责：
- 创建 HTTP/HTTPS/SOCKS5 代理服务器
- 管理各种代理协议的处理逻辑
- 集成 MITM 中间人攻击解密功能
- 支持透明代理的流量识别和转发

### TunSessionManager

`TunSessionManager` 是 TUN 模式的核心，负责：
- 从 TUN 设备读取原始 IP 数据包
- 解析 IPv4 和 TCP 协议头
- 维护 TCP 会话状态机（SYN、SYN-ACK、ESTABLISHED、FIN 等）
- 管理会话生命周期和数据包重组

### TunTcpBridge

`TunTcpBridge` 负责 TUN 模式下的 TCP 桥接：
- 将 TUN 会话的客户端数据桥接到真实的目标服务器
- 处理客户端到服务器 (c2s) 和服务器到客户端 (s2c) 的数据流
- 维护完整的 TCP 字节流，支持数据重传和顺序保证

```
┌─────────────────────────────────────────────────────────────────┐
│                        ai-proxy                                  │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │ HTTP Proxy  │  │HTTPS/SOCKS5 │  │    Transparent Proxy    │  │
│  │   Server    │  │   Server    │  │                         │  │
│  └──────┬──────┘  └──────┬──────┘  └─────────────────────────┘  │
│         │                │                                      │
│         └────────────────┴────────────────┬────────────────────┘
│                                           │                      │
│  ┌──────────────────────────────────────┐ │  ┌────────────────┐  │
│  │           ProxyServer                 │◄┘  │ MITM Decrypt │  │
│  │  - Request routing                   │    │ - CA signing │  │
│  │  - Header manipulation              │    │ - Cert cache │  │
│  │  - Auth handling                     │    └────────────────┘  │
│  └──────────────────────────────────────┘                       │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    TUN Mode (Optional)                    │   │
│  │  ┌─────────────────┐      ┌────────────────────────────┐  │   │
│  │  │ TunSessionManager│     │      TunTcpBridge          │  │   │
│  │  │ - IP packet parse │◄────►│ - TCP session bridging    │  │   │
│  │  │ - TCP state mgmt  │     │ - c2s/s2c data flow        │  │   │
│  │  │ - Session tracking│     │ - Byte stream handling     │  │   │
│  │  └─────────────────┘      └────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐│
│  │                         Logger                              ││
│  │  - Request/Response logging    - Binary body persistence    ││
│  │  - Structured storage          - Automatic rotation         ││
│  └────────────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────────┘
```

## 测试

```bash
# 编译并运行测试
npm test

# 仅编译
npm run build

# 开发模式（热重载）
npm run dev
```

测试文件位于 `test/` 目录，包含：
- 代理连接测试
- 协议处理测试
- 日志记录测试

## SSL/TLS 证书生成

如需使用 MITM 功能，需要生成 CA 证书：

```bash
# 创建证书目录
mkdir -p ssl/mitm-cache

# 生成 CA 私钥和证书
openssl genrsa -out ssl/ca.key.pem 2048
openssl req -x509 -new -nodes -key ssl/ca.key.pem -sha256 -days 3650 -out ssl/ca.cert.pem \
  -subj "/C=CN/O=ai-proxy/CN=ai-proxy CA"

# 生成服务器证书（用于 HTTPS 监听）
openssl genrsa -out ssl/server.key.pem 2048
openssl req -new -key ssl/server.key.pem -out ssl/server.csr \
  -subj "/C=CN/O=ai-proxy/CN=localhost"
openssl x509 -req -in ssl/server.csr -CA ssl/ca.cert.pem -CAkey ssl/ca.key.pem \
  -CAcreateserial -out ssl/server.cert.pem -days 365 -sha256
```

将 `ssl/ca.cert.pem` 安装到客户端信任库，即可自动信任 MITM 生成的所有证书。

## 许可证

MIT License

---

**项目状态**: 活跃开发中

**问题反馈**: 请通过 GitHub Issues 提交
