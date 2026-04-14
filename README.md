# ai-proxy

一个 TypeScript 写的代理程序，支持：

- HTTP 代理
- HTTPS 代理（代理服务本身走 TLS）
- SOCKS5 代理
- 透明代理（HTTP 自动分流；HTTPS 可用于 MITM / 隧道式接入）
- 基础认证
- 请求 / 响应日志落盘
- 请求体 / 响应体大小上限控制
- HTTP CONNECT 隧道
- HTTPS CONNECT MITM 解密
- WebSocket Upgrade 转发
- 简单状态页：`/status` 和 `/status.json`

## 安装

```bash
npm install
npm run build
```

## 测试

```bash
npm test
```

这会先执行 TypeScript 编译，再跑配置、日志和代理转发的单元 / 集成测试。

## 启动

### HTTP 代理

```bash
npm start -- --protocol http --host 127.0.0.1 --port 8080
```

### HTTPS 代理

默认读取项目里的 `ssl/ca.key.pem` 和 `ssl/ca.cert.pem` 作为监听证书：

```bash
npm start -- --protocol https --host 127.0.0.1 --port 8443
```

### SOCKS5 代理

```bash
npm start -- --protocol socks5 --host 127.0.0.1 --port 1080
```

### 透明代理

透明模式用于接收被系统重定向过来的原始 TCP 流量，适合作为 TUN / iptables / 端口重定向后的接入点，主要处理：

- 普通 HTTP 请求：按 Host 头转发
- HTTPS ClientHello：可用于按 SNI 分流的实验性接入

```bash
npm start -- \
  --protocol transparent \
  --host 0.0.0.0 \
  --port 8080
```

如果要在透明模式下做 HTTPS 解密：

```bash
npm start -- \
  --protocol transparent \
  --host 0.0.0.0 \
  --port 8080 \
  --mitm \
  --mitm-ca-key ./ssl/ca.key.pem \
  --mitm-ca-cert ./ssl/ca.cert.pem \
  --mitm-cache-dir ./ssl/mitm-cache
```

透明模式默认会把 HTTPS 上游连接到 `:443`，HTTP 以 Host 头里的端口为准。可以用：

- `--transparent-http-port`
- `--transparent-tls-port`

来调试特殊环境下的回退端口。

### 开启 MITM 解密（CONNECT）

MITM 模式用于解密 HTTPS CONNECT 流量，并把请求 / 响应记录下来。

```bash
npm start -- \
  --protocol http \
  --host 127.0.0.1 \
  --port 8080 \
  --mitm \
  --mitm-ca-key ./ssl/ca.key.pem \
  --mitm-ca-cert ./ssl/ca.cert.pem \
  --mitm-cache-dir ./ssl/mitm-cache
```

如果你的上游环境是自签名证书或实验环境，也可以显式放宽上游证书校验：

```bash
npm start -- --mitm --mitm-insecure-upstream
```

## 状态页

代理启动后，可以直接访问：

- `http://127.0.0.1:8080/status`
- `http://127.0.0.1:8080/status.json`

如果前面还有 Nginx，也可以把这两个路径转发过去。

状态页会显示：

- 协议、主机、端口
- 运行时长
- 日志目录
- body 捕获上限
- 认证是否开启
- MITM / 透明代理开关
- 请求 / 响应 / 错误 / CONNECT / MITM / UPGRADE / SOCKS5 / 透明连接计数
- 最近 10 条事件

## 认证

```bash
npm start -- --protocol http --auth-user proxyuser --auth-pass proxypass
```

SOCKS5 模式下如果提供了 `--auth-user` / `--auth-pass`，会启用用户名密码认证。

## 配置文件

```json
{
  "host": "127.0.0.1",
  "port": 8080,
  "protocol": "http",
  "logDir": "./log",
  "authUser": "proxyuser",
  "authPass": "proxypass",
  "mitmEnabled": true,
  "mitmInsecureUpstream": true,
  "mitmCaKeyPath": "./ssl/ca.key.pem",
  "mitmCaCertPath": "./ssl/ca.cert.pem",
  "mitmCacheDir": "./ssl/mitm-cache",
  "transparentHttpPort": 80,
  "transparentTlsPort": 443,
  "requestHeaders": ["x-added-request=1"],
  "responseHeaders": ["x-added-response=1"],
  "timeoutMs": 30000,
  "bodyCaptureLimitBytes": 262144
}
```

启动：

```bash
npm start -- --config ./proxy.config.json
```

## 日志

日志会写到：

- `./log/req/<host>/...req`
- `./log/rsp/<host>/...rsp`
- `./log/body/req/<host>/...`
- `./log/body/rsp/<host>/...`

当响应包含较大的二进制内容或 `content-disposition` 时，正文会保存成文件，日志里会写 `file://...` 路径。

默认会把请求 / 响应体截断到 `256 KiB`，避免大流量把内存和日志撑爆。可以通过 `--log-body-max-bytes` 调整。

## 示例

### HTTP 代理测试

```bash
curl -x http://127.0.0.1:8080 http://example.com/
```

### HTTPS 代理测试

```bash
curl -x https://127.0.0.1:8443 --proxy-insecure https://example.com/
```

### SOCKS5 代理测试

```bash
curl --socks5 127.0.0.1:1080 http://example.com/
```

### 透明代理测试

HTTP 透明代理时，客户端仍然发普通 HTTP 请求，只是被系统重定向到代理：

```bash
curl -H 'Host: example.com' http://127.0.0.1:8080/
```

HTTPS 透明代理时，客户端直接做 TLS 握手，代理按 SNI 分流：

```bash
curl --cacert ./ssl/ca.cert.pem https://example.com/
```

### MITM 测试（CONNECT）

当 `--mitm` 开启后，先把 proxy CA 证书交给客户端信任：

```bash
curl -x http://127.0.0.1:8080 --cacert ./ssl/ca.cert.pem https://example.com/
```

## 目录结构

- `src/`：TypeScript 源码
- `dist/`：编译后的 JS 输出
- `test/`：测试
- `ssl/`：CA 根证书和 MITM 缓存
- `log/`：请求 / 响应日志
- `log-webui/`：状态页日志

## 发布 / CI

- 推送到 `main` 后，GitHub Actions 会自动执行 `npm ci` 和 `npm run build`。
- 本地发布前建议先跑一遍：

```bash
npm ci
npm run build
```

- 如果要发版，建议先更新 `package.json` 的版本号，再打 tag。
