# ai-proxy

一个 TypeScript 写的代理程序，支持：

- HTTP 代理
- HTTPS 代理（代理服务本身走 TLS）
- SOCKS5 代理
- 基础认证
- 请求 / 响应日志落盘
- HTTP CONNECT 隧道
- WebSocket Upgrade 转发

## 安装

```bash
npm install
npm run build
```

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
  "requestHeaders": ["x-added-request=1"],
  "responseHeaders": ["x-added-response=1"],
  "timeoutMs": 30000
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
