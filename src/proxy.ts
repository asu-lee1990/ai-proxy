import fs from 'fs';
import http, { IncomingHttpHeaders, IncomingMessage, ServerResponse } from 'http';
import https from 'https';
import net from 'net';
import path from 'path';
import tls from 'tls';
import { Duplex } from 'stream';
import { normalizeConfig, ProxyConfig } from './config';
import { HeaderMap, Logger } from './logger';

interface HeaderOverrides {
  [key: string]: string;
}

class SocketReader {
  private readonly chunks: Buffer[] = [];
  private length = 0;
  private readonly waiters: Array<() => void> = [];
  private closed = false;
  private stopped = false;

  constructor(private readonly socket: net.Socket) {
    socket.on('data', (chunk: Buffer) => {
      if (this.stopped) {
        return;
      }
      const buf = Buffer.from(chunk);
      this.chunks.push(buf);
      this.length += buf.length;
      this.flush();
    });

    socket.on('end', () => {
      this.closed = true;
      this.flush();
    });

    socket.on('close', () => {
      this.closed = true;
      this.flush();
    });

    socket.on('error', () => {
      this.closed = true;
      this.flush();
    });
  }

  private flush(): void {
    while (this.waiters.length > 0) {
      const resolve = this.waiters.shift();
      resolve?.();
    }
  }

  private async waitFor(size: number): Promise<void> {
    while (this.length < size) {
      if (this.closed) {
        throw new Error('Socket closed before enough data arrived');
      }
      await new Promise<void>((resolve) => this.waiters.push(resolve));
    }
  }

  private consume(size: number): Buffer {
    const out = Buffer.allocUnsafe(size);
    let offset = 0;

    while (offset < size && this.chunks.length > 0) {
      const first = this.chunks[0];
      const take = Math.min(size - offset, first.length);
      first.copy(out, offset, 0, take);
      offset += take;

      if (take === first.length) {
        this.chunks.shift();
      } else {
        this.chunks[0] = first.subarray(take);
      }
    }

    this.length -= size;
    return out;
  }

  async read(size: number): Promise<Buffer> {
    if (size === 0) {
      return Buffer.alloc(0);
    }
    await this.waitFor(size);
    return this.consume(size);
  }

  detach(): Buffer {
    this.stopped = true;
    const remaining = this.length > 0 ? this.consume(this.length) : Buffer.alloc(0);
    this.socket.removeAllListeners('data');
    this.socket.removeAllListeners('end');
    this.socket.removeAllListeners('close');
    this.socket.removeAllListeners('error');
    return remaining;
  }
}

function parseHeaderOverrides(values: string[] = []): HeaderOverrides {
  const headers: HeaderOverrides = {};

  for (const entry of values) {
    const index = entry.indexOf('=') >= 0 ? entry.indexOf('=') : entry.indexOf(':');
    if (index <= 0) {
      throw new Error(`Invalid header override: ${entry}. Use key=value.`);
    }
    const key = entry.slice(0, index).trim().toLowerCase();
    const value = entry.slice(index + 1).trim();
    if (!key) {
      throw new Error(`Invalid header override key: ${entry}`);
    }
    headers[key] = value;
  }

  return headers;
}

function isHopByHopHeader(name: string): boolean {
  const lower = name.toLowerCase();
  return (
    lower === 'connection' ||
    lower === 'proxy-connection' ||
    lower === 'keep-alive' ||
    lower === 'proxy-authenticate' ||
    lower === 'proxy-authorization' ||
    lower === 'te' ||
    lower === 'trailer' ||
    lower === 'transfer-encoding' ||
    lower === 'upgrade'
  );
}

function headersToObject(headers: IncomingHttpHeaders): HeaderMap {
  const out: HeaderMap = {};
  for (const [key, value] of Object.entries(headers)) {
    out[key] = value;
  }
  return out;
}

function mergeHeaders(base: IncomingHttpHeaders, overrides: HeaderOverrides, removeProxyHeaders = true): HeaderMap {
  const out: HeaderMap = {};
  for (const [key, value] of Object.entries(base)) {
    if (isHopByHopHeader(key)) {
      continue;
    }
    if (removeProxyHeaders && key.toLowerCase().startsWith('proxy-')) {
      continue;
    }
    out[key] = value;
  }

  for (const [key, value] of Object.entries(overrides)) {
    out[key] = value;
  }

  return out;
}

function resolveMaybeRelative(filePath: string): string {
  if (path.isAbsolute(filePath)) {
    return filePath;
  }
  return path.resolve(process.cwd(), filePath);
}

function defaultTlsKeyPath(): string {
  return path.resolve(__dirname, '../ssl/ca.key.pem');
}

function defaultTlsCertPath(): string {
  return path.resolve(__dirname, '../ssl/ca.cert.pem');
}

function formatRequestTarget(req: IncomingMessage): URL | null {
  const rawUrl = req.url ?? '';
  if (!rawUrl) {
    return null;
  }

  try {
    if (/^https?:\/\//i.test(rawUrl)) {
      return new URL(rawUrl);
    }
  } catch {
    return null;
  }

  const host = req.headers.host;
  if (!host) {
    return null;
  }

  try {
    return new URL(rawUrl, `http://${host}`);
  } catch {
    return null;
  }
}

function basicAuthHeader(user: string, pass: string): string {
  return `Basic ${Buffer.from(`${user}:${pass}`, 'utf8').toString('base64')}`;
}

function formatStatusLine(version: string, statusCode?: number, statusMessage?: string): string {
  const code = statusCode ?? 502;
  return `HTTP/${version} ${code} ${statusMessage ?? ''}`.trim();
}

function normalizeAddress(address: string, family: string | undefined): { atyp: number; host: Buffer } {
  if (family === 'IPv6' || address.includes(':')) {
    const segments = address.split(':');
    const raw = Buffer.alloc(16);
    // Minimal IPv6 encoding support for logging/replies. If the address is compressed,
    // we just fall back to 0.0.0.0 in the reply payload.
    if (segments.length === 8 && segments.every((part) => /^[0-9a-fA-F]{0,4}$/.test(part))) {
      for (let i = 0; i < 8; i += 1) {
        raw.writeUInt16BE(parseInt(segments[i] || '0', 16), i * 2);
      }
      return { atyp: 0x04, host: raw };
    }
    return { atyp: 0x01, host: Buffer.from([0, 0, 0, 0]) };
  }

  return {
    atyp: 0x01,
    host: Buffer.from(address.split('.').map((part) => Number.parseInt(part, 10) & 0xff)),
  };
}

function addressToSocksReply(address: string, family: string | undefined, port: number): Buffer {
  const { atyp, host } = normalizeAddress(address, family);
  const reply = Buffer.alloc(4 + host.length + 2);
  reply[0] = 0x05;
  reply[1] = 0x00;
  reply[2] = 0x00;
  reply[3] = atyp;
  host.copy(reply, 4);
  reply.writeUInt16BE(port, 4 + host.length);
  return reply;
}

interface BodyCaptureState {
  chunks: Buffer[];
  bytes: number;
  truncated: boolean;
}

function createBodyCaptureState(): BodyCaptureState {
  return {
    chunks: [],
    bytes: 0,
    truncated: false,
  };
}

function captureBodyChunk(state: BodyCaptureState, chunk: Buffer, limit: number): void {
  if (limit <= 0) {
    state.truncated = state.truncated || chunk.length > 0;
    return;
  }

  if (state.bytes >= limit) {
    state.truncated = true;
    return;
  }

  const remaining = limit - state.bytes;
  const slice = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk;
  state.chunks.push(Buffer.from(slice));
  state.bytes += slice.length;
  if (slice.length < chunk.length) {
    state.truncated = true;
  }
}

function captureBodyBuffer(state: BodyCaptureState): Buffer {
  return state.bytes > 0 ? Buffer.concat(state.chunks, state.bytes) : Buffer.alloc(0);
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatDuration(ms: number): string {
  if (ms < 1000) {
    return `${ms}ms`;
  }
  const seconds = ms / 1000;
  if (seconds < 60) {
    return `${seconds.toFixed(1)}s`;
  }
  const minutes = seconds / 60;
  if (minutes < 60) {
    return `${minutes.toFixed(1)}m`;
  }
  const hours = minutes / 60;
  return `${hours.toFixed(1)}h`;
}

interface ProxyEvent {
  at: string;
  kind: 'request' | 'response' | 'connect' | 'upgrade' | 'socks5' | 'status' | 'error';
  target: string;
  summary: string;
}

export class ProxyServer {
  private readonly config: ProxyConfig;
  private readonly logger: Logger;
  private readonly requestOverrides: HeaderOverrides;
  private readonly responseOverrides: HeaderOverrides;
  private readonly httpAgent: http.Agent;
  private readonly httpsAgent: https.Agent;
  private readonly startedAt = Date.now();
  private readonly recentEvents: ProxyEvent[] = [];
  private readonly stats = {
    requests: 0,
    responses: 0,
    errors: 0,
    connects: 0,
    upgrades: 0,
    socks5: 0,
  };

  constructor(config: ProxyConfig) {
    this.config = normalizeConfig(config);
    this.logger = new Logger(this.config.logDir);
    this.requestOverrides = parseHeaderOverrides(this.config.requestHeaders);
    this.responseOverrides = parseHeaderOverrides(this.config.responseHeaders);
    this.httpAgent = new http.Agent({ keepAlive: true, maxSockets: 64 });
    this.httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 64 });
  }

  private log(message: string): void {
    if (!this.config.quiet) {
      console.log(message);
    }
  }

  private recordEvent(kind: ProxyEvent['kind'], target: string, summary: string): void {
    this.recentEvents.unshift({ at: new Date().toISOString(), kind, target, summary });
    if (this.recentEvents.length > 10) {
      this.recentEvents.pop();
    }
  }

  private buildStatusData(): Record<string, unknown> {
    return {
      service: 'ai-proxy',
      protocol: this.config.protocol,
      host: this.config.host,
      port: this.config.port,
      uptimeMs: Date.now() - this.startedAt,
      uptime: formatDuration(Date.now() - this.startedAt),
      logDir: path.resolve(this.config.logDir),
      bodyCaptureLimitBytes: this.config.bodyCaptureLimitBytes,
      authEnabled: Boolean(this.config.authUser || this.config.authPass),
      stats: this.stats,
      recentEvents: this.recentEvents,
    };
  }

  private renderStatusHtml(): string {
    const status = this.buildStatusData();
    return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>ai-proxy status</title>
  <style>
    body { font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; margin: 24px; background: #0b1020; color: #e5e7eb; }
    .card { max-width: 960px; background: #111827; border: 1px solid #243041; border-radius: 16px; padding: 20px; box-shadow: 0 8px 30px rgba(0,0,0,.25); }
    h1 { margin-top: 0; font-size: 24px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin: 16px 0; }
    .item { background: #0f172a; border: 1px solid #1f2937; border-radius: 12px; padding: 12px; }
    .label { color: #94a3b8; font-size: 12px; margin-bottom: 6px; }
    .value { font-size: 18px; word-break: break-word; }
    pre { background: #0f172a; border: 1px solid #1f2937; border-radius: 12px; padding: 12px; overflow: auto; }
    a { color: #93c5fd; }
    .muted { color: #94a3b8; }
  </style>
</head>
<body>
  <div class="card">
    <h1>ai-proxy 状态页</h1>
    <div class="muted">自动刷新：每 3 秒</div>
    <div class="grid" id="stats"></div>
    <h2>最近事件</h2>
    <pre id="events">${escapeHtml(JSON.stringify(status.recentEvents, null, 2))}</pre>
    <p><a href="/status.json">查看 JSON</a></p>
  </div>
  <script>
    const render = (data) => {
      const stats = document.getElementById('stats');
      stats.innerHTML = '';
      const fields = [
        ['服务', data.service],
        ['协议', data.protocol],
        ['监听', data.host + ':' + data.port],
        ['运行时长', data.uptime],
        ['日志目录', data.logDir],
        ['Body 上限', String(data.bodyCaptureLimitBytes) + ' bytes'],
        ['认证', data.authEnabled ? 'enabled' : 'disabled'],
        ['请求数', data.stats.requests],
        ['响应数', data.stats.responses],
        ['错误数', data.stats.errors],
        ['CONNECT', data.stats.connects],
        ['UPGRADE', data.stats.upgrades],
        ['SOCKS5', data.stats.socks5],
      ];
      for (const [label, value] of fields) {
        const item = document.createElement('div');
        item.className = 'item';
        item.innerHTML = '<div class="label">' + label + '</div><div class="value">' + String(value) + '</div>';
        stats.appendChild(item);
      }
      document.getElementById('events').textContent = JSON.stringify(data.recentEvents, null, 2);
    };

    const refresh = async () => {
      const res = await fetch('/status.json', { cache: 'no-store' });
      render(await res.json());
    };

    refresh();
    setInterval(refresh, 3000);
  </script>
</body>
</html>`;
  }

  private resolveStatusFormat(req: IncomingMessage): 'html' | 'json' | null {
    const rawUrl = req.url ?? '';
    if (/^https?:\/\//i.test(rawUrl)) {
      return null;
    }

    const pathname = rawUrl.split('?', 1)[0];
    if (pathname === '/status.json' || pathname === '/__proxy/status.json') {
      return 'json';
    }
    if (pathname === '/status' || pathname === '/__proxy/status') {
      return 'html';
    }
    return null;
  }

  private sendStatusResponse(req: IncomingMessage, res: ServerResponse): void {
    const format = this.resolveStatusFormat(req);
    if (!format) {
      return;
    }

    const target = this.resolveTarget(req);
    const targetHost = target ? `${target.hostname}${target.port ? `:${target.port}` : ''}` : 'local';
    this.recordEvent('status', targetHost, 'served status page');

    if (format === 'json') {
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify(this.buildStatusData(), null, 2));
      return;
    }

    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(this.renderStatusHtml());
  }

  private authenticateProxy(headers: IncomingHttpHeaders): boolean {
    if (!this.config.authUser || !this.config.authPass) {
      return true;
    }

    const header = headers['proxy-authorization'];
    if (!header || Array.isArray(header)) {
      return false;
    }

    return header === basicAuthHeader(this.config.authUser, this.config.authPass);
  }

  private authenticateSocks5(username: string, password: string): boolean {
    if (!this.config.authUser || !this.config.authPass) {
      return true;
    }
    return username === this.config.authUser && password === this.config.authPass;
  }

  private getTlsOptions(): tls.TlsOptions {
    const keyPath = resolveMaybeRelative(this.config.tlsKeyPath ?? defaultTlsKeyPath());
    const certPath = resolveMaybeRelative(this.config.tlsCertPath ?? defaultTlsCertPath());

    if (!fs.existsSync(keyPath)) {
      throw new Error(`TLS key not found: ${keyPath}`);
    }
    if (!fs.existsSync(certPath)) {
      throw new Error(`TLS certificate not found: ${certPath}`);
    }

    return {
      key: fs.readFileSync(keyPath),
      cert: fs.readFileSync(certPath),
    };
  }

  private sendProxyAuthRequired(res: ServerResponse): void {
    res.writeHead(407, {
      'Proxy-Authenticate': 'Basic realm="ai-proxy"',
      'Content-Type': 'text/plain; charset=utf-8',
    });
    res.end('Proxy authentication required');
  }

  private resolveTarget(req: IncomingMessage): URL | null {
    return formatRequestTarget(req);
  }

  private applyResponseOverrides(headers: IncomingHttpHeaders): HeaderMap {
    const out = headersToObject(headers);
    for (const [key, value] of Object.entries(this.responseOverrides)) {
      out[key] = value;
    }
    return out;
  }

  private buildUpstreamHeaders(req: IncomingMessage, target: URL): HeaderMap {
    const out = mergeHeaders(req.headers, this.requestOverrides);
    out.host = target.port ? `${target.hostname}:${target.port}` : target.hostname;
    return out;
  }

  private forwardHttpRequest(req: IncomingMessage, res: ServerResponse, target: URL): void {
    const targetHost = target.port ? `${target.hostname}:${target.port}` : target.hostname;
    const requestHeaders = this.buildUpstreamHeaders(req, target);
    const requestBody = createBodyCaptureState();
    const responseBody = createBodyCaptureState();
    const client = target.protocol === 'https:' ? https : http;
    const agent = target.protocol === 'https:' ? this.httpsAgent : this.httpAgent;

    this.stats.requests += 1;
    this.recordEvent('request', targetHost, `${req.method ?? 'GET'} ${target.toString()}`);

    const upstreamReq = client.request(
      {
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port || undefined,
        method: req.method,
        path: `${target.pathname}${target.search}` || '/',
        headers: requestHeaders,
        timeout: this.config.timeoutMs,
        agent,
      },
      (upstreamRes) => {
        const responseHeaders = this.applyResponseOverrides(upstreamRes.headers);
        res.writeHead(upstreamRes.statusCode ?? 502, responseHeaders);

        upstreamRes.on('data', (chunk: Buffer) => {
          const buf = Buffer.from(chunk);
          captureBodyChunk(responseBody, buf, this.config.bodyCaptureLimitBytes ?? 0);
          res.write(buf);
        });

        upstreamRes.on('end', () => {
          res.end();
          this.stats.responses += 1;
          const responseLine = formatStatusLine(upstreamRes.httpVersion, upstreamRes.statusCode, upstreamRes.statusMessage);
          this.recordEvent('response', targetHost, responseLine);
          this.logger.logResponse(
            targetHost,
            responseLine,
            responseHeaders,
            captureBodyBuffer(responseBody),
            responseBody.truncated,
          );
        });
      },
    );

    upstreamReq.on('timeout', () => {
      upstreamReq.destroy(new Error('Upstream request timed out'));
    });

    upstreamReq.on('error', (error) => {
      this.stats.errors += 1;
      this.recordEvent('error', targetHost, (error as Error).message);
      if (!res.headersSent) {
        res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
      }
      res.end(`Bad Gateway: ${(error as Error).message}`);
    });

    req.on('data', (chunk: Buffer) => {
      const buf = Buffer.from(chunk);
      captureBodyChunk(requestBody, buf, this.config.bodyCaptureLimitBytes ?? 0);
      upstreamReq.write(buf);
    });

    req.on('end', () => {
      upstreamReq.end();
      const requestLine = `${req.method ?? 'GET'} ${target.toString()} HTTP/${req.httpVersion}`;
      this.logger.logRequest(
        targetHost,
        requestLine,
        requestHeaders,
        captureBodyBuffer(requestBody),
        requestBody.truncated,
      );
    });

    req.on('aborted', () => {
      upstreamReq.destroy(new Error('Client request aborted'));
    });
  }

  private handleConnect(req: IncomingMessage, clientSocket: Duplex, head: Buffer): void {
    if (!this.authenticateProxy(req.headers)) {
      clientSocket.write(
        'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="ai-proxy"\r\n\r\n',
      );
      clientSocket.destroy();
      return;
    }

    const target = req.url ?? '';
    const [hostname, portPart] = target.split(':');
    const port = Number.parseInt(portPart || '443', 10);
    const targetHost = `${hostname}:${port}`;
    this.stats.connects += 1;
    this.recordEvent('connect', targetHost, `CONNECT ${target}`);
    this.log(`[CONNECT] ${targetHost}`);
    this.logger.logRequest(targetHost, `CONNECT ${target} HTTP/${req.httpVersion}`, headersToObject(req.headers));

    const serverSocket = net.connect({ host: hostname, port }, () => {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length > 0) {
        serverSocket.write(head);
      }
      clientSocket.pipe(serverSocket).pipe(clientSocket);
    });

    serverSocket.on('error', (error) => {
      clientSocket.write(`HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n${(error as Error).message}`);
      clientSocket.destroy();
    });

    clientSocket.on('error', () => {
      serverSocket.destroy();
    });
  }

  private handleUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer): void {
    if (!this.authenticateProxy(req.headers)) {
      socket.write('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="ai-proxy"\r\n\r\n');
      socket.destroy();
      return;
    }

    const target = this.resolveTarget(req);
    if (!target) {
      socket.write('HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nUnable to resolve target URL');
      socket.destroy();
      return;
    }

    const targetHost = target.port ? `${target.hostname}:${target.port}` : target.hostname;
    const requestHeaders = this.buildUpstreamHeaders(req, target);
    const client = target.protocol === 'https:' ? https : http;
    const agent = target.protocol === 'https:' ? this.httpsAgent : this.httpAgent;

    this.stats.upgrades += 1;
    this.recordEvent('upgrade', targetHost, `${req.method ?? 'GET'} ${target.toString()}`);

    const upstreamReq = client.request(
      {
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port || undefined,
        method: req.method,
        path: `${target.pathname}${target.search}` || '/',
        headers: {
          ...requestHeaders,
          connection: 'Upgrade',
          upgrade: String(req.headers.upgrade ?? 'websocket'),
        },
        timeout: this.config.timeoutMs,
        agent,
      },
      () => {
        // Normal response isn't expected for upgrades, but keep the socket safe.
      },
    );

    upstreamReq.on('upgrade', (upstreamRes, upstreamSocket, upstreamHead) => {
      const responseHeaders = this.applyResponseOverrides(upstreamRes.headers);
      const headerBlock = Object.entries(responseHeaders)
        .map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(', ') : String(value)}`)
        .join('\r\n');
      socket.write(`HTTP/${upstreamRes.httpVersion} ${upstreamRes.statusCode ?? 101} ${upstreamRes.statusMessage ?? 'Switching Protocols'}\r\n${headerBlock}\r\n\r\n`);
      if (upstreamHead.length > 0) {
        socket.write(upstreamHead);
      }
      if (head.length > 0) {
        upstreamSocket.write(head);
      }
      socket.pipe(upstreamSocket as net.Socket);
      (upstreamSocket as net.Socket).pipe(socket);
      this.logger.logRequest(targetHost, `${req.method ?? 'GET'} ${target.toString()} HTTP/${req.httpVersion}`, requestHeaders);
      this.logger.logResponse(targetHost, formatStatusLine(upstreamRes.httpVersion, upstreamRes.statusCode, upstreamRes.statusMessage), responseHeaders);
    });

    upstreamReq.on('timeout', () => upstreamReq.destroy(new Error('Upstream request timed out')));
    upstreamReq.on('error', (error) => {
      socket.write(`HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n${(error as Error).message}`);
      socket.destroy();
    });

    upstreamReq.end();
  }

  private async handleSocks5Connection(socket: net.Socket): Promise<void> {
    const reader = new SocketReader(socket);

    try {
      const greeting = await reader.read(2);
      if (greeting[0] !== 0x05) {
        socket.destroy();
        return;
      }

      const methodCount = greeting[1];
      const methods = await reader.read(methodCount);
      const supportsNoAuth = methods.includes(0x00);
      const supportsUserPass = methods.includes(0x02);
      const wantUserPass = Boolean(this.config.authUser || this.config.authPass);
      let chosenMethod = 0xff;

      if (wantUserPass && supportsUserPass) {
        chosenMethod = 0x02;
      } else if (!wantUserPass && supportsNoAuth) {
        chosenMethod = 0x00;
      } else if (supportsNoAuth && !wantUserPass) {
        chosenMethod = 0x00;
      }

      socket.write(Buffer.from([0x05, chosenMethod]));
      if (chosenMethod === 0xff) {
        socket.destroy();
        return;
      }

      if (chosenMethod === 0x02) {
        const authVersion = (await reader.read(1))[0];
        if (authVersion !== 0x01) {
          socket.write(Buffer.from([0x01, 0x01]));
          socket.destroy();
          return;
        }

        const userLength = (await reader.read(1))[0];
        const username = (await reader.read(userLength)).toString('utf8');
        const passLength = (await reader.read(1))[0];
        const password = (await reader.read(passLength)).toString('utf8');

        if (!this.authenticateSocks5(username, password)) {
          socket.write(Buffer.from([0x01, 0x01]));
          socket.destroy();
          return;
        }

        socket.write(Buffer.from([0x01, 0x00]));
      }

      const requestHead = await reader.read(4);
      if (requestHead[0] !== 0x05) {
        socket.destroy();
        return;
      }

      const command = requestHead[1];
      const addressType = requestHead[3];
      if (command !== 0x01) {
        socket.write(Buffer.from([0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        socket.destroy();
        return;
      }

      let host = '';
      if (addressType === 0x01) {
        host = Array.from(await reader.read(4)).join('.');
      } else if (addressType === 0x03) {
        const len = (await reader.read(1))[0];
        host = (await reader.read(len)).toString('utf8');
      } else if (addressType === 0x04) {
        const raw = await reader.read(16);
        const parts: string[] = [];
        for (let i = 0; i < 16; i += 2) {
          parts.push(raw.readUInt16BE(i).toString(16));
        }
        host = parts.join(':');
      } else {
        socket.write(Buffer.from([0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        socket.destroy();
        return;
      }

      const port = (await reader.read(2)).readUInt16BE(0);
      const targetHost = `${host}:${port}`;
      this.stats.socks5 += 1;
      this.recordEvent('socks5', targetHost, `CONNECT ${host}:${port}`);
      this.log(`[SOCKS5] CONNECT ${targetHost}`);
      this.logger.logRequest(targetHost, `SOCKS5 CONNECT ${host}:${port}`, { command: 'CONNECT' });

      const upstream = net.connect({ host, port });

      upstream.once('connect', () => {
        const local = upstream.address();
        if (typeof local === 'string') {
          socket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        } else if (local && typeof local === 'object' && 'address' in local) {
          const info = local as net.AddressInfo;
          socket.write(addressToSocksReply(String(info.address), info.family, info.port));
        } else {
          socket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        }

        const remaining = reader.detach();
        if (remaining.length > 0) {
          upstream.write(remaining);
        }

        socket.pipe(upstream);
        upstream.pipe(socket);
      });

      upstream.on('error', (error) => {
        socket.write(Buffer.from([0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        socket.destroy(new Error((error as Error).message));
      });

      socket.on('error', () => {
        upstream.destroy();
      });
    } catch (error) {
      socket.destroy(error as Error);
    }
  }

  start(): http.Server | https.Server | net.Server {
    if (this.config.protocol === 'socks5') {
      const server = net.createServer((socket) => {
        void this.handleSocks5Connection(socket);
      });

      server.on('error', (error) => {
        console.error('[SOCKS5] Server error:', error);
      });

      server.listen(this.config.port, this.config.host, () => {
        this.log(`SOCKS5 proxy listening on socks5://${this.config.host}:${this.config.port}`);
      });
      return server;
    }

    const handler = (req: IncomingMessage, res: ServerResponse) => {
      if (!this.authenticateProxy(req.headers)) {
        this.sendProxyAuthRequired(res);
        return;
      }

      if (this.resolveStatusFormat(req)) {
        this.sendStatusResponse(req, res);
        return;
      }

      const target = this.resolveTarget(req);
      if (!target) {
        res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Unable to resolve target URL');
        return;
      }

      const targetHost = target.port ? `${target.hostname}:${target.port}` : target.hostname;
      this.log(`[HTTP] ${req.method ?? 'GET'} ${target.toString()}`);
      this.forwardHttpRequest(req, res, target);
    };

    const server = this.config.protocol === 'https'
      ? https.createServer(this.getTlsOptions(), handler)
      : http.createServer(handler);

    server.keepAliveTimeout = 60_000;
    server.headersTimeout = Math.max((this.config.timeoutMs ?? 30_000) + 5_000, 65_000);

    server.on('connect', (req, clientSocket, head) => this.handleConnect(req, clientSocket, head));
    server.on('upgrade', (req, socket, head) => this.handleUpgrade(req, socket, head));
    server.on('error', (error) => {
      console.error(`[${this.config.protocol.toUpperCase()}] Server error:`, error);
    });

    server.on('close', () => {
      this.httpAgent.destroy();
      this.httpsAgent.destroy();
    });

    server.listen(this.config.port, this.config.host, () => {
      this.log(`${this.config.protocol.toUpperCase()} proxy listening on ${this.config.protocol}://${this.config.host}:${this.config.port}`);
      this.log(`Log directory: ${path.resolve(this.config.logDir)}`);
    });

    return server;
  }
}
