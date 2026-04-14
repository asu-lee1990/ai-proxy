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

export class ProxyServer {
  private readonly config: ProxyConfig;
  private readonly logger: Logger;
  private readonly requestOverrides: HeaderOverrides;
  private readonly responseOverrides: HeaderOverrides;

  constructor(config: ProxyConfig) {
    this.config = normalizeConfig(config);
    this.logger = new Logger(this.config.logDir);
    this.requestOverrides = parseHeaderOverrides(this.config.requestHeaders);
    this.responseOverrides = parseHeaderOverrides(this.config.responseHeaders);
  }

  private log(message: string): void {
    if (!this.config.quiet) {
      console.log(message);
    }
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
    const requestBody: Buffer[] = [];
    const isHttpsTarget = target.protocol === 'https:';
    const client = isHttpsTarget ? https : http;

    const upstreamReq = client.request(
      {
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port || undefined,
        method: req.method,
        path: `${target.pathname}${target.search}` || '/',
        headers: requestHeaders,
        timeout: this.config.timeoutMs,
      },
      (upstreamRes) => {
        const responseHeaders = this.applyResponseOverrides(upstreamRes.headers);
        const responseChunks: Buffer[] = [];
        res.writeHead(upstreamRes.statusCode ?? 502, responseHeaders);

        upstreamRes.on('data', (chunk: Buffer) => {
          const buf = Buffer.from(chunk);
          responseChunks.push(buf);
          res.write(buf);
        });

        upstreamRes.on('end', () => {
          res.end();
          const responseLine = formatStatusLine(upstreamRes.httpVersion, upstreamRes.statusCode, upstreamRes.statusMessage);
          this.logger.logResponse(targetHost, responseLine, responseHeaders, Buffer.concat(responseChunks));
        });
      },
    );

    upstreamReq.on('timeout', () => {
      upstreamReq.destroy(new Error('Upstream request timed out'));
    });

    upstreamReq.on('error', (error) => {
      if (!res.headersSent) {
        res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
      }
      res.end(`Bad Gateway: ${(error as Error).message}`);
    });

    req.on('data', (chunk: Buffer) => {
      const buf = Buffer.from(chunk);
      requestBody.push(buf);
      upstreamReq.write(buf);
    });

    req.on('end', () => {
      upstreamReq.end();
      const requestLine = `${req.method ?? 'GET'} ${target.toString()} HTTP/${req.httpVersion}`;
      this.logger.logRequest(targetHost, requestLine, requestHeaders, Buffer.concat(requestBody));
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
    const requestBody: Buffer[] = [];

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
      this.logger.logRequest(targetHost, `${req.method ?? 'GET'} ${target.toString()} HTTP/${req.httpVersion}`, requestHeaders, Buffer.concat(requestBody));
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

    server.on('connect', (req, clientSocket, head) => this.handleConnect(req, clientSocket, head));
    server.on('upgrade', (req, socket, head) => this.handleUpgrade(req, socket, head));
    server.on('error', (error) => {
      console.error(`[${this.config.protocol.toUpperCase()}] Server error:`, error);
    });

    server.listen(this.config.port, this.config.host, () => {
      this.log(`${this.config.protocol.toUpperCase()} proxy listening on ${this.config.protocol}://${this.config.host}:${this.config.port}`);
      this.log(`Log directory: ${path.resolve(this.config.logDir)}`);
    });

    return server;
  }
}
