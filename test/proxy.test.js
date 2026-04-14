const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const tls = require('node:tls');
const net = require('node:net');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { once } = require('node:events');

const { ProxyServer } = require('../dist/proxy');
const { normalizeConfig } = require('../dist/config');
const { closeServer, createBufferedReader, getPort, listen, tempDir } = require('./helpers');

async function createTargetServer(handler) {
  const server = http.createServer(handler);
  server.listen(0, '127.0.0.1');
  await listen(server);
  return server;
}

async function createHttpsTargetServer(root) {
  const caKey = path.join(root, 'target-ca.key.pem');
  const caCert = path.join(root, 'target-ca.cert.pem');
  const serverKey = path.join(root, 'target.key.pem');
  const serverCert = path.join(root, 'target.cert.pem');
  const csr = path.join(root, 'target.csr.pem');
  const ext = path.join(root, 'target.ext.cnf');

  execFileSync(
    'openssl',
    ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', caKey, '-out', caCert, '-subj', '/CN=ai-proxy-test-ca', '-days', '2'],
    { stdio: 'pipe' },
  );

  fs.writeFileSync(
    ext,
    [
      '[v3_req]',
      'basicConstraints = CA:FALSE',
      'keyUsage = digitalSignature, keyEncipherment',
      'extendedKeyUsage = serverAuth',
      'subjectAltName = @alt_names',
      '',
      '[alt_names]',
      'DNS.1 = localhost',
      'IP.1 = 127.0.0.1',
      '',
    ].join('\n'),
  );

  execFileSync(
    'openssl',
    ['req', '-new', '-nodes', '-newkey', 'rsa:2048', '-keyout', serverKey, '-out', csr, '-subj', '/CN=localhost'],
    { stdio: 'pipe' },
  );

  execFileSync(
    'openssl',
    ['x509', '-req', '-in', csr, '-CA', caCert, '-CAkey', caKey, '-CAcreateserial', '-out', serverCert, '-days', '2', '-sha256', '-extfile', ext, '-extensions', 'v3_req'],
    { stdio: 'pipe', cwd: root },
  );

  const server = https.createServer(
    {
      key: fs.readFileSync(serverKey),
      cert: fs.readFileSync(serverCert),
    },
    (req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
      res.end(`https-target:${req.url}`);
    },
  );

  server.listen(0, '127.0.0.1');
  await listen(server);
  return { server, caCert };
}

async function createProxyServer(protocol, logDir, extra = {}) {
  const proxy = new ProxyServer(
    normalizeConfig({
      host: '127.0.0.1',
      port: 0,
      protocol,
      logDir,
      ...extra,
    }),
  );
  const server = proxy.start();
  await listen(server);
  return server;
}

function httpRequest(options, body) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
      res.on('end', () => {
        resolve({
          headers: res.headers,
          statusCode: res.statusCode,
          body: Buffer.concat(chunks).toString('utf8'),
        });
      });
    });

    req.on('error', reject);
    if (body) {
      req.end(body);
    } else {
      req.end();
    }
  });
}

test('HTTP proxy forwards absolute-form requests', async () => {
  const root = tempDir('ai-proxy-http-');
  const logDir = path.join(root, 'log');

  const target = await createTargetServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
    res.end(`target:${req.url}`);
  });

  const proxy = await createProxyServer('http', logDir);

  try {
    const targetPort = getPort(target);
    const proxyPort = getPort(proxy);

    const result = await httpRequest({
      host: '127.0.0.1',
      port: proxyPort,
      method: 'GET',
      path: `http://127.0.0.1:${targetPort}/hello?x=1`,
    });

    assert.equal(result.statusCode, 200);
    assert.equal(result.body, 'target:/hello?x=1');

    const reqDir = path.join(logDir, 'req', `127.0.0.1_${targetPort}`);
    assert.ok(fs.existsSync(reqDir));
    assert.equal(fs.readdirSync(reqDir).filter((name) => name.endsWith('.req')).length, 1);
  } finally {
    await closeServer(proxy);
    await closeServer(target);
  }
});


test('transparent HTTP proxy forwards origin-form requests', async () => {
  const root = tempDir('ai-proxy-transparent-http-');
  const logDir = path.join(root, 'log');

  const target = await createTargetServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
    res.end(`transparent-http:${req.url}`);
  });

  const proxy = await createProxyServer('transparent', logDir, {
    transparentHttpPort: getPort(target),
  });

  try {
    const targetPort = getPort(target);
    const proxyPort = getPort(proxy);

    const result = await httpRequest({
      host: '127.0.0.1',
      port: proxyPort,
      method: 'GET',
      path: '/hello?x=1',
      headers: { Host: `127.0.0.1:${targetPort}` },
    });

    assert.equal(result.statusCode, 200);
    assert.equal(result.body, 'transparent-http:/hello?x=1');
  } finally {
    await closeServer(proxy);
    await closeServer(target);
  }
});


test('HTTP proxy serves a status UI and JSON payload', async () => {
  const root = tempDir('ai-proxy-status-');
  const logDir = path.join(root, 'log');
  const proxy = await createProxyServer('http', logDir);

  try {
    const proxyPort = getPort(proxy);

    const html = await httpRequest({
      host: '127.0.0.1',
      port: proxyPort,
      method: 'GET',
      path: '/status',
    });

    assert.equal(html.statusCode, 200);
    assert.match(html.body, /ai-proxy 状态页/);
    assert.match(html.body, /TUN 活跃会话/);

    const json = await httpRequest({
      host: '127.0.0.1',
      port: proxyPort,
      method: 'GET',
      path: '/status.json',
      headers: { accept: 'application/json' },
    });

    assert.equal(json.statusCode, 200);
    const payload = JSON.parse(json.body);
    assert.equal(payload.service, 'ai-proxy');
    assert.equal(payload.protocol, 'http');
    assert.ok(Array.isArray(payload.recentEvents));
    assert.ok(Array.isArray(payload.tunSessions));
    assert.ok(Array.isArray(payload.tunSessionLines));
    if (payload.tunSessionLines.length > 0) {
      assert.match(payload.tunSessionLines[0], /->/);
    }
  } finally {
    await closeServer(proxy);
  }
});

test('MITM HTTPS CONNECT decrypts and forwards requests', async () => {
  const root = tempDir('ai-proxy-mitm-');
  const logDir = path.join(root, 'log');
  const proxyCaKey = path.join(__dirname, '..', 'ssl', 'ca.key.pem');
  const proxyCaCert = path.join(__dirname, '..', 'ssl', 'ca.cert.pem');

  const target = await createHttpsTargetServer(root);
  const proxy = await createProxyServer('http', logDir, {
    mitmEnabled: true,
    mitmCaKeyPath: proxyCaKey,
    mitmCaCertPath: proxyCaCert,
    mitmCacheDir: path.join(root, 'mitm-cache'),
  });

  try {
    const targetPort = getPort(target.server);
    const proxyPort = getPort(proxy);
    const connectResponse = await new Promise((resolve, reject) => {
      const socket = net.connect(proxyPort, '127.0.0.1');
      const connectLine = `CONNECT localhost:${targetPort} HTTP/1.1\r\nHost: localhost:${targetPort}\r\n\r\n`;
      let buffer = '';
      let tlsSocket = null;
      const chunks = [];
      let done = false;
      const timeout = setTimeout(() => settle(new Error('MITM client timeout')), 10000);

      function settle(err, value) {
        if (done) {
          return;
        }
        done = true;
        clearTimeout(timeout);
        socket.destroy();
        if (tlsSocket) {
          tlsSocket.destroy();
        }
        if (err) {
          reject(err);
        } else {
          resolve(value);
        }
      }

      socket.on('connect', () => {
        socket.write(connectLine);
      });

      socket.on('data', (chunk) => {
        buffer += chunk.toString('utf8');
        if (!buffer.includes('\r\n\r\n') || tlsSocket) {
          return;
        }

        assert.match(buffer, /200 Connection Established/);
        tlsSocket = tls.connect({
          socket,
          servername: 'localhost',
          ca: fs.readFileSync(proxyCaCert),
          rejectUnauthorized: true,
        });

        tlsSocket.on('secureConnect', () => {
          tlsSocket.write(`GET /hello?x=1 HTTP/1.1\r\nHost: localhost:${targetPort}\r\nConnection: close\r\n\r\n`);
        });

        tlsSocket.on('data', (data) => {
          chunks.push(Buffer.from(data));
        });

        tlsSocket.on('end', () => {
          settle(null, Buffer.concat(chunks).toString('utf8'));
        });

        tlsSocket.on('error', (err) => settle(err));
      });

      socket.on('error', (err) => settle(err));
    });

    assert.match(connectResponse, /https-target:\/hello\?x=1/);

    const reqDir = path.join(logDir, 'req', `localhost_${targetPort}`);
    assert.ok(fs.existsSync(reqDir));
    assert.ok(fs.readdirSync(reqDir).some((name) => name.endsWith('.req')));
  } finally {
    await closeServer(proxy);
    await closeServer(target.server);
  }
});


test('SOCKS5 proxy tunnels TCP traffic', async () => {
  const root = tempDir('ai-proxy-socks-');
  const logDir = path.join(root, 'log');

  const target = await createTargetServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8', connection: 'close' });
    res.end(`socks-ok:${req.url}`);
  });

  const proxy = await createProxyServer('socks5', logDir);

  try {
    const targetPort = getPort(target);
    const proxyPort = getPort(proxy);

    const socket = net.connect(proxyPort, '127.0.0.1');
    await once(socket, 'connect');
    const reader = createBufferedReader(socket);

    socket.write(Buffer.from([0x05, 0x01, 0x00]));
    const greeting = await reader.readExact(2);
    assert.deepEqual([...greeting], [0x05, 0x00]);

    socket.write(Buffer.from([
      0x05,
      0x01,
      0x00,
      0x01,
      127,
      0,
      0,
      1,
      (targetPort >> 8) & 0xff,
      targetPort & 0xff,
    ]));

    const connectReply = await reader.readExact(10);
    assert.equal(connectReply[0], 0x05);
    assert.equal(connectReply[1], 0x00);

    socket.write(
      `GET /through-socks HTTP/1.1\r\nHost: 127.0.0.1:${targetPort}\r\nConnection: close\r\n\r\n`,
    );

    const response = await reader.readAll();
    assert.match(response.toString('utf8'), /socks-ok:\/through-socks/);

    socket.destroy();

    const reqDir = path.join(logDir, 'req', `127.0.0.1_${targetPort}`);
    assert.ok(fs.existsSync(reqDir));
    assert.equal(fs.readdirSync(reqDir).filter((name) => name.endsWith('.req')).length, 1);
  } finally {
    await closeServer(proxy);
    await closeServer(target);
  }
});
