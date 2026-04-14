const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const path = require('node:path');
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

async function createProxyServer(protocol, logDir) {
  const proxy = new ProxyServer(
    normalizeConfig({
      host: '127.0.0.1',
      port: 0,
      protocol,
      logDir,
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
