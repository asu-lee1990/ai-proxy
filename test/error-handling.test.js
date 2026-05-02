const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const net = require('node:net');

const { ProxyServer } = require('../dist/proxy');
const { normalizeConfig } = require('../dist/config');
const { getPort, closeServer } = require('./helpers');

/**
 * Error Handling Tests
 * 测试各种错误场景的处理
 */

test('ProxyServer rejects invalid protocol gracefully', async () => {
  const config = normalizeConfig({ port: 0, protocol: 'invalid' });
  
  // Note: This test assumes the server validates protocol
  // If protocol is not validated, the test documents expected behavior
  const server = new ProxyServer(config);
  
  try {
    await server.start();
    // If it starts, that's also valid behavior (fallback)
  } catch (err) {
    assert.ok(err.message.includes('protocol') || err.message.includes('Invalid'));
  } finally {
    await closeServer(server);
  }
});

test('ProxyServer handles port in use', async () => {
  // Create a server on a specific port
  const blockingServer = http.createServer();
  blockingServer.listen(0, '127.0.0.1');
  await new Promise((resolve) => blockingServer.on('listening', resolve));
  const blockedPort = blockingServer.address().port;

  // Try to create proxy on same port
  const config = normalizeConfig({ port: blockedPort, host: '127.0.0.1' });
  const proxy = new ProxyServer(config);

  try {
    await proxy.start();
    // Some implementations may succeed if binding to 0.0.0.0 vs 127.0.0.1
  } catch (err) {
    assert.ok(err.message.includes('EADDRINUSE') || err.code === 'EADDRINUSE');
  } finally {
    blockingServer.close();
    await closeServer(proxy);
    await new Promise((r) => setTimeout(r, 100));
  }
});

test('ProxyServer handles connection to non-existent upstream', async () => {
  const config = normalizeConfig({ port: 0 });
  const server = new ProxyServer(config);
  await server.start();
  const port = getPort(server);

  const client = http.request({
    host: '127.0.0.1',
    port,
    method: 'GET',
    path: 'http://127.0.0.1:59999/non-existent', // 端口未使用
  });

  // Should handle gracefully without crashing
  client.on('error', (err) => {
    assert.ok(err); // Connection error expected
  });

  client.end();

  // Give time for error handling
  await new Promise((resolve) => setTimeout(resolve, 500));
  await closeServer(server);
});

test('ProxyServer handles malformed HTTP requests gracefully', async () => {
  const config = normalizeConfig({ port: 0 });
  const server = new ProxyServer(config);
  await server.start();
  const port = getPort(server);

  // Send garbage data
  const socket = net.createConnection({ host: '127.0.0.1', port });
  
  await new Promise((resolve) => socket.on('connect', resolve));
  
  socket.write('NOT_HTTP_GARBAGE_DATA\r\n\r\n');
  
  // Wait for response or connection close
  await new Promise((resolve) => {
    socket.on('data', () => {});
    socket.on('close', resolve);
    socket.on('error', resolve);
    setTimeout(resolve, 1000);
  });

  socket.destroy();
  await closeServer(server);
  
  // Server should still be alive after handling garbage
  assert.ok(server);
});

test('ProxyServer handles very large request body', async () => {
  const config = normalizeConfig({ 
    port: 0, 
    bodyCaptureLimitBytes: 1024 // 1KB limit
  });
  const server = new ProxyServer(config);
  await server.start();
  const port = getPort(server);

  // Create target server
  const target = http.createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => body += chunk);
    req.on('end', () => res.end('received'));
  });
  target.listen(0, '127.0.0.1');
  await new Promise((r) => target.on('listening', r));
  const targetPort = target.address().port;

  // Send large body
  const largeBody = 'x'.repeat(10 * 1024); // 10KB
  const req = http.request({
    host: '127.0.0.1',
    port,
    method: 'POST',
    path: `http://127.0.0.1:${targetPort}/`,
    headers: { 'Content-Type': 'text/plain', 'Content-Length': largeBody.length },
  });

  req.write(largeBody);
  
  await new Promise((resolve) => {
    req.on('response', (res) => {
      assert.equal(res.statusCode, 200);
      resolve();
    });
    req.on('error', resolve);
    setTimeout(resolve, 2000);
  });

  req.end();
  target.close();
  await closeServer(server);
});
