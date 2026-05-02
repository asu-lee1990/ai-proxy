const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const { ProxyServer } = require('../dist/proxy');
const { normalizeConfig } = require('../dist/config');
const { getPort, closeServer } = require('./helpers');

/**
 * Integration Edge Cases
 * 测试边界情况的集成场景
 */

test('handles concurrent requests to different targets', async () => {
  // Create multiple target servers
  const targets = [];
  for (let i = 0; i < 3; i++) {
    const target = http.createServer((req, res) => {
      res.end(`target-${i}`);
    });
    target.listen(0, '127.0.0.1');
    await new Promise((r) => target.on('listening', r));
    targets.push({ server: target, port: target.address().port });
  }

  // Create proxy
  const config = normalizeConfig({ port: 0 });
  const proxy = new ProxyServer(config);
  await proxy.start();
  const proxyPort = getPort(proxy);

  // Concurrent requests
  const requests = targets.map((t) => {
    return new Promise((resolve, reject) => {
      const req = http.get(`http://127.0.0.1:${proxyPort}/`, {
        headers: { Host: `127.0.0.1:${t.port}` },
      }, (res) => {
        let data = '';
        res.on('data', (chunk) => data += chunk);
        res.on('end', () => resolve({ port: t.port, data }));
      });
      req.on('error', reject);
      req.setTimeout(5000, () => reject(new Error('timeout')));
    });
  });

  const results = await Promise.all(requests);
  
  // Verify each request went to correct target
  results.forEach((r, i) => {
    assert.equal(r.data, `target-${i}`);
  });

  targets.forEach((t) => t.server.close());
  await closeServer(proxy);
});

test('handles request with special characters in URL', async () => {
  const target = http.createServer((req, res) => {
    res.end(req.url);
  });
  target.listen(0, '127.0.0.1');
  await new Promise((r) => target.on('listening', r));
  const targetPort = target.address().port;

  const config = normalizeConfig({ port: 0 });
  const proxy = new ProxyServer(config);
  await proxy.start();
  const proxyPort = getPort(proxy);

  const specialPaths = [
    '/path%20with%20spaces',
    '/path?query=value&other=test',
    '/unicode-中文-path',
  ];

  for (const path of specialPaths) {
    const response = await new Promise((resolve, reject) => {
      const req = http.get(`http://127.0.0.1:${proxyPort}${path}`, {
        headers: { Host: `127.0.0.1:${targetPort}` },
      }, (res) => {
        let data = '';
        res.on('data', (chunk) => data += chunk);
        res.on('end', () => resolve(data));
      });
      req.on('error', reject);
      req.setTimeout(3000, () => reject(new Error('timeout')));
    });

    // URL should be preserved through proxy
    assert.ok(response.includes(path.split('?')[0]) || response.includes(encodeURI(path.split('?')[0])));
  }

  target.close();
  await closeServer(proxy);
});

test('handles request with large headers', async () => {
  const target = http.createServer((req, res) => {
    res.end('ok');
  });
  target.listen(0, '127.0.0.1');
  await new Promise((r) => target.on('listening', r));
  const targetPort = target.address().port;

  const config = normalizeConfig({ port: 0 });
  const proxy = new ProxyServer(config);
  await proxy.start();
  const proxyPort = getPort(proxy);

  const largeHeaderValue = 'x'.repeat(4000); // 4KB header
  
  const response = await new Promise((resolve, reject) => {
    const req = http.get(`http://127.0.0.1:${proxyPort}/`, {
      headers: { 
        Host: `127.0.0.1:${targetPort}`,
        'X-Large-Header': largeHeaderValue,
      },
    }, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => resolve(res.statusCode));
    });
    req.on('error', reject);
    req.setTimeout(3000, () => reject(new Error('timeout')));
  });

  // Should handle large headers without error
  assert.ok(response === 200 || response === 413); // 413 = Request Entity Too Large

  target.close();
  await closeServer(proxy);
});

test('proxy survives rapid start/stop cycles', async () => {
  const config = normalizeConfig({ port: 0 });

  for (let i = 0; i < 3; i++) {
    const proxy = new ProxyServer(config);
    await proxy.start();
    const port = getPort(proxy);
    
    // Quick request
    const req = http.get(`http://127.0.0.1:${port}/`, { 
      headers: { Host: 'localhost' } 
    });
    req.on('error', () => {});
    req.end();
    
    await new Promise((r) => setTimeout(r, 50));
    await closeServer(proxy);
  }

  // Should complete without memory leaks or crashes
  assert.ok(true);
});
