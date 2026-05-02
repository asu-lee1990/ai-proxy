const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { loadConfig, normalizeConfig } = require('../dist/config');
const { tempDir } = require('./helpers');

/**
 * Config Edge Case Tests
 * 测试配置的边界情况和错误处理
 */

test('normalizeConfig handles empty object', () => {
  const config = normalizeConfig({});
  assert.equal(config.host, '127.0.0.1');
  assert.equal(config.port, 8080);
  assert.equal(config.protocol, 'http');
});

test('normalizeConfig merges custom values with defaults', () => {
  const config = normalizeConfig({ port: 9090, host: '0.0.0.0' });
  assert.equal(config.port, 9090);
  assert.equal(config.host, '0.0.0.0');
  assert.equal(config.protocol, 'http'); // 保持默认
  assert.equal(config.timeoutMs, 30000); // 保持默认
});

test('normalizeConfig handles all supported protocols', () => {
  const protocols = ['http', 'https', 'socks5', 'transparent', 'tun'];
  for (const protocol of protocols) {
    const config = normalizeConfig({ protocol });
    assert.equal(config.protocol, protocol, `Protocol ${protocol} should be accepted`);
  }
});

test('loadConfig handles empty JSON file', () => {
  const root = tempDir('ai-proxy-config-empty-');
  const file = path.join(root, 'proxy.json');
  fs.writeFileSync(file, '{}');

  const config = loadConfig(file);
  assert.equal(config.host, '127.0.0.1'); // 应用默认值
  assert.equal(config.port, 8080);
});

test('loadConfig handles complex nested config', () => {
  const root = tempDir('ai-proxy-config-complex-');
  const file = path.join(root, 'proxy.json');
  const complexConfig = {
    host: '192.168.1.100',
    port: 3128,
    protocol: 'http',
    authUser: 'admin',
    authPass: 'secure_password',
    requestHeaders: ['X-Custom-Header=value'],
    responseHeaders: ['X-Proxy-By=ai-proxy'],
    timeoutMs: 60000,
    bodyCaptureLimitBytes: 512 * 1024,
  };
  fs.writeFileSync(file, JSON.stringify(complexConfig, null, 2));

  const config = loadConfig(file);
  assert.equal(config.host, '192.168.1.100');
  assert.equal(config.port, 3128);
  assert.equal(config.authUser, 'admin');
  assert.equal(config.timeoutMs, 60000);
  assert.deepEqual(config.requestHeaders, ['X-Custom-Header=value']);
});

test('loadConfig throws on invalid JSON', () => {
  const root = tempDir('ai-proxy-config-invalid-');
  const file = path.join(root, 'proxy.json');
  fs.writeFileSync(file, '{ invalid json content }');

  assert.throws(() => loadConfig(file), /JSON/);
});

test('config preserves arrays correctly', () => {
  const config = normalizeConfig({
    requestHeaders: ['X-Header-1=v1', 'X-Header-2=v2'],
    responseHeaders: ['X-Response-1=r1'],
  });

  assert.equal(config.requestHeaders.length, 2);
  assert.equal(config.responseHeaders.length, 1);
  assert.equal(config.requestHeaders[0], 'X-Header-1=v1');
});
