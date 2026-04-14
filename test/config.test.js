const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { loadConfig, normalizeConfig } = require('../dist/config');
const { tempDir } = require('./helpers');

test('normalizeConfig applies safe defaults', () => {
  const config = normalizeConfig();

  assert.deepEqual(config, {
    host: '127.0.0.1',
    port: 8080,
    protocol: 'http',
    logDir: './log',
    authUser: undefined,
    authPass: undefined,
    tlsKeyPath: undefined,
    tlsCertPath: undefined,
    mitmEnabled: false,
    mitmInsecureUpstream: false,
    mitmCaKeyPath: undefined,
    mitmCaCertPath: undefined,
    mitmCacheDir: './ssl/mitm-cache',
    transparentHttpPort: 80,
    transparentTlsPort: 443,
    requestHeaders: [],
    responseHeaders: [],
    timeoutMs: 30000,
    bodyCaptureLimitBytes: 256 * 1024,
    quiet: false,
  });
});

test('loadConfig reads a partial JSON file and normalizes it', () => {
  const root = tempDir('ai-proxy-config-');
  const file = path.join(root, 'proxy.json');
  fs.writeFileSync(file, JSON.stringify({ port: 9001, protocol: 'socks5', authUser: 'u' }, null, 2));

  const config = loadConfig(file);

  assert.equal(config.host, '127.0.0.1');
  assert.equal(config.port, 9001);
  assert.equal(config.protocol, 'socks5');
  assert.equal(config.authUser, 'u');
  assert.equal(config.requestHeaders.length, 0);
  assert.equal(config.responseHeaders.length, 0);
  assert.equal(config.timeoutMs, 30000);
});

test('loadConfig throws when the file is missing', () => {
  assert.throws(() => loadConfig('/definitely/not/here.json'), /Config file not found/);
});
