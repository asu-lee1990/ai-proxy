const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { Logger } = require('../dist/logger');
const { firstFilePath, tempDir } = require('./helpers');

test('Logger keeps small text bodies inline', () => {
  const root = tempDir('ai-proxy-logs-');
  const logDir = path.join(root, 'log');
  const logger = new Logger(logDir);

  logger.logRequest(
    'example.com:8080',
    'GET /hello HTTP/1.1',
    { 'content-type': 'text/plain; charset=utf-8' },
    Buffer.from('hello world', 'utf8'),
  );

  const reqDir = path.join(logDir, 'req', 'example.com_8080');
  const reqFile = firstFilePath(reqDir);
  const content = fs.readFileSync(reqFile, 'utf8');

  assert.match(content, /GET \/hello HTTP\/1\.1/);
  assert.match(content, /content-type: text\/plain; charset=utf-8/);
  assert.match(content, /hello world/);
});

test('Logger persists binary bodies and content-disposition payloads to files', () => {
  const root = tempDir('ai-proxy-logs-');
  const logDir = path.join(root, 'log');
  const logger = new Logger(logDir);

  logger.logResponse(
    'example.com:8080',
    'HTTP/1.1 200 OK',
    {
      'content-type': 'application/octet-stream',
      'content-disposition': 'attachment; filename="report.bin"',
    },
    Buffer.from([0, 1, 2, 3]),
  );

  const rspDir = path.join(logDir, 'rsp', 'example.com_8080');
  const rspFile = firstFilePath(rspDir);
  const rspContent = fs.readFileSync(rspFile, 'utf8');
  assert.match(rspContent, /HTTP\/1\.1 200 OK/);
  assert.match(rspContent, /file:\/\//);

  const bodyDir = path.join(logDir, 'body', 'rsp', 'example.com_8080');
  const bodyFiles = fs.readdirSync(bodyDir);
  assert.ok(bodyFiles.some((name) => name.endsWith('.bin') && name.includes('report.bin')));
});
