import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

export type HeaderMap = Record<string, string | string[] | number | undefined>;

export interface LogEntry {
  kind: 'req' | 'rsp';
  targetHost: string;
  line: string;
  headers: HeaderMap;
  body?: Buffer;
  bodyTruncated?: boolean;
}

const TEXT_CONTENT_RE = /^(text\/|application\/(json|xml|javascript|x-www-form-urlencoded)|image\/svg\+xml)/i;
const BINARY_CONTENT_RE = /^(application\/octet-stream|image\/|audio\/|video\/|font\/|application\/pdf)/i;

function sanitizeSegment(value: string): string {
  return value.replace(/[^a-zA-Z0-9._-]+/g, '_').replace(/^_+|_+$/g, '') || 'unknown';
}

function stringifyHeaderValue(value: string | string[] | number | undefined): string {
  if (value === undefined) {
    return '';
  }
  if (Array.isArray(value)) {
    return value.join(', ');
  }
  return String(value);
}

function getHeaderValue(headers: HeaderMap, name: string): string {
  const lower = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === lower) {
      return stringifyHeaderValue(value);
    }
  }
  return '';
}

function inferExtension(contentType: string, disposition: string): string {
  const lowerType = contentType.toLowerCase();
  if (lowerType.includes('json')) return '.json';
  if (lowerType.includes('html')) return '.html';
  if (lowerType.includes('xml')) return '.xml';
  if (lowerType.includes('javascript')) return '.js';
  if (lowerType.includes('svg')) return '.svg';
  if (lowerType.includes('jpeg') || lowerType.includes('jpg')) return '.jpg';
  if (lowerType.includes('png')) return '.png';
  if (lowerType.includes('gif')) return '.gif';
  if (lowerType.includes('webp')) return '.webp';
  if (lowerType.includes('pdf')) return '.pdf';

  const match = /filename\*?=(?:UTF-8''|"?)([^";]+)/i.exec(disposition);
  if (match?.[1]) {
    const ext = path.extname(match[1].trim());
    if (ext) {
      return ext;
    }
  }

  return '.bin';
}

function shouldPersistBody(headers: HeaderMap, body: Buffer, bodyTruncated = false): boolean {
  const contentType = getHeaderValue(headers, 'content-type');
  const disposition = getHeaderValue(headers, 'content-disposition');

  if (bodyTruncated || disposition) {
    return true;
  }

  if (body.length > 64 * 1024) {
    return true;
  }

  if (!contentType) {
    return false;
  }

  return BINARY_CONTENT_RE.test(contentType) || !TEXT_CONTENT_RE.test(contentType);
}

function bodyToText(headers: HeaderMap, body: Buffer, bodyDir: string, bodyTruncated = false): string {
  const contentType = getHeaderValue(headers, 'content-type');
  const disposition = getHeaderValue(headers, 'content-disposition');

  if (!shouldPersistBody(headers, body, bodyTruncated)) {
    const text = body.toString('utf8');
    return bodyTruncated ? `${text}\n[truncated after ${body.length} bytes]` : text;
  }

  const safeDir = path.join(bodyDir, sanitizeSegment(getHeaderValue(headers, 'x-target-host') || 'unknown'));
  fs.mkdirSync(safeDir, { recursive: true });

  const baseName = disposition
    ? sanitizeSegment((/filename\*?=(?:UTF-8''|"?)([^";]+)/i.exec(disposition)?.[1] ?? 'body').trim())
    : 'body';
  const ext = inferExtension(contentType, disposition);
  const fileName = `${Date.now()}-${crypto.randomUUID()}-${baseName}${ext}`;
  const filePath = path.join(safeDir, fileName);
  fs.writeFileSync(filePath, body);
  return bodyTruncated ? `file://${filePath} (truncated after ${body.length} bytes)` : `file://${filePath}`;
}

export class Logger {
  private readonly logDir: string;

  constructor(logDir: string) {
    this.logDir = logDir;
    fs.mkdirSync(path.join(logDir, 'req'), { recursive: true });
    fs.mkdirSync(path.join(logDir, 'rsp'), { recursive: true });
    fs.mkdirSync(path.join(logDir, 'body', 'req'), { recursive: true });
    fs.mkdirSync(path.join(logDir, 'body', 'rsp'), { recursive: true });
  }

  log(entry: LogEntry): void {
    const targetHost = sanitizeSegment(entry.targetHost);
    const hostDir = path.join(this.logDir, entry.kind, targetHost);
    fs.mkdirSync(hostDir, { recursive: true });

    const bodyDir = path.join(this.logDir, 'body', entry.kind);
    const headerLines = Object.entries(entry.headers).map(([key, value]) => `${key}: ${stringifyHeaderValue(value)}`);
    const headerMapForBody: HeaderMap = {
      ...entry.headers,
      'x-target-host': entry.targetHost,
    };
    const bodyText = entry.body ? bodyToText(headerMapForBody, entry.body, bodyDir, entry.bodyTruncated) : '';

    const content = [entry.line, ...headerLines, '', bodyText].join('\n');
    const suffix = entry.kind === 'req' ? '.req' : '.rsp';
    const filePath = path.join(hostDir, `${Date.now()}-${crypto.randomUUID()}${suffix}`);
    fs.writeFileSync(filePath, content);
  }

  logRequest(targetHost: string, line: string, headers: HeaderMap, body?: Buffer, bodyTruncated = false): void {
    this.log({ kind: 'req', targetHost, line, headers, body, bodyTruncated });
  }

  logResponse(targetHost: string, line: string, headers: HeaderMap, body?: Buffer, bodyTruncated = false): void {
    this.log({ kind: 'rsp', targetHost, line, headers, body, bodyTruncated });
  }
}
