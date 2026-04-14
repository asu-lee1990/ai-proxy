import fs from 'fs';

export type ProxyProtocol = 'http' | 'https' | 'socks5';

export interface ProxyConfig {
  host: string;
  port: number;
  protocol: ProxyProtocol;
  logDir: string;
  authUser?: string;
  authPass?: string;
  tlsKeyPath?: string;
  tlsCertPath?: string;
  requestHeaders?: string[];
  responseHeaders?: string[];
  timeoutMs?: number;
  bodyCaptureLimitBytes?: number;
  quiet?: boolean;
}

export function normalizeConfig(input: Partial<ProxyConfig> = {}): ProxyConfig {
  return {
    host: input.host ?? '127.0.0.1',
    port: input.port ?? 8080,
    protocol: input.protocol ?? 'http',
    logDir: input.logDir ?? './log',
    authUser: input.authUser,
    authPass: input.authPass,
    tlsKeyPath: input.tlsKeyPath,
    tlsCertPath: input.tlsCertPath,
    requestHeaders: input.requestHeaders ?? [],
    responseHeaders: input.responseHeaders ?? [],
    timeoutMs: input.timeoutMs ?? 30000,
    bodyCaptureLimitBytes: input.bodyCaptureLimitBytes ?? 256 * 1024,
    quiet: input.quiet ?? false,
  };
}

export function loadConfig(filePath: string): ProxyConfig {
  if (!fs.existsSync(filePath)) {
    throw new Error(`Config file not found: ${filePath}`);
  }

  const parsed = JSON.parse(fs.readFileSync(filePath, 'utf-8')) as Partial<ProxyConfig>;
  return normalizeConfig(parsed);
}
