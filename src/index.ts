import { Command } from 'commander';
import path from 'path';
import { loadConfig, normalizeConfig, ProxyConfig, ProxyProtocol } from './config';
import { ProxyServer } from './proxy';

function collect(value: string, previous: string[] = []): string[] {
  previous.push(value);
  return previous;
}

function parsePort(value: string): number {
  const port = Number.parseInt(value, 10);
  if (Number.isNaN(port) || port <= 0 || port > 65535) {
    throw new Error(`Invalid port: ${value}`);
  }
  return port;
}

function parseMilliseconds(value: string): number {
  const ms = Number.parseInt(value, 10);
  if (Number.isNaN(ms) || ms < 0) {
    throw new Error(`Invalid timeout value: ${value}`);
  }
  return ms;
}

function parsePositiveInteger(value: string, label: string): number {
  const parsed = Number.parseInt(value, 10);
  if (Number.isNaN(parsed) || parsed < 0) {
    throw new Error(`Invalid ${label}: ${value}`);
  }
  return parsed;
}

function parseProtocol(value: string): ProxyProtocol {
  if (value === 'http' || value === 'https' || value === 'socks5' || value === 'transparent') {
    return value;
  }
  throw new Error(`Invalid protocol: ${value}. Use http, https, socks5, or transparent.`);
}

function mergeConfig(base: ProxyConfig, overrides: Partial<ProxyConfig>): ProxyConfig {
  return normalizeConfig({
    ...base,
    ...overrides,
    requestHeaders: overrides.requestHeaders ?? base.requestHeaders,
    responseHeaders: overrides.responseHeaders ?? base.responseHeaders,
  });
}

const program = new Command();
program
  .name('ai-proxy')
  .description('A TypeScript proxy CLI with HTTP / HTTPS / SOCKS5 support')
  .option('-c, --config <path>', 'Path to a JSON config file')
  .option('--host <host>', 'Listen host')
  .option('--port <port>', 'Listen port', parsePort)
  .option('--protocol <protocol>', 'http, https, socks5, or transparent', parseProtocol)
  .option('--log-dir <path>', 'Log directory')
  .option('--auth-user <user>', 'Authentication username')
  .option('--auth-pass <pass>', 'Authentication password')
  .option('--tls-key <path>', 'TLS private key path for HTTPS listener')
  .option('--tls-cert <path>', 'TLS certificate path for HTTPS listener')
  .option('--mitm', 'Enable HTTPS CONNECT MITM decryption', false)
  .option('--mitm-insecure-upstream', 'Disable upstream certificate verification while MITM is enabled')
  .option('--mitm-ca-key <path>', 'CA private key path for MITM leaf signing')
  .option('--mitm-ca-cert <path>', 'CA certificate path for MITM leaf signing')
  .option('--mitm-cache-dir <path>', 'Directory used to cache generated MITM leaf certificates')
  .option('--transparent-http-port <port>', 'Fallback upstream port for transparent HTTP mode', parsePort)
  .option('--transparent-tls-port <port>', 'Fallback upstream port for transparent TLS mode', parsePort)
  .option('--request-header <header>', 'Add an upstream request header, key=value', collect, [])
  .option('--response-header <header>', 'Inject a header into proxy responses, key=value', collect, [])
  .option('--timeout-ms <ms>', 'Upstream timeout in milliseconds', parseMilliseconds)
  .option('--log-body-max-bytes <bytes>', 'Maximum bytes to keep in memory for request/response body logging', (value) => parsePositiveInteger(value, 'body capture limit'))
  .option('--quiet', 'Disable console logging', false)
  .parse(process.argv);

const options = program.opts();

let baseConfig = normalizeConfig();
if (options.config) {
  const configPath = path.resolve(process.cwd(), options.config);
  baseConfig = loadConfig(configPath);
}

const mergedConfig = mergeConfig(baseConfig, {
  host: options.host,
  port: options.port,
  protocol: options.protocol,
  logDir: options.logDir,
  authUser: options.authUser,
  authPass: options.authPass,
  tlsKeyPath: options.tlsKey,
  tlsCertPath: options.tlsCert,
  mitmEnabled: options.mitm,
  mitmInsecureUpstream: options.mitmInsecureUpstream,
  mitmCaKeyPath: options.mitmCaKey,
  mitmCaCertPath: options.mitmCaCert,
  mitmCacheDir: options.mitmCacheDir,
  transparentHttpPort: options.transparentHttpPort,
  transparentTlsPort: options.transparentTlsPort,
  requestHeaders: options.requestHeader,
  responseHeaders: options.responseHeader,
  timeoutMs: options.timeoutMs,
  bodyCaptureLimitBytes: options.logBodyMaxBytes,
  quiet: options.quiet,
});

const proxy = new ProxyServer(mergedConfig);
proxy.start();
