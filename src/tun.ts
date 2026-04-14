import { EventEmitter } from 'events';
import crypto from 'crypto';
import fs from 'fs';
import net from 'net';

export type TunProtocol = 'ipv4' | 'unknown';
export type TcpSessionState = 'new' | 'syn-sent' | 'syn-recv' | 'established' | 'fin-wait' | 'closed' | 'reset';
export type TcpDirection = 'c2s' | 's2c';

export interface TunPacketSummary {
  family: TunProtocol;
  protocol: number;
  src: string;
  dst: string;
  srcPort?: number;
  dstPort?: number;
  sequence?: number;
  acknowledgment?: number;
  headerLength?: number;
  flags?: string[];
  totalLength: number;
  payloadLength: number;
}

export interface TunTcpSession {
  id: string;
  client: {
    ip: string;
    port: number;
  };
  server: {
    ip: string;
    port: number;
  };
  state: TcpSessionState;
  packets: number;
  bytesFromClient: number;
  bytesFromServer: number;
  createdAt: number;
  lastSeenAt: number;
  lastFlags: string[];
}

export interface TunSessionEvent {
  type: 'session-start' | 'session-update' | 'session-close' | 'packet';
  direction: TcpDirection;
  session: TunTcpSession;
  summary: TunPacketSummary;
  payload: Buffer;
}

interface TunTcpBridgeFlow {
  id: string;
  clientIp: string;
  clientPort: number;
  serverIp: string;
  serverPort: number;
  clientSeq: number;
  clientAck: number;
  serverSeq: number;
  socket?: net.Socket;
  connected: boolean;
  closed: boolean;
  pending: Buffer[];
  lastSeenAt: number;
}

function ipv4ToString(packet: Buffer, offset: number): string {
  return [packet[offset], packet[offset + 1], packet[offset + 2], packet[offset + 3]].join('.');
}

function ipv4Bytes(address: string): Buffer {
  return Buffer.from(address.split('.').map((part) => Number.parseInt(part, 10) & 0xff));
}

function tcpFlagsToNames(flags: number): string[] {
  const names: string[] = [];
  if (flags & 0x01) names.push('FIN');
  if (flags & 0x02) names.push('SYN');
  if (flags & 0x04) names.push('RST');
  if (flags & 0x08) names.push('PSH');
  if (flags & 0x10) names.push('ACK');
  if (flags & 0x20) names.push('URG');
  if (flags & 0x40) names.push('ECE');
  if (flags & 0x80) names.push('CWR');
  return names;
}

function tcpFlagsToMask(flags: string[]): number {
  let mask = 0;
  for (const flag of flags) {
    switch (flag) {
      case 'FIN': mask |= 0x01; break;
      case 'SYN': mask |= 0x02; break;
      case 'RST': mask |= 0x04; break;
      case 'PSH': mask |= 0x08; break;
      case 'ACK': mask |= 0x10; break;
      case 'URG': mask |= 0x20; break;
      case 'ECE': mask |= 0x40; break;
      case 'CWR': mask |= 0x80; break;
      default: break;
    }
  }
  return mask;
}

function hasFlag(flags: string[] | undefined, name: string): boolean {
  return Boolean(flags && flags.includes(name));
}

function sessionId(clientIp: string, clientPort: number, serverIp: string, serverPort: number): string {
  return `${clientIp}:${clientPort}->${serverIp}:${serverPort}`;
}

function internetChecksum(buffer: Buffer): number {
  let sum = 0;
  let i = 0;
  while (i + 1 < buffer.length) {
    sum += buffer.readUInt16BE(i);
    i += 2;
  }
  if (i < buffer.length) {
    sum += buffer[i] << 8;
  }
  while ((sum >> 16) > 0) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  return (~sum) & 0xffff;
}

function u32(value: number): number {
  return value >>> 0;
}

function randomU32(): number {
  return crypto.randomBytes(4).readUInt32BE(0);
}

function buildIpv4TcpPacket(options: {
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  sequence: number;
  acknowledgment: number;
  flags: string[];
  payload?: Buffer;
  ttl?: number;
  identification?: number;
  windowSize?: number;
}): Buffer {
  const payload = options.payload ?? Buffer.alloc(0);
  const ipHeaderLength = 20;
  const tcpHeaderLength = 20;
  const totalLength = ipHeaderLength + tcpHeaderLength + payload.length;
  const packet = Buffer.alloc(totalLength);

  packet[0] = 0x45;
  packet[1] = 0x00;
  packet.writeUInt16BE(totalLength, 2);
  packet.writeUInt16BE(options.identification ?? (randomU32() & 0xffff), 4);
  packet.writeUInt16BE(0x4000, 6);
  packet[8] = options.ttl ?? 64;
  packet[9] = 6;
  packet.writeUInt16BE(0, 10);
  ipv4Bytes(options.srcIp).copy(packet, 12);
  ipv4Bytes(options.dstIp).copy(packet, 16);

  const tcpOffset = ipHeaderLength;
  packet.writeUInt16BE(options.srcPort, tcpOffset);
  packet.writeUInt16BE(options.dstPort, tcpOffset + 2);
  packet.writeUInt32BE(u32(options.sequence), tcpOffset + 4);
  packet.writeUInt32BE(u32(options.acknowledgment), tcpOffset + 8);
  packet[tcpOffset + 12] = 0x50;
  packet[tcpOffset + 13] = tcpFlagsToMask(options.flags);
  packet.writeUInt16BE(options.windowSize ?? 65535, tcpOffset + 14);
  packet.writeUInt16BE(0, tcpOffset + 16);
  packet.writeUInt16BE(0, tcpOffset + 18);
  if (payload.length > 0) {
    payload.copy(packet, tcpOffset + tcpHeaderLength);
  }

  packet.writeUInt16BE(internetChecksum(packet.subarray(0, ipHeaderLength)), 10);

  const pseudoHeader = Buffer.alloc(12 + tcpHeaderLength + payload.length);
  ipv4Bytes(options.srcIp).copy(pseudoHeader, 0);
  ipv4Bytes(options.dstIp).copy(pseudoHeader, 4);
  pseudoHeader[8] = 0;
  pseudoHeader[9] = 6;
  pseudoHeader.writeUInt16BE(tcpHeaderLength + payload.length, 10);
  packet.copy(pseudoHeader, 12, tcpOffset, tcpOffset + tcpHeaderLength + payload.length);
  pseudoHeader.writeUInt16BE(0, 12 + 16);
  pseudoHeader.writeUInt16BE(internetChecksum(pseudoHeader), 12 + 16);
  packet.writeUInt16BE(pseudoHeader.readUInt16BE(12 + 16), tcpOffset + 16);

  return packet;
}

export function parseIpv4Packet(packet: Buffer): TunPacketSummary | null {
  if (packet.length < 20) {
    return null;
  }

  const version = packet[0] >> 4;
  const ihl = (packet[0] & 0x0f) * 4;
  if (version !== 4 || ihl < 20 || packet.length < ihl) {
    return null;
  }

  const totalLength = packet.readUInt16BE(2);
  const protocol = packet[9];
  const src = ipv4ToString(packet, 12);
  const dst = ipv4ToString(packet, 16);
  const payloadLength = Math.max(0, Math.min(totalLength, packet.length) - ihl);

  const summary: TunPacketSummary = {
    family: 'ipv4',
    protocol,
    src,
    dst,
    totalLength,
    payloadLength,
  };

  if (protocol === 6 && packet.length >= ihl + 20) {
    const srcPort = packet.readUInt16BE(ihl);
    const dstPort = packet.readUInt16BE(ihl + 2);
    const dataOffset = ((packet[ihl + 12] >> 4) & 0x0f) * 4;
    const flags = packet[ihl + 13] & 0xff;
    summary.srcPort = srcPort;
    summary.dstPort = dstPort;
    summary.sequence = packet.readUInt32BE(ihl + 4);
    summary.acknowledgment = packet.readUInt32BE(ihl + 8);
    summary.headerLength = dataOffset;
    summary.flags = tcpFlagsToNames(flags);
    summary.payloadLength = Math.max(0, Math.min(totalLength, packet.length) - ihl - dataOffset);
  } else if (protocol === 17 && packet.length >= ihl + 8) {
    summary.srcPort = packet.readUInt16BE(ihl);
    summary.dstPort = packet.readUInt16BE(ihl + 2);
  }

  return summary;
}

export function extractIpv4Payload(packet: Buffer): Buffer | null {
  if (packet.length < 20) {
    return null;
  }

  const version = packet[0] >> 4;
  const ihl = (packet[0] & 0x0f) * 4;
  if (version !== 4 || ihl < 20 || packet.length < ihl) {
    return null;
  }

  const totalLength = packet.readUInt16BE(2);
  const protocol = packet[9];
  const limit = Math.min(totalLength, packet.length);

  if (protocol === 6 && limit >= ihl + 20) {
    const dataOffset = ((packet[ihl + 12] >> 4) & 0x0f) * 4;
    const start = ihl + dataOffset;
    return start <= limit ? packet.subarray(start, limit) : Buffer.alloc(0);
  }

  if (protocol === 17 && limit >= ihl + 8) {
    const start = ihl + 8;
    return start <= limit ? packet.subarray(start, limit) : Buffer.alloc(0);
  }

  return null;
}

export function formatTunSummary(summary: TunPacketSummary): string {
  const ports = summary.srcPort !== undefined && summary.dstPort !== undefined
    ? `:${summary.srcPort} -> :${summary.dstPort}`
    : '';
  const flags = summary.flags && summary.flags.length > 0 ? ` flags=${summary.flags.join(',')}` : '';
  const seq = summary.sequence !== undefined ? ` seq=${summary.sequence}` : '';
  const ack = summary.acknowledgment !== undefined ? ` ack=${summary.acknowledgment}` : '';
  return `${summary.src} -> ${summary.dst} proto=${summary.protocol}${ports} len=${summary.totalLength} payload=${summary.payloadLength}${seq}${ack}${flags}`;
}

function cloneSession(session: TunTcpSession): TunTcpSession {
  return {
    ...session,
    client: { ...session.client },
    server: { ...session.server },
    lastFlags: [...session.lastFlags],
  };
}

export class TunSessionManager extends EventEmitter {
  private readonly sessions = new Map<string, TunTcpSession>();

  get activeCount(): number {
    return this.sessions.size;
  }

  snapshot(): TunTcpSession[] {
    return Array.from(this.sessions.values()).map(cloneSession);
  }

  deleteSession(id: string): boolean {
    return this.sessions.delete(id);
  }

  processPacket(summary: TunPacketSummary, payload: Buffer): TunSessionEvent | null {
    if (summary.family !== 'ipv4' || summary.protocol !== 6 || summary.srcPort === undefined || summary.dstPort === undefined) {
      return null;
    }

    const key = sessionId(summary.src, summary.srcPort, summary.dst, summary.dstPort);
    const reverseKey = sessionId(summary.dst, summary.dstPort, summary.src, summary.srcPort);
    const existing = this.sessions.get(key) ?? this.sessions.get(reverseKey);

    const direction: TcpDirection = existing && existing.client.ip === summary.src && existing.client.port === summary.srcPort
      ? 'c2s'
      : existing
        ? 's2c'
        : 'c2s';

    let session = existing;
    let eventType: TunSessionEvent['type'] = 'packet';

    if (!session) {
      session = {
        id: key,
        client: { ip: summary.src, port: summary.srcPort },
        server: { ip: summary.dst, port: summary.dstPort },
        state: 'new',
        packets: 0,
        bytesFromClient: 0,
        bytesFromServer: 0,
        createdAt: Date.now(),
        lastSeenAt: Date.now(),
        lastFlags: [],
      };
      this.sessions.set(key, session);
      eventType = 'session-start';
    }

    session.packets += 1;
    session.lastSeenAt = Date.now();
    session.lastFlags = summary.flags ?? [];

    const flags = summary.flags ?? [];
    if (hasFlag(flags, 'RST')) {
      session.state = 'reset';
      eventType = 'session-close';
      this.sessions.delete(session.id);
    } else if (hasFlag(flags, 'FIN')) {
      session.state = 'fin-wait';
    } else if (hasFlag(flags, 'SYN') && hasFlag(flags, 'ACK')) {
      session.state = 'syn-recv';
    } else if (hasFlag(flags, 'SYN')) {
      session.state = 'syn-sent';
    } else if (hasFlag(flags, 'ACK')) {
      if (session.state === 'syn-recv' || session.state === 'syn-sent' || session.state === 'new') {
        session.state = 'established';
      }
    }

    if (direction === 'c2s') {
      session.bytesFromClient += summary.payloadLength;
    } else {
      session.bytesFromServer += summary.payloadLength;
    }

    const event: TunSessionEvent = {
      type: eventType,
      direction,
      session: cloneSession(session),
      summary,
      payload,
    };

    this.emit(eventType, event);
    this.emit('packet', event);
    return event;
  }
}

export class TunMonitor extends EventEmitter {
  private running = false;
  private readonly bufferSize: number;

  constructor(private readonly fd: number, bufferSize = 65535) {
    super();
    this.bufferSize = bufferSize;
  }

  async start(): Promise<void> {
    if (this.running) {
      return;
    }
    this.running = true;

    while (this.running) {
      const packet = await this.readPacket();
      if (!packet) {
        continue;
      }
      const summary = parseIpv4Packet(packet);
      if (summary) {
        this.emit('packet', summary, packet);
      } else {
        this.emit('unknown', packet);
      }
    }
  }

  stop(): void {
    this.running = false;
  }

  private readPacket(): Promise<Buffer | null> {
    return new Promise((resolve, reject) => {
      const buffer = Buffer.allocUnsafe(this.bufferSize);
      fs.read(this.fd, buffer, 0, buffer.length, null, (err, bytesRead) => {
        if (err) {
          if ((err as NodeJS.ErrnoException).code === 'EAGAIN' || (err as NodeJS.ErrnoException).code === 'EINTR') {
            resolve(null);
            return;
          }
          reject(err);
          return;
        }
        if (bytesRead <= 0) {
          resolve(null);
          return;
        }
        resolve(buffer.subarray(0, bytesRead));
      });
    });
  }
}

export class TunTcpBridge extends EventEmitter {
  private readonly sessionManager = new TunSessionManager();
  private readonly flows = new Map<string, TunTcpBridgeFlow>();
  private readonly idleTimeoutMs: number;
  private readonly sweepIntervalMs: number;
  private readonly sweepTimer: NodeJS.Timeout;
  private lastSweepAt: number;

  constructor(private readonly fd: number, options: { idleTimeoutMs?: number; sweepIntervalMs?: number } = {}) {
    super();
    this.idleTimeoutMs = options.idleTimeoutMs ?? 60_000;
    this.sweepIntervalMs = options.sweepIntervalMs ?? Math.min(30_000, this.idleTimeoutMs);
    this.lastSweepAt = Date.now();
    this.sweepTimer = setInterval(() => {
      this.maybeSweepIdleFlows();
    }, this.sweepIntervalMs);
    this.sweepTimer.unref();
  }

  get activeSessions(): number {
    return this.sessionManager.activeCount;
  }

  snapshot(): TunTcpSession[] {
    return this.sessionManager.snapshot();
  }

  handlePacket(summary: TunPacketSummary, packet: Buffer): void {
    this.maybeSweepIdleFlows();
    if (summary.family !== 'ipv4' || summary.protocol !== 6 || summary.srcPort === undefined || summary.dstPort === undefined) {
      return;
    }

    const payload = extractIpv4Payload(packet) ?? Buffer.alloc(0);
    const event = this.sessionManager.processPacket(summary, payload);
    if (!event) {
      return;
    }

    const flow = this.ensureFlow(summary);
    flow.lastSeenAt = Date.now();

    if (flow.closed) {
      return;
    }

    const flags = summary.flags ?? [];
    if (hasFlag(flags, 'RST')) {
      this.sendTcpPacket(flow, ['RST'], Buffer.alloc(0), flow.clientAck);
      flow.closed = true;
      this.closeFlow(flow.id);
      return;
    }

    if (hasFlag(flags, 'SYN') && !hasFlag(flags, 'ACK')) {
      flow.clientSeq = summary.sequence ?? 0;
      flow.clientAck = u32((summary.sequence ?? 0) + 1);
      flow.serverSeq = randomU32();
      this.sendTcpPacket(flow, ['SYN', 'ACK'], Buffer.alloc(0), flow.clientAck);
      return;
    }

    if (payload.length > 0) {
      flow.clientAck = u32((summary.sequence ?? 0) + payload.length + (hasFlag(flags, 'FIN') ? 1 : 0));
      this.enqueueToUpstream(flow, payload);
      this.sendTcpPacket(flow, ['ACK'], Buffer.alloc(0), flow.clientAck);
    }

    if (hasFlag(flags, 'FIN')) {
      flow.clientAck = u32((summary.sequence ?? 0) + payload.length + 1);
      this.sendTcpPacket(flow, ['FIN', 'ACK'], Buffer.alloc(0), flow.clientAck);
      flow.closed = true;
      if (flow.socket) {
        flow.socket.end();
      } else {
        this.closeFlow(flow.id);
      }
    }
  }

  close(): void {
    clearInterval(this.sweepTimer);
    for (const id of Array.from(this.flows.keys())) {
      this.closeFlow(id);
    }
  }

  evictIdleFlows(now = Date.now()): number {
    this.lastSweepAt = now;
    let evicted = 0;
    for (const [id, flow] of this.flows.entries()) {
      if (now - flow.lastSeenAt <= this.idleTimeoutMs) {
        continue;
      }
      this.closeFlow(id);
      evicted += 1;
    }
    return evicted;
  }

  private maybeSweepIdleFlows(now = Date.now()): number {
    if (now - this.lastSweepAt < this.sweepIntervalMs) {
      return 0;
    }
    return this.evictIdleFlows(now);
  }

  private ensureFlow(summary: TunPacketSummary): TunTcpBridgeFlow {
    const flowId = sessionId(summary.src, summary.srcPort ?? 0, summary.dst, summary.dstPort ?? 0);
    const existing = this.flows.get(flowId);
    if (existing) {
      return existing;
    }

    const flow: TunTcpBridgeFlow = {
      id: flowId,
      clientIp: summary.src,
      clientPort: summary.srcPort ?? 0,
      serverIp: summary.dst,
      serverPort: summary.dstPort ?? 80,
      clientSeq: summary.sequence ?? 0,
      clientAck: u32((summary.sequence ?? 0) + 1),
      serverSeq: randomU32(),
      connected: false,
      closed: false,
      pending: [],
      lastSeenAt: Date.now(),
    };
    this.flows.set(flowId, flow);
    return flow;
  }

  private enqueueToUpstream(flow: TunTcpBridgeFlow, payload: Buffer): void {
    if (flow.closed) {
      return;
    }

    if (!flow.socket) {
      const socket = net.connect({ host: flow.serverIp, port: flow.serverPort || 80 });
      flow.socket = socket;
      socket.on('connect', () => {
        flow.connected = true;
        for (const chunk of flow.pending.splice(0)) {
          socket.write(chunk);
        }
      });
      socket.on('data', (chunk) => {
        if (flow.closed) {
          return;
        }
        this.sendTcpPacket(flow, ['PSH', 'ACK'], Buffer.from(chunk), flow.clientAck);
      });
      socket.on('close', () => {
        flow.connected = false;
        if (!flow.closed) {
          this.sendTcpPacket(flow, ['FIN', 'ACK'], Buffer.alloc(0), flow.clientAck);
        }
        this.closeFlow(flow.id);
      });
      socket.on('error', () => {
        if (!flow.closed) {
          this.sendTcpPacket(flow, ['RST'], Buffer.alloc(0), flow.clientAck);
        }
        this.closeFlow(flow.id);
      });
    }

    if (flow.connected && flow.socket) {
      flow.socket.write(payload);
    } else {
      flow.pending.push(Buffer.from(payload));
    }
  }

  private sendTcpPacket(flow: TunTcpBridgeFlow, flags: string[], payload: Buffer, acknowledgment: number): void {
    if (flow.closed) {
      return;
    }

    const packet = buildIpv4TcpPacket({
      srcIp: flow.serverIp,
      dstIp: flow.clientIp,
      srcPort: flow.serverPort,
      dstPort: flow.clientPort,
      sequence: flow.serverSeq,
      acknowledgment,
      flags,
      payload,
    });
    this.writePacket(packet);
    flow.serverSeq = u32(flow.serverSeq + payload.length + (hasFlag(flags, 'SYN') ? 1 : 0) + (hasFlag(flags, 'FIN') ? 1 : 0));
  }

  private writePacket(packet: Buffer): void {
    fs.write(this.fd, packet, 0, packet.length, null, (err) => {
      if (err) {
        this.emit('error', err);
      }
    });
  }

  private closeFlow(id: string): void {
    const flow = this.flows.get(id);
    if (!flow) {
      this.sessionManager.deleteSession(id);
      return;
    }
    flow.closed = true;
    flow.socket?.destroy();
    this.flows.delete(id);
    this.sessionManager.deleteSession(id);
  }
}
