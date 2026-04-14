import { EventEmitter } from 'events';
import fs from 'fs';

export type TunProtocol = 'ipv4' | 'unknown';

export interface TunPacketSummary {
  family: TunProtocol;
  protocol: number;
  src: string;
  dst: string;
  srcPort?: number;
  dstPort?: number;
  flags?: string[];
  totalLength: number;
  payloadLength: number;
}

function ipv4ToString(packet: Buffer, offset: number): string {
  return [packet[offset], packet[offset + 1], packet[offset + 2], packet[offset + 3]].join('.');
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
    summary.flags = tcpFlagsToNames(flags);
    summary.payloadLength = Math.max(0, Math.min(totalLength, packet.length) - ihl - dataOffset);
  } else if (protocol === 17 && packet.length >= ihl + 8) {
    summary.srcPort = packet.readUInt16BE(ihl);
    summary.dstPort = packet.readUInt16BE(ihl + 2);
  }

  return summary;
}

export function formatTunSummary(summary: TunPacketSummary): string {
  const ports = summary.srcPort !== undefined && summary.dstPort !== undefined
    ? `:${summary.srcPort} -> :${summary.dstPort}`
    : '';
  const flags = summary.flags && summary.flags.length > 0 ? ` flags=${summary.flags.join(',')}` : '';
  return `${summary.src} -> ${summary.dst} proto=${summary.protocol}${ports} len=${summary.totalLength} payload=${summary.payloadLength}${flags}`;
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
