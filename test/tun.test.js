const test = require('node:test');
const assert = require('node:assert/strict');

const { parseIpv4Packet, formatTunSummary } = require('../dist/tun');

function buildIpv4TcpPacket() {
  const packet = Buffer.alloc(20 + 20 + 5);
  packet[0] = 0x45; // v4, IHL=5
  packet[1] = 0x00;
  packet.writeUInt16BE(packet.length, 2);
  packet.writeUInt16BE(0x1234, 4);
  packet.writeUInt16BE(0x4000, 6);
  packet[8] = 64;
  packet[9] = 6; // TCP
  packet[12] = 10;
  packet[13] = 0;
  packet[14] = 0;
  packet[15] = 1;
  packet[16] = 1;
  packet[17] = 1;
  packet[18] = 1;
  packet[19] = 1;

  const tcp = 20;
  packet.writeUInt16BE(54321, tcp);
  packet.writeUInt16BE(443, tcp + 2);
  packet.writeUInt32BE(100, tcp + 4);
  packet.writeUInt32BE(200, tcp + 8);
  packet[tcp + 12] = 0x50; // data offset 5
  packet[tcp + 13] = 0x18; // PSH + ACK
  packet.writeUInt16BE(65535, tcp + 14);
  packet.writeUInt16BE(0, tcp + 16);
  packet.writeUInt16BE(0, tcp + 18);

  packet.write('hello', tcp + 20, 'utf8');
  return packet;
}

test('parseIpv4Packet parses a TCP packet summary', () => {
  const summary = parseIpv4Packet(buildIpv4TcpPacket());

  assert.ok(summary);
  assert.equal(summary.family, 'ipv4');
  assert.equal(summary.src, '10.0.0.1');
  assert.equal(summary.dst, '1.1.1.1');
  assert.equal(summary.srcPort, 54321);
  assert.equal(summary.dstPort, 443);
  assert.deepEqual(summary.flags, ['PSH', 'ACK']);
  assert.equal(summary.totalLength, 45);
  assert.equal(summary.payloadLength, 5);
  assert.match(formatTunSummary(summary), /10\.0\.0\.1 -> 1\.1\.1\.1/);
});

test('parseIpv4Packet returns null for non-IPv4 input', () => {
  assert.equal(parseIpv4Packet(Buffer.from([0x60, 0, 0, 0])), null);
});
