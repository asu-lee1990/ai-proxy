const test = require('node:test');
const assert = require('node:assert/strict');
const events = require('node:events');
const fs = require('node:fs');
const net = require('node:net');

const { parseIpv4Packet, formatTunSessionSummary, formatTunSummary, TunSessionManager, TunTcpBridge } = require('../dist/tun');

function buildIpv4TcpPacket(flags = 0x18, payload = 'hello') {
  const packet = Buffer.alloc(20 + 20 + Buffer.byteLength(payload));
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
  packet[tcp + 13] = flags;
  packet.writeUInt16BE(65535, tcp + 14);
  packet.writeUInt16BE(0, tcp + 16);
  packet.writeUInt16BE(0, tcp + 18);

  packet.write(payload, tcp + 20, 'utf8');
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

test('TunSessionManager tracks TCP sessions', () => {
  const manager = new TunSessionManager();
  const synSummary = parseIpv4Packet(buildIpv4TcpPacket(0x02, ''));
  assert.ok(synSummary);

  const start = manager.processPacket(synSummary, Buffer.alloc(0));
  assert.ok(start);
  assert.equal(manager.activeCount, 1);
  assert.equal(start.session.state, 'syn-sent');

  const ackSummary = parseIpv4Packet(buildIpv4TcpPacket(0x18, 'ping'));
  assert.ok(ackSummary);

  const update = manager.processPacket(ackSummary, Buffer.from('ping'));
  assert.ok(update);
  assert.equal(manager.activeCount, 1);
  assert.equal(update.session.state, 'established');
  assert.equal(update.session.bytesFromClient, 4);
});

test('formatTunSessionSummary renders a compact single line', () => {
  const manager = new TunSessionManager();
  const synSummary = parseIpv4Packet(buildIpv4TcpPacket(0x02, ''));
  assert.ok(synSummary);
  manager.processPacket(synSummary, Buffer.alloc(0));
  const summary = manager.summarize(1, Date.now() + 1500)[0];
  assert.ok(summary);

  const line = formatTunSessionSummary(summary);
  assert.match(line, /10\.0\.0\.1:54321 -> 1\.1\.1\.1:443/);
  assert.match(line, /syn-sent/);
  assert.match(line, /p1/);
  assert.match(line, /age=1\.5s/);
});

test('TunTcpBridge advances sequence numbers once per segment', async () => {
  const originalWrite = fs.write;
  const originalConnect = net.connect;
  const writes = [];
  let endCalls = 0;

  fs.write = (fd, buffer, offset, length, position, callback) => {
    const slice = Buffer.from(buffer.subarray(offset, offset + length));
    writes.push(slice);
    if (typeof callback === 'function') {
      callback(null, length, buffer);
    }
  };

  net.connect = () => {
    const socket = new events.EventEmitter();
    socket.write = () => true;
    socket.destroy = () => {};
    socket.end = () => { endCalls += 1; queueMicrotask(() => socket.emit('close')); };
    socket.setNoDelay = () => {};
    socket.setKeepAlive = () => {};
    socket.pause = () => {};
    socket.resume = () => {};
    socket.unref = () => {};
    queueMicrotask(() => socket.emit('connect'));
    return socket;
  };

  try {
    const bridge = new TunTcpBridge(42);
    const synPacket = buildIpv4TcpPacket(0x02, '');
    const dataPacket = buildIpv4TcpPacket(0x18, 'ping');
    const synSummary = parseIpv4Packet(synPacket);
    const dataSummary = parseIpv4Packet(dataPacket);

    assert.ok(synSummary);
    assert.ok(dataSummary);

    bridge.handlePacket(synSummary, synPacket);
    bridge.handlePacket(dataSummary, dataPacket);

    const finPacket = buildIpv4TcpPacket(0x11, '');
    const finSummary = parseIpv4Packet(finPacket);
    assert.ok(finSummary);
    bridge.handlePacket(finSummary, finPacket);

    await new Promise((resolve) => setImmediate(resolve));

    assert.equal(writes.length >= 3, true);
    const synAck = parseIpv4Packet(writes[0]);
    const ackOnly = parseIpv4Packet(writes[1]);
    const finAck = parseIpv4Packet(writes[2]);
    assert.ok(synAck);
    assert.ok(ackOnly);
    assert.ok(finAck);
    assert.deepEqual(synAck.flags, ['SYN', 'ACK']);
    assert.deepEqual(ackOnly.flags, ['ACK']);
    assert.deepEqual(finAck.flags, ['FIN', 'ACK']);
    assert.equal(ackOnly.sequence, synAck.sequence + 1);
    assert.equal(endCalls, 1);
    bridge.close();
  } finally {
    fs.write = originalWrite;
    net.connect = originalConnect;
  }
});

test('TunTcpBridge evicts idle flows', () => {
  const originalWrite = fs.write;
  const originalConnect = net.connect;

  fs.write = (fd, buffer, offset, length, position, callback) => {
    if (typeof callback === 'function') {
      callback(null, length, buffer);
    }
  };

  net.connect = () => {
    const socket = new events.EventEmitter();
    socket.write = () => true;
    socket.destroy = () => {};
    socket.end = () => {};
    socket.setNoDelay = () => {};
    socket.setKeepAlive = () => {};
    socket.pause = () => {};
    socket.resume = () => {};
    socket.unref = () => {};
    queueMicrotask(() => socket.emit('connect'));
    return socket;
  };

  try {
    const bridge = new TunTcpBridge(42, { idleTimeoutMs: 1, sweepIntervalMs: 1000 });
    const synPacket = buildIpv4TcpPacket(0x02, '');
    const synSummary = parseIpv4Packet(synPacket);
    assert.ok(synSummary);

    bridge.handlePacket(synSummary, synPacket);
    assert.equal(bridge.snapshot().length, 1);

    const summaries = bridge.summarizeSessions(1);
    assert.equal(summaries.length, 1);
    assert.equal(summaries[0].client, '10.0.0.1:54321');
    assert.equal(summaries[0].server, '1.1.1.1:443');
    assert.ok(typeof summaries[0].ageMs === 'number');

    const evicted = bridge.evictIdleFlows(Date.now() + 10_000);
    assert.equal(evicted, 1);
    assert.equal(bridge.snapshot().length, 0);
    bridge.close();
  } finally {
    fs.write = originalWrite;
    net.connect = originalConnect;
  }
});
