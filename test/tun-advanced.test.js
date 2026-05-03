const test = require('node:test');
const assert = require('node:assert/strict');
const events = require('node:events');
const fs = require('node:fs');
const net = require('node:net');

const {
  parseIpv4Packet,
  extractIpv4Payload,
  formatTunSummary,
  formatTunSessionSummary,
  buildIpv4TcpPacket,
  TunSessionManager,
  TunTcpBridge,
} = require('../dist/tun');

function buildTestPacket(flags = 0x18, payload = 'hello') {
  const packet = Buffer.alloc(20 + 20 + Buffer.byteLength(payload));
  packet[0] = 0x45;
  packet[1] = 0x00;
  packet.writeUInt16BE(packet.length, 2);
  packet.writeUInt16BE(0x1234, 4);
  packet.writeUInt16BE(0x4000, 6);
  packet[8] = 64;
  packet[9] = 6;
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
  packet[tcp + 12] = 0x50;
  packet[tcp + 13] = flags;
  packet.writeUInt16BE(65535, tcp + 14);
  packet.writeUInt16BE(0, tcp + 16);
  packet.writeUInt16BE(0, tcp + 18);

  packet.write(payload, tcp + 20, 'utf8');
  return packet;
}

test('TunSessionManager handles multiple concurrent sessions', () => {
  const manager = new TunSessionManager();

  for (let i = 0; i < 10; i++) {
    const packet = buildIpv4TcpPacket({
      srcIp: '10.0.0.1',
      dstIp: '10.0.0.2',
      srcPort: 12345 + i,
      dstPort: 80,
      sequence: 1000 + i * 100,
      acknowledgment: 0,
      flags: ['SYN'],
    });

    const summary = parseIpv4Packet(packet);
    assert.ok(summary);
    const payload = extractIpv4Payload(packet) ?? Buffer.alloc(0);
    manager.processPacket(summary, payload);
  }

  assert.equal(manager.activeCount, 10);

  for (let i = 0; i < 10; i++) {
    const packet = buildIpv4TcpPacket({
      srcIp: '10.0.0.2',
      dstIp: '10.0.0.1',
      srcPort: 80,
      dstPort: 12345 + i,
      sequence: 5000 + i * 100,
      acknowledgment: 1001 + i * 100,
      flags: ['SYN', 'ACK'],
    });

    const summary = parseIpv4Packet(packet);
    assert.ok(summary);
    const payload = extractIpv4Payload(packet) ?? Buffer.alloc(0);
    manager.processPacket(summary, payload);
  }

  for (let i = 0; i < 10; i++) {
    const packet = buildIpv4TcpPacket({
      srcIp: '10.0.0.1',
      dstIp: '10.0.0.2',
      srcPort: 12345 + i,
      dstPort: 80,
      sequence: 1001 + i * 100,
      acknowledgment: 5001 + i * 100,
      flags: ['ACK'],
    });

    const summary = parseIpv4Packet(packet);
    assert.ok(summary);
    const payload = extractIpv4Payload(packet) ?? Buffer.alloc(0);
    manager.processPacket(summary, payload);
  }

  const sessions = manager.snapshot();
  assert.equal(sessions.length, 10);
  assert.ok(sessions.every(s => s.state === 'established'));

  for (let i = 0; i < 10; i++) {
    const packet = buildIpv4TcpPacket({
      srcIp: '10.0.0.1',
      dstIp: '10.0.0.2',
      srcPort: 12345 + i,
      dstPort: 80,
      sequence: 1002 + i * 100,
      acknowledgment: 5001 + i * 100,
      flags: ['FIN', 'ACK'],
    });

    const summary = parseIpv4Packet(packet);
    assert.ok(summary);
    const payload = extractIpv4Payload(packet) ?? Buffer.alloc(0);
    manager.processPacket(summary, payload);
  }

  const finalSessions = manager.snapshot();
  assert.ok(finalSessions.every(s => s.state === 'fin-wait' || s.state === 'closed'));
});

test('TunSessionManager handles session eviction', () => {
  const manager = new TunSessionManager();

  const packet = buildIpv4TcpPacket({
    srcIp: '192.168.1.1',
    dstIp: '192.168.1.2',
    srcPort: 54321,
    dstPort: 443,
    sequence: 100,
    acknowledgment: 0,
    flags: ['SYN'],
  });

  const summary = parseIpv4Packet(packet);
  const payload = extractIpv4Payload(packet) ?? Buffer.alloc(0);
  manager.processPacket(summary, payload);

  assert.equal(manager.activeCount, 1);

  const deleted = manager.deleteSession('192.168.1.1:54321->192.168.1.2:443');
  assert.ok(deleted);
  assert.equal(manager.activeCount, 0);

  const deletedAgain = manager.deleteSession('192.168.1.1:54321->192.168.1.2:443');
  assert.equal(deletedAgain, false);
});

test('formatTunSummary handles all packet types', () => {
  const tcpPacket = buildIpv4TcpPacket({
    srcIp: '10.0.0.1',
    dstIp: '10.0.0.2',
    srcPort: 12345,
    dstPort: 80,
    sequence: 1000,
    acknowledgment: 2000,
    flags: ['SYN', 'ACK'],
    payload: Buffer.from('GET / HTTP/1.1'),
  });

  const tcpSummary = parseIpv4Packet(tcpPacket);
  const tcpFormatted = formatTunSummary(tcpSummary);
  assert.match(tcpFormatted, /10\.0\.0\.1 -> 10\.0\.0\.2/);
  assert.match(tcpFormatted, /:12345 -> :80/);
  assert.match(tcpFormatted, /SYN,ACK/);
  assert.match(tcpFormatted, /seq=1000/);
  assert.match(tcpFormatted, /ack=2000/);
});

test('formatTunSessionSummary formats correctly', () => {
  const summary = {
    id: 'test-session',
    client: '192.168.1.1:12345',
    server: '192.168.1.2:443',
    state: 'established',
    packets: 100,
    bytesFromClient: 5000,
    bytesFromServer: 10000,
    lastSeenAt: Date.now() - 5000,
    ageMs: 5000,
    lastFlags: ['ACK'],
  };

  const formatted = formatTunSessionSummary(summary);
  assert.match(formatted, /192\.168\.1\.1:12345 -> 192\.168\.1\.2:443/);
  assert.match(formatted, /established/);
  assert.match(formatted, /p100/);
  assert.match(formatted, /c5000\/s10000/);
  assert.match(formatted, /age=5\.0s/);
  assert.match(formatted, /flags=ACK/);
});

test('buildIpv4TcpPacket validates inputs', () => {
  const packet = buildIpv4TcpPacket({
    srcIp: 'invalid-ip',
    dstIp: 'also-invalid',
    srcPort: 12345,
    dstPort: 80,
    sequence: 0,
    acknowledgment: 0,
    flags: ['SYN'],
  });

  assert.ok(packet.length >= 40);
  const summary = parseIpv4Packet(packet);
  assert.ok(summary);
});

test('TunTcpBridge handles RST packets correctly', async () => {
  const originalWrite = fs.write;
  const originalConnect = net.connect;
  const writes = [];

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
    socket.end = () => { queueMicrotask(() => socket.emit('close')); };
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
    const synPacket = buildTestPacket(0x02, '');
    const synSummary = parseIpv4Packet(synPacket);
    bridge.handlePacket(synSummary, synPacket);

    assert.equal(bridge.activeSessions, 1);

    const rstPacket = buildTestPacket(0x04, '');
    const rstSummary = parseIpv4Packet(rstPacket);
    bridge.handlePacket(rstSummary, rstPacket);

    assert.equal(bridge.activeSessions, 0);

    bridge.close();
  } finally {
    fs.write = originalWrite;
    net.connect = originalConnect;
  }
});

test('TunTcpBridge idle flow eviction works correctly', async () => {
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
    const bridge = new TunTcpBridge(42, { idleTimeoutMs: 100, sweepIntervalMs: 50 });

    const synPacket = buildTestPacket(0x02, '');
    const synSummary = parseIpv4Packet(synPacket);
    bridge.handlePacket(synSummary, synPacket);

    assert.equal(bridge.activeSessions, 1);

    await new Promise(resolve => setTimeout(resolve, 300));

    const synPacket2 = buildTestPacket(0x02, '');
    synPacket2.writeUInt8(10, 12);
    synPacket2.writeUInt8(0, 13);
    synPacket2.writeUInt8(0, 14);
    synPacket2.writeUInt8(3, 15);
    synPacket2.writeUInt8(1, 16);
    synPacket2.writeUInt8(1, 17);
    synPacket2.writeUInt8(1, 18);
    synPacket2.writeUInt8(1, 19);
    const synSummary2 = parseIpv4Packet(synPacket2);
    bridge.handlePacket(synSummary2, synPacket2);

    assert.equal(bridge.activeSessions, 1);

    const sessions = bridge.snapshot();
    assert.equal(sessions.length, 1);
    assert.equal(sessions[0].client.ip, '10.0.0.3');

    bridge.close();
  } finally {
    fs.write = originalWrite;
    net.connect = originalConnect;
  }
});

test('TunTcpBridge session summary format is correct', async () => {
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
    const bridge = new TunTcpBridge(42);

    for (let i = 0; i < 5; i++) {
      const synPacket = buildIpv4TcpPacket({
        srcIp: `10.0.0.${i + 1}`,
        dstIp: '192.168.1.1',
        srcPort: 10000 + i,
        dstPort: 80,
        sequence: i * 1000,
        acknowledgment: 0,
        flags: ['SYN'],
      });

      const summary = parseIpv4Packet(synPacket);
      bridge.handlePacket(summary, synPacket);
    }

    const allSessions = bridge.summarizeSessions(10);
    assert.equal(allSessions.length, 5);

    const limitedSessions = bridge.summarizeSessions(3);
    assert.equal(limitedSessions.length, 3);

    for (const summary of allSessions) {
      assert.ok(typeof summary.id === 'string');
      assert.ok(typeof summary.client === 'string');
      assert.ok(typeof summary.server === 'string');
      assert.ok(['new', 'syn-sent', 'syn-recv', 'established', 'fin-wait', 'closed', 'reset'].includes(summary.state));
      assert.ok(typeof summary.packets === 'number');
      assert.ok(typeof summary.bytesFromClient === 'number');
      assert.ok(typeof summary.bytesFromServer === 'number');
      assert.ok(typeof summary.lastSeenAt === 'number');
      assert.ok(typeof summary.ageMs === 'number');
      assert.ok(Array.isArray(summary.lastFlags));

      const formatted = formatTunSessionSummary(summary);
      assert.match(formatted, /->/);
      assert.match(formatted, new RegExp(summary.state));
    }

    bridge.close();
  } finally {
    fs.write = originalWrite;
    net.connect = originalConnect;
  }
});
