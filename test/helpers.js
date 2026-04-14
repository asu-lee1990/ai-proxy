const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { once } = require('node:events');

function tempDir(prefix = 'ai-proxy-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function listen(server) {
  return once(server, 'listening');
}

function closeServer(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
}

function getPort(server) {
  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('Server is not listening on a TCP port');
  }
  return address.port;
}

function firstFilePath(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const file = entries.find((entry) => entry.isFile());
  if (!file) {
    throw new Error(`No file found in ${dir}`);
  }
  return path.join(dir, file.name);
}

function createBufferedReader(socket) {
  const queue = [];
  let available = 0;
  let ended = false;
  let error = null;
  const waiters = [];

  const wake = () => {
    while (waiters.length > 0) {
      const resolve = waiters.shift();
      resolve();
    }
  };

  socket.on('data', (chunk) => {
    const buf = Buffer.from(chunk);
    queue.push(buf);
    available += buf.length;
    wake();
  });
  socket.on('end', () => {
    ended = true;
    wake();
  });
  socket.on('close', () => {
    ended = true;
    wake();
  });
  socket.on('error', (err) => {
    error = err;
    wake();
  });

  const readExact = async (size) => {
    while (available < size) {
      if (error) {
        throw error;
      }
      if (ended) {
        throw new Error('Socket ended before enough data arrived');
      }
      await new Promise((resolve) => waiters.push(resolve));
    }

    const out = Buffer.allocUnsafe(size);
    let offset = 0;
    while (offset < size) {
      const first = queue[0];
      const take = Math.min(size - offset, first.length);
      first.copy(out, offset, 0, take);
      offset += take;
      available -= take;
      if (take === first.length) {
        queue.shift();
      } else {
        queue[0] = first.subarray(take);
      }
    }
    return out;
  };

  const readAll = () => new Promise((resolve, reject) => {
    const chunks = [];
    const onData = (chunk) => chunks.push(Buffer.from(chunk));
    const onEnd = () => cleanup(resolve, Buffer.concat(chunks));
    const onError = (err) => cleanup(reject, err);
    const cleanup = (fn, value) => {
      socket.off('data', onData);
      socket.off('end', onEnd);
      socket.off('error', onError);
      fn(value);
    };
    socket.on('data', onData);
    socket.on('end', onEnd);
    socket.on('error', onError);
  });

  return { readExact, readAll };
}

module.exports = {
  closeServer,
  createBufferedReader,
  firstFilePath,
  getPort,
  listen,
  tempDir,
};
