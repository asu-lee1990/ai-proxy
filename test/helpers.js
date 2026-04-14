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

module.exports = {
  closeServer,
  firstFilePath,
  getPort,
  listen,
  tempDir,
};
