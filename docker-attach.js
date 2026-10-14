
#!/usr/bin/env node
'use strict';

const http = require('http');

const socketPath = process.env.DOCKER_SOCK ||
  '/var/run/docker.sock';

const apiVersion = 'v1.48';
const containerId = process.argv[2];

if (!containerId || !/^[a-zA-Z0-9_.-]+$/.test(containerId)) {
  console.error('Usage: node docker-attach.js CONTAINER_ID');
  process.exit(2);
}

const req = http.request({
  socketPath,
  method: 'POST',
  path: `/${apiVersion}/containers/${containerId}/attach?` +
    'stream=1&stdout=1&stderr=1&stdin=0&logs=1',
  headers: {
    Connection: 'Upgrade',
    Upgrade: 'tcp'
  }
});

function output(data) {
  process.stdout.write(data);
}

req.on('upgrade', (res, socket, head) => {
  if (res.statusCode !== 101) {
    console.error(`Unexpected status: ${res.statusCode}`);
    socket.destroy();
    process.exitCode = 1;
    return;
  }

  if (head.length) output(head);
  socket.on('data', output);
  socket.on('error', err => {
    console.error(`Socket error: ${err.message}`);
    process.exitCode = 1;
  });
  socket.on('end', () => {
    console.log('\n[Container stream ended]');
  });
});

req.on('response', res => {
  let body = '';

  res.on('data', chunk => body += chunk);
  res.on('end', () => {
    console.error(`Docker returned HTTP ${res.statusCode}: ${body}`);
    process.exitCode = 1;
  });
});

req.on('error', err => {
  console.error(`Docker API error: ${err.message}`);
  process.exitCode = 1;
});

req.end();
