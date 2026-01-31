/**
 * Smoke test for OpenClaw Railway template
 */

const http = require('http');

const PORT = process.env.PORT || 8080;
const HOST = 'localhost';

async function request(path, options = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: HOST,
      port: PORT,
      path,
      method: options.method || 'GET',
      headers: options.headers || {},
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve({ status: res.statusCode, data }));
    });
    req.on('error', reject);
    req.end();
  });
}

async function runTests() {
  console.log('Running smoke tests...\n');

  const tests = [
    {
      name: 'Health check endpoint',
      fn: async () => {
        const res = await request('/setup/healthz');
        if (res.status !== 200) throw new Error(`Expected 200, got ${res.status}`);
        const data = JSON.parse(res.data);
        if (data.status !== 'ok') throw new Error(`Expected status ok, got ${data.status}`);
      }
    },
    {
      name: 'Setup page requires auth',
      fn: async () => {
        const res = await request('/setup');
        if (res.status !== 401) throw new Error(`Expected 401, got ${res.status}`);
      }
    },
    {
      name: 'Gateway returns 503 when not ready',
      fn: async () => {
        const res = await request('/');
        if (res.status !== 503) throw new Error(`Expected 503, got ${res.status}`);
      }
    },
  ];

  let passed = 0;
  let failed = 0;

  for (const test of tests) {
    try {
      await test.fn();
      console.log(`✓ ${test.name}`);
      passed++;
    } catch (err) {
      console.log(`✗ ${test.name}: ${err.message}`);
      failed++;
    }
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch(err => {
  console.error('Smoke test error:', err);
  process.exit(1);
});
