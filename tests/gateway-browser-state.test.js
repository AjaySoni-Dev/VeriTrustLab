const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');

const read = (path) => fs.readFileSync(path, 'utf8');

test('standalone demo-clutter pages stay removed while shared Gateway and Link engines remain enabled', () => {
  for (const path of ['detection.html', 'link-check.html', 'gateway.html', 'cli.html']) {
    assert.equal(fs.existsSync(path), false, `${path} must stay removed from the judge-facing product`);
  }

  const vercel = JSON.parse(read('vercel.json'));
  const redirects = new Map((vercel.redirects || []).map((entry) => [entry.source, entry.destination]));
  assert.equal(redirects.get('/detection'), '/phishing');
  assert.equal(redirects.get('/link-check'), '/phishing');
  assert.equal(redirects.get('/gateway'), '/phishing');
  assert.equal(redirects.get('/cli'), '/gateway-powershell#live-smtp');

  const modules = JSON.parse(read('config/modules.json'));
  assert.equal(modules.phishing, true);
  assert.equal(modules.link, true, 'embedded URL intelligence must remain available to email analysis');
  assert.equal(modules.gateway, true, 'shared correlation/Gateway engine must remain available');

  assert.equal(fs.existsSync('api/gateway.js'), true);
  assert.equal(fs.existsSync('lib/routes/gateway'), true);
  assert.equal(fs.existsSync('assets/js/pages/gateway.js'), false);
  assert.equal(fs.existsSync('assets/js/pages/link-check.js'), false);
  assert.equal(fs.existsSync('assets/js/pages/cli.js'), false);
});
