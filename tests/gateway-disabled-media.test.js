const test = require('node:test');
const assert = require('node:assert/strict');
const { assertSubmissionModulesEnabled } = require('../lib/gateway/orchestrator');

test('Gateway rejects media when the deepfake module is disabled', () => {
  assert.throws(() => assertSubmissionModulesEnabled({ content: { media: [{ upload_id: 'x', kind: 'image' }] } }), (error) => error.code === 'GATEWAY_MEDIA_MODULE_DISABLED' && error.status === 422);
});

test('Gateway still accepts text/URL submissions when media is absent', () => {
  assert.doesNotThrow(() => assertSubmissionModulesEnabled({ content: { media: [], text: 'hello', urls: ['https://example.com/'] } }));
});

test('Gateway allows media to reach normal routing when the deepfake module is explicitly enabled', () => {
  const { spawnSync } = require('node:child_process');
  const modulePath = ['./lib/gateway', 'orchestrator'].join('/');
  const script = `const { assertSubmissionModulesEnabled } = require(${JSON.stringify(modulePath)}); assertSubmissionModulesEnabled({ content: { media: [{ upload_id: 'x', kind: 'image' }] } });`;
  const run = spawnSync(process.execPath, ['-e', script], {
    cwd: require('node:path').resolve(__dirname, '..'),
    env: { ...process.env, VERITRUST_MODULES: JSON.stringify({ deepfake: true }) },
    encoding: 'utf8',
  });
  assert.equal(run.status, 0, run.stderr || run.stdout);
});
