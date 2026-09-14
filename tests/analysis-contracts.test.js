const assert = require('node:assert/strict');
const test = require('node:test');
const results = require('../assets/js/core/analysis-result');
const { normalizeDeepfakeScores } = require('../lib/detection-service');
const { normalizeSwiftOutput } = require('../lib/link-intelligence');
const { validateGatewaySubmission } = require('../lib/gateway/contracts');

test('missing and invalid scores remain unavailable, including explicit null', () => {
  for (const value of [null, undefined, '', '0.5', NaN, Infinity, -1, 1.1]) assert.equal(results.percent(value), 'Not available');
  assert.equal(results.percent(0), '0%');
  assert.equal(results.percent(1), '100%');
});

test('deepfake accepts known probabilities and fails closed on unmapped or malformed output', () => {
  assert.equal(normalizeDeepfakeScores([{ label: 'Real', score: 0.9 }, { label: 'Fake', score: 0.1 }]).fakeScore, 0.1);
  for (const scores of [
    [], [{ label: 'LABEL_0', score: 1 }], [{ label: 'unreal', score: 1 }],
    [{ label: 'Real', score: 1 }],
    [{ label: 'Real', score: 0.9 }, { label: 'Fake', score: 0.9 }],
    [{ label: 'Real', score: null }, { label: 'Fake', score: 1 }],
    [{ label: 'Real', score: 0 }, { label: 'Fake', score: Infinity }],
    [{ label: 'Real', score: 0.5 }, { label: 'Real', score: 0.5 }],
  ]) assert.throws(() => normalizeDeepfakeScores(scores));
});

test('Swift validates the pinned binary class contract and preserves zero scores', () => {
  const safe = normalizeSwiftOutput([{ label: 'BENIGN', score: 1 }, { label: 'MALWARE', score: 0 }]);
  assert.equal(safe.model_score, 0);
  assert.equal(safe.confidence, 1);
  assert.equal(normalizeSwiftOutput([{ label: 'BENIGN', score: 0.1 }, { label: 'MALWARE', score: 0.9 }]).label, 'Malicious');
  for (const scores of [[], [{ label: 'unknown', score: 1 }], [{ label: 'BENIGN', score: 1 }], [{ label: 'BENIGN', score: 0.1 }, { label: 'MALWARE', score: '0.9' }]]) assert.throws(() => normalizeSwiftOutput(scores));
});

test('Gateway rejects missing and duplicated upload references before orchestration', () => {
  const media = { kind: 'image', upload_id: '12345678-1234-4123-8123-123456789012' };
  assert.throws(() => validateGatewaySubmission({ content: { media: [{ kind: 'image' }] } }), { code: 'GATEWAY_UPLOAD_REQUIRED' });
  assert.throws(() => validateGatewaySubmission({ content: { media: [media, media] } }), { code: 'GATEWAY_UPLOAD_DUPLICATE' });
  assert.equal(validateGatewaySubmission({ content: { media: [media] } }).content.media.length, 1);
});

test('browser validates every input before uploading media', () => {
  assert.throws(() => results.validateGatewayInput({}));
  assert.throws(() => results.validateGatewayInput({ urls: ['javascript:alert(1)'] }));
  assert.throws(() => results.validateGatewayInput({ urls: ['https://user:secret@example.test'] }));
  assert.throws(() => results.validateGatewayInput({ files: [{ name: 'empty.png', type: 'image/png', size: 0 }] }));
  assert.doesNotThrow(() => results.validateGatewayInput({ text: 'Review this', urls: ['https://example.test'] }));
});

test('deadline aborts requests with actionable uncertainty instead of claiming server failure', async () => {
  await assert.rejects(results.withDeadline((signal) => new Promise((resolve, reject) => {
    signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
  }), 5), /server may still be processing/);
  assert.equal(await results.withDeadline(async () => 'done', 10), 'done');
});
