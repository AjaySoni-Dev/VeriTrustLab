const test = require('node:test');
const assert = require('node:assert/strict');
const { correlate, deterministicEmailRisk } = require('../lib/gateway/correlation');

const policy = {
  actions: { allow_below: 0.35, warn_below: 0.55, manual_review_below: 0.7, quarantine_below: 0.9, block_at_or_above: 0.9 },
  failure_modes: { interactive_text_url: 'hold' },
  enforcement: { mode: 'advisory', automatic_block: false, convert_block_to: 'quarantine' },
};

function evidence(kind, score, verdict = 'unknown', reasonCodes = []) {
  return { id: `${kind}-${Math.random()}`, kind, status: 'completed', score, verdict, confidence: 'moderate', reasonCodes, required: false };
}

test('many isolated medium link scores do not make an otherwise benign email suspicious', () => {
  const links = Array.from({ length: 10 }, (_, index) => evidence('link', 0.5 + index * 0.005, 'suspicious', ['URL_MANY_QUERY_PARAMS']));
  const result = correlate([
    evidence('phishing', 0.18, 'safe', []),
    ...links,
    { id: 'forensics', kind: 'email_forensics', status: 'completed', score: null, verdict: 'unknown', confidence: 'unknown', reasonCodes: ['LINK_DOMAIN_UNRELATED_TO_AUTHOR'], required: false },
  ], policy, { emailContext: true });
  assert.ok(result.risk < 0.45, `expected low risk, got ${result.risk}`);
  assert.equal(result.verdict, 'low');
});

test('a high-confidence malicious link can still elevate the email', () => {
  const result = correlate([
    evidence('phishing', 0.2, 'safe', []),
    evidence('link', 0.92, 'malicious', ['URL_BRAND_IMPERSONATION']),
  ], policy, { emailContext: true });
  assert.ok(result.risk >= 0.9);
  assert.equal(result.verdict, 'critical');
  assert.ok(result.reason_codes.includes('MALICIOUS_URL'));
});

test('temporary authentication errors are not treated as verified malicious authentication failures', () => {
  const tempOnly = deterministicEmailRisk(['SPF_TEMPERROR', 'CREDENTIAL_REQUEST']);
  const strongFailure = deterministicEmailRisk(['DMARC_FAIL', 'CREDENTIAL_REQUEST']);
  assert.ok(tempOnly < 0.45);
  assert.ok(strongFailure >= 0.7);
});
