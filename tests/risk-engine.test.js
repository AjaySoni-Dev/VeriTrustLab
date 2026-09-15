const test = require('node:test');
const assert = require('node:assert/strict');
const {
  buildPhishingIndicators,
  combinePhishingScores,
  scorePhishingIndicators,
} = require('../lib/risk-engine');

test('ordinary external links are contextual rather than suspicious by themselves', () => {
  const links = Array.from({ length: 10 }, (_, index) => `https://docs.example.com/resources/${index}`).join(' ');
  const indicators = buildPhishingIndicators(`Here are the requested documentation links: ${links}`);
  const external = indicators.find((item) => item.type === 'external_link');
  assert.ok(external);
  assert.equal(external.severity, 'Low');
  assert.equal(indicators.some((item) => item.type === 'suspicious_url'), false);
  assert.ok(scorePhishingIndicators(indicators) < 0.3);
});

test('normal account-action wording requires corroboration before medium email risk', () => {
  const indicators = buildPhishingIndicators('Please sign in to your account portal to review your monthly statement.');
  const rules = scorePhishingIndicators(indicators);
  const combined = combinePhishingScores(0.2, rules);
  assert.ok(rules < 0.45, `rule score ${rules} should remain below medium threshold`);
  assert.ok(combined < 0.45, `combined score ${combined} should remain below medium threshold`);
});

test('moderate provider phishing probability without corroboration is uncertain, not likely phishing', () => {
  const { phishingDecisionState } = require('../lib/risk-engine');
  assert.equal(phishingDecisionState('LIKELY_PHISHING', 0.72, 0.08, 0.58), 'UNCERTAIN');
  assert.equal(phishingDecisionState('LIKELY_PHISHING', 0.9, 0.08, 0.72), 'LIKELY_PHISHING');
  assert.equal(phishingDecisionState('LIKELY_PHISHING', 0.74, 0.5, 0.69), 'LIKELY_PHISHING');
});
