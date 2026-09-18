const test = require('node:test');
const assert = require('node:assert/strict');
const { campaignFromMatches, normalizeEntity } = require('../lib/email/campaign-memory');

function match(scanId, entity) {
  return { scan_id: scanId, entity_type: entity.entity_type, entity_value: entity.entity_value, value_hash: entity.value_hash, weight: entity.weight, trust_level: entity.trust_level, created_at: '2026-09-18T00:00:00Z' };
}

test('Campaign Memory correlates an exact attachment hash by itself', () => {
  const attachment = normalizeEntity('attachment_sha256', 'a'.repeat(64));
  const result = campaignFromMatches('current', [attachment], [match('prior', attachment)]);
  assert.equal(result.state, 'CORRELATED');
  assert.equal(result.related_scan_count, 1);
});

test('Campaign Memory rejects a weak URL-domain-only overlap', () => {
  const domain = normalizeEntity('url_domain', 'example.com');
  const result = campaignFromMatches('current', [domain], [match('prior', domain)]);
  assert.equal(result.state, 'NO_STRONG_MATCH');
  assert.equal(result.related_scan_count, 0);
});

test('Campaign Memory accepts sufficient weighted overlap across independent entity types', () => {
  const domain = normalizeEntity('url_domain', 'example.com');
  const sender = normalizeEntity('from_domain', 'mail.example.com');
  const result = campaignFromMatches('current', [domain, sender], [match('prior', domain), match('prior', sender)]);
  assert.equal(result.state, 'CORRELATED');
  assert.equal(result.related_scan_count, 1);
});
