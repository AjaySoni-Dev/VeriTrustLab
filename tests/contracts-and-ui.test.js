const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');

test('plain-text capability advertises the threat intelligence the runtime actually performs', () => {
  const source = fs.readFileSync(path.join(root, 'lib/email/contracts.js'), 'utf8');
  const plain = source.match(/plain_text:\s*Object\.freeze\(\{[\s\S]*?\}\),/u)?.[0] || '';
  assert.match(plain, /threat_intelligence:\s*true/u);
});

test('result UI says attachment metadata and truthful lineage wording', () => {
  const source = fs.readFileSync(path.join(root, 'assets/js/pages/email-investigation.js'), 'utf8');
  assert.match(source, /Attachment metadata \/ Links/u);
  assert.match(source, /Linked to a prior investigation as an evidence upgrade/u);
  assert.doesNotMatch(source, /Upgraded from a prior evidence stage/u);
  assert.doesNotMatch(source, /<polyline/u);
});

test('public OpenAPI evidence verification requires both passport and evidence', () => {
  const source = fs.readFileSync(path.join(root, 'openapi/veritrust-email-v2.yaml'), 'utf8');
  const schema = source.match(/EvidenceVerificationRequest:[\s\S]*?EvidenceVerificationResponse:/u)?.[0] || '';
  assert.match(schema, /required:\s*\n\s*- passport\s*\n\s*- evidence/u);
});
