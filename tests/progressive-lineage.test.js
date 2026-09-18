const test = require('node:test');
const assert = require('node:assert/strict');
const {
  investigationLineage,
  validateLineageParentReport,
} = require('../lib/email/lineage');

function report(mode, overrides = {}) {
  return { scan: { id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', source: 'phishing-v2', status: 'completed', metadata: { input_mode: mode }, ...overrides } };
}

test('Progressive lineage allows only forward evidence acquisition', () => {
  const parent = validateLineageParentReport(report('plain_text'), 'raw_eml');
  assert.equal(parent.parentMode, 'plain_text');
  assert.throws(() => validateLineageParentReport(report('raw_eml'), 'raw_eml'), (error) => error.code === 'EMAIL_LINEAGE_STAGE_NOT_MONOTONIC');
  assert.throws(() => validateLineageParentReport(report('trusted_receiver_event'), 'raw_eml'), (error) => error.code === 'EMAIL_LINEAGE_STAGE_NOT_MONOTONIC');
});

test('Progressive lineage rejects incomplete or non-email parents', () => {
  assert.throws(() => validateLineageParentReport(report('plain_text', { status: 'processing' }), 'raw_eml'), (error) => error.code === 'EMAIL_LINEAGE_PARENT_INCOMPLETE');
  assert.throws(() => validateLineageParentReport(report('plain_text', { source: 'api' }), 'raw_eml'), (error) => error.code === 'EMAIL_LINEAGE_PARENT_TYPE_INVALID');
});

test('lineage wording data records a user-linked upgrade without claiming same-message proof', () => {
  const lineage = investigationLineage({ parentScanId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', currentScanId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', mode: 'raw_eml', parentMode: 'plain_text' });
  assert.equal(lineage.relationship, 'user_linked_evidence_upgrade');
  assert.equal(lineage.same_message_verified, false);
  assert.equal(lineage.parent_acquisition_stage, 'plain_text');
});
