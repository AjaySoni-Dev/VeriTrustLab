const test = require('node:test');
const assert = require('node:assert/strict');

process.env.VERITRUST_CONTENT_HMAC_KEY = 'test-content-hmac-key-'.repeat(4);

const {
  createEvidencePassport,
  matchPersistedPassport,
  verifyEvidencePackage,
} = require('../lib/email/evidence-passport');

function evidence() {
  return {
    schema_version: 'phishing-evidence-7',
    artifact_id: '11111111-1111-4111-8111-111111111111',
    input_mode: 'raw_eml',
    evidence_manifest: { completed_at: '2026-09-18T00:00:00.000Z', parser_version: 'test' },
    limitations: [],
    completed_at: '2026-09-18T00:00:00.000Z',
  };
}

function persistenceRow(passport) {
  const payload = { ...passport };
  delete payload.signature_algorithm;
  delete payload.key_id;
  delete payload.key_source;
  delete payload.public_key_jwk;
  delete payload.signature;
  return {
    payload,
    signature_algorithm: passport.signature_algorithm,
    key_id: passport.key_id,
    public_key_jwk: passport.public_key_jwk,
    signature: passport.signature,
    evidence_sha256: passport.evidence_sha256,
    manifest_sha256: passport.manifest_sha256,
  };
}

test('Evidence Passport verifies the complete evidence package and rejects tampering', () => {
  const original = evidence();
  const passport = createEvidencePassport({ scanId: '22222222-2222-4222-8222-222222222222', evidence: original, decision: { risk: 0.4, verdict: 'unknown' } });
  const trusted = verifyEvidencePackage({ passport, evidence: original }, { trustedKeyIds: [passport.key_id], requireTrustedIssuer: true });
  assert.equal(trusted.valid, true);
  assert.equal(trusted.evidence_hash_valid, true);
  assert.equal(trusted.manifest_hash_valid, true);

  const tampered = { ...original, input_mode: 'trusted_receiver_event' };
  const invalid = verifyEvidencePackage({ passport, evidence: tampered }, { trustedKeyIds: [passport.key_id], requireTrustedIssuer: true });
  assert.equal(invalid.valid, false);
  assert.equal(invalid.evidence_hash_valid, false);
  assert.ok(invalid.errors.includes('EVIDENCE_HASH_MISMATCH'));
});

test('persisted Passport is reused only when reconstructed evidence hashes match', () => {
  const original = evidence();
  const passport = createEvidencePassport({ scanId: '33333333-3333-4333-8333-333333333333', evidence: original });
  const row = persistenceRow(passport);
  const matched = matchPersistedPassport(original, row);
  assert.equal(matched.matched, true);
  assert.equal(matched.passport.passport_id, passport.passport_id);
  assert.equal(matched.passport.key_id, passport.key_id);
  assert.equal(matched.passport.signature, passport.signature);

  const changed = matchPersistedPassport({ ...original, limitations: ['NEW_LIMITATION'] }, row);
  assert.equal(changed.matched, false);
  assert.equal(changed.passport, null);
  assert.equal(changed.reason, 'SIGNED_EVIDENCE_SNAPSHOT_UNAVAILABLE');
});
