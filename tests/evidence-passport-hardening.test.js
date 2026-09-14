const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

process.env.VERITRUST_CONTENT_HMAC_KEY ||= 'test-only-veritrust-content-hmac-key-0123456789abcdef';

const {
  MAX_EVIDENCE_PACKAGE_BYTES,
  VERIFICATION_SCOPES,
  VERIFICATION_STATUS,
  assertJsonDomain,
  canonicalize,
  createEvidencePassport,
  hydrateEvidencePassport,
  signingKeyPair,
  trustedEvidenceKeyIds,
  validatePassportV1,
  verifyEvidencePackage,
} = require('../lib/email/evidence-passport');
const {
  evidencePassportRow,
  evidencePassportRowsEqual,
  persistEvidencePassport,
} = require('../lib/email/persistence');
const { resolveHistoricalEvidencePackage } = require('../lib/email/evidence-history');
const browserCore = require('../assets/js/core/evidence-passport-browser.js');

const ORG_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const SCAN_ID = '22222222-2222-4222-8222-222222222222';
const ARTIFACT_ID = '11111111-1111-4111-8111-111111111111';

function privateKeyPemFromSeed(byte) {
  const seed = Buffer.alloc(32, byte);
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  return crypto.createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' })
    .export({ format: 'pem', type: 'pkcs8' })
    .toString();
}

const KEY_A_PEM = privateKeyPemFromSeed(0x11);
const KEY_B_PEM = privateKeyPemFromSeed(0x22);

function sampleEvidence() {
  return {
    schema_version: 'phishing-evidence-7',
    scan_id: SCAN_ID,
    artifact_id: ARTIFACT_ID,
    input_mode: 'trusted_receiver_event',
    state: 'UNCERTAIN',
    completed_at: '2026-09-11T08:00:00.000Z',
    evidence_manifest: {
      schema_version: 'phishing-evidence-7',
      pipeline_version: 'mailgraph-pipeline-6',
      raw_sha256: 'a'.repeat(64),
      completed_at: '2026-09-11T08:00:00.000Z',
    },
    observations: [{ code: 'TEST_OBSERVATION', source: 'test', quality: 'direct' }],
    infrastructure: [{ ip_address: '8.8.8.8', ip_classification: 'public', trust_level: 'trusted_receiver' }],
    limitations: [],
  };
}

function sampleDecision() {
  return {
    risk: 0.72,
    severity: 'high',
    verdict: 'high',
    recommendation: 'manual_review',
    degraded: false,
    reason_codes: ['TEST'],
    correlation_version: 'gateway-correlation-v3',
  };
}

function issueWithKey(pem, trusted = '') {
  process.env.VERITRUST_EVIDENCE_SIGNING_PRIVATE_KEY = pem;
  process.env.VERITRUST_EVIDENCE_TRUSTED_KEY_IDS = trusted;
  const evidence = sampleEvidence();
  const passport = createEvidencePassport({ scanId: SCAN_ID, evidence, decision: sampleDecision() });
  return { evidence, passport };
}

function restoreEnv(snapshot) {
  for (const [key, value] of Object.entries(snapshot)) {
    if (typeof value === 'undefined') delete process.env[key];
    else process.env[key] = value;
  }
}

function envSnapshot() {
  return {
    NODE_ENV: process.env.NODE_ENV,
    VERCEL_ENV: process.env.VERCEL_ENV,
    VERITRUST_EVIDENCE_SIGNING_PRIVATE_KEY: process.env.VERITRUST_EVIDENCE_SIGNING_PRIVATE_KEY,
    VERITRUST_EVIDENCE_TRUSTED_KEY_IDS: process.env.VERITRUST_EVIDENCE_TRUSTED_KEY_IDS,
  };
}

function mutationCases(passport) {
  const validIdButWrong = `vt_evp_${passport.passport_id.slice(-24).replace(/^./u, passport.passport_id.endsWith('0') ? '1' : '0')}`;
  return [
    ['unsupported version', (p) => { p.passport_version = 'veritrust-evidence-passport-2'; }, 'UNSUPPORTED_PASSPORT_VERSION'],
    ['unsupported algorithm', (p) => { p.signature_algorithm = 'RSA-PSS'; }, 'UNSUPPORTED_SIGNATURE_ALGORITHM'],
    ['malformed passport id', (p) => { p.passport_id = 'vt_bad'; }, 'PASSPORT_ID_INVALID'],
    ['passport id mismatch', (p) => { p.passport_id = validIdButWrong; }, 'PASSPORT_ID_MISMATCH'],
    ['malformed evidence digest', (p) => { p.evidence_sha256 = 'ABC'; }, 'EVIDENCE_DIGEST_INVALID'],
    ['malformed manifest digest', (p) => { p.manifest_sha256 = 'xyz'; }, 'MANIFEST_DIGEST_INVALID'],
    ['malformed key id', (p) => { p.key_id = 'ed25519:not-hex'; }, 'KEY_ID_INVALID'],
    ['private JWK material', (p) => { p.public_key_jwk.d = 'secret'; }, 'PUBLIC_KEY_PRIVATE_MATERIAL'],
    ['wrong JWK curve', (p) => { p.public_key_jwk.crv = 'X25519'; }, 'PUBLIC_KEY_INVALID'],
    ['ambiguous JWK field', (p) => { p.public_key_jwk.use = 'sig'; }, 'PUBLIC_KEY_AMBIGUOUS_FIELDS'],
    ['malformed JWK x characters', (p) => { p.public_key_jwk.x = `${p.public_key_jwk.x.slice(0, -1)}=`; }, 'PUBLIC_KEY_X_INVALID'],
    ['incorrect JWK x length', (p) => { p.public_key_jwk.x = p.public_key_jwk.x.slice(0, -1); }, 'PUBLIC_KEY_X_INVALID'],
    ['invalid signature characters', (p) => { p.signature = `${p.signature.slice(0, -1)}!`; }, 'SIGNATURE_ENCODING_INVALID'],
    ['incorrect signature length', (p) => { p.signature = p.signature.slice(0, -1); }, 'SIGNATURE_ENCODING_INVALID'],
    ['invalid scan UUID', (p) => { p.scan_id = 'scan-123'; }, 'SCAN_ID_INVALID'],
    ['invalid artifact UUID', (p) => { p.artifact_id = 'artifact-123'; }, 'ARTIFACT_ID_INVALID'],
    ['invalid timestamp', (p) => { p.issued_at = 'not-a-time'; }, 'ISSUED_AT_INVALID'],
    ['oversized statement', (p) => { p.statement = 'x'.repeat(2049); }, 'STATEMENT_INVALID'],
    ['unknown Passport field', (p) => { p.surprise = true; }, 'PASSPORT_UNKNOWN_FIELD'],
  ];
}

test('full verification, Passport-only, unknown issuer, and untrusted issuer have distinct semantics', () => {
  const snapshot = envSnapshot();
  try {
    const { evidence, passport } = issueWithKey(KEY_A_PEM);
    const trusted = [passport.key_id];
    const full = verifyEvidencePackage({ passport, evidence }, { trustedKeyIds: trusted });
    assert.equal(full.status, VERIFICATION_STATUS.VERIFIED);
    assert.equal(full.verification_scope, VERIFICATION_SCOPES.FULL_PACKAGE);
    assert.equal(full.valid, true);
    assert.equal(full.evidence_integrity_checked, true);
    assert.equal(full.manifest_integrity_checked, true);
    assert.equal(full.evidence_hash_valid, true);
    assert.equal(full.manifest_hash_valid, true);

    const partial = verifyEvidencePackage({ passport }, { trustedKeyIds: trusted });
    assert.equal(partial.status, VERIFICATION_STATUS.PASSPORT_SIGNATURE_VERIFIED_EVIDENCE_NOT_CHECKED);
    assert.equal(partial.verification_scope, VERIFICATION_SCOPES.PASSPORT_ONLY);
    assert.equal(partial.valid, false);
    assert.equal(partial.evidence_integrity_checked, false);
    assert.equal(partial.manifest_integrity_checked, false);
    assert.equal(partial.evidence_hash_valid, null);
    assert.equal(partial.manifest_hash_valid, null);
    assert.ok(partial.warnings.includes('EVIDENCE_NOT_CHECKED'));

    const unknown = verifyEvidencePackage({ passport, evidence });
    assert.equal(unknown.status, VERIFICATION_STATUS.CRYPTOGRAPHICALLY_VALID_ISSUER_UNKNOWN);
    assert.equal(unknown.signature_valid, true);
    assert.equal(unknown.issuer_trusted, null);
    assert.equal(unknown.valid, false);

    const untrusted = verifyEvidencePackage({ passport, evidence }, { trustedKeyIds: ['ed25519:000000000000000000000000'] });
    assert.equal(untrusted.status, VERIFICATION_STATUS.UNTRUSTED_ISSUER);
    assert.equal(untrusted.signature_valid, true);
    assert.equal(untrusted.key_id_valid, true);
    assert.equal(untrusted.evidence_hash_valid, true);
    assert.equal(untrusted.issuer_trusted, false);
    assert.equal(untrusted.valid, false);
  } finally { restoreEnv(snapshot); }
});

test('evidence and manifest tampering fail independently', () => {
  const snapshot = envSnapshot();
  try {
    const { evidence, passport } = issueWithKey(KEY_A_PEM);
    const trusted = [passport.key_id];
    const evidenceTamper = structuredClone(evidence);
    evidenceTamper.state = 'LIKELY_BENIGN';
    const evidenceResult = verifyEvidencePackage({ passport, evidence: evidenceTamper }, { trustedKeyIds: trusted });
    assert.equal(evidenceResult.valid, false);
    assert.equal(evidenceResult.evidence_hash_valid, false);
    assert.ok(evidenceResult.errors.includes('EVIDENCE_HASH_MISMATCH'));

    const manifestTamper = structuredClone(evidence);
    manifestTamper.evidence_manifest.pipeline_version = 'tampered';
    const manifestResult = verifyEvidencePackage({ passport, evidence: manifestTamper }, { trustedKeyIds: trusted });
    assert.equal(manifestResult.valid, false);
    assert.equal(manifestResult.manifest_hash_valid, false);
    assert.ok(manifestResult.errors.includes('MANIFEST_HASH_MISMATCH'));
  } finally { restoreEnv(snapshot); }
});

test('strict v1 validation rejects malformed, ambiguous, and internally inconsistent Passports before trust is granted', () => {
  const snapshot = envSnapshot();
  try {
    const { evidence, passport } = issueWithKey(KEY_A_PEM);
    for (const [name, mutate, expectedCode] of mutationCases(passport)) {
      const candidate = structuredClone(passport);
      mutate(candidate);
      const validation = validatePassportV1(candidate);
      assert.ok(validation.errors.includes(expectedCode), `${name} should include ${expectedCode}; got ${validation.errors.join(', ')}`);
      const result = verifyEvidencePackage({ passport: candidate, evidence }, { trustedKeyIds: [passport.key_id] });
      assert.equal(result.valid, false, `${name} must never be fully valid`);
      assert.equal(result.status, VERIFICATION_STATUS.VERIFICATION_FAILED, `${name} must fail verification`);
    }
  } finally { restoreEnv(snapshot); }
});

test('canonicalization rejects non-JSON runtime values, cycles, depth overflow, and node overflow', () => {
  const badValues = [
    undefined,
    1n,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    Number.NEGATIVE_INFINITY,
    () => 1,
    Symbol('x'),
    new Date('2026-01-01T00:00:00Z'),
  ];
  for (const value of badValues) assert.throws(() => canonicalize({ value }), (error) => error?.code === 'EVIDENCE_JSON_DOMAIN_INVALID');
  assert.throws(() => canonicalize([undefined]), (error) => error?.code === 'EVIDENCE_JSON_DOMAIN_INVALID');
  const cycle = {}; cycle.self = cycle;
  assert.throws(() => canonicalize(cycle), (error) => error?.code === 'EVIDENCE_JSON_CYCLE');

  let deep = 'leaf';
  for (let index = 0; index < 66; index += 1) deep = { next: deep };
  assert.throws(() => canonicalize(deep), (error) => error?.code === 'EVIDENCE_CANONICALIZATION_LIMIT');
  assert.throws(() => canonicalize(Array.from({ length: 50001 }, () => 0)), (error) => error?.code === 'EVIDENCE_CANONICALIZATION_LIMIT');
  assert.doesNotThrow(() => assertJsonDomain({ ok: [null, true, false, 1.5, 'text'] }));
});

test('fixed canonicalization vectors are byte-identical in Node and browser implementations', () => {
  const vectors = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures/evidence-passport-canonicalization.json'), 'utf8'));
  for (const vector of vectors) {
    assert.equal(canonicalize(vector.input), vector.canonical, `${vector.name} Node canonicalization changed`);
    assert.equal(browserCore.canonicalize(vector.input), vector.canonical, `${vector.name} browser canonicalization changed`);
  }
});

test('Node and browser verification cores agree on full and Passport-only v1 results', async () => {
  const snapshot = envSnapshot();
  try {
    const { evidence, passport } = issueWithKey(KEY_A_PEM);
    const trustedKeyIds = [passport.key_id];
    const nodeFull = verifyEvidencePackage({ passport, evidence }, { trustedKeyIds });
    const browserFull = await browserCore.verifyEvidencePackage({ passport, evidence }, { trustedKeyIds });
    assert.deepEqual(browserFull, nodeFull);
    const nodePartial = verifyEvidencePackage({ passport }, { trustedKeyIds });
    const browserPartial = await browserCore.verifyEvidencePackage({ passport }, { trustedKeyIds });
    assert.deepEqual(browserPartial, nodePartial);
  } finally { restoreEnv(snapshot); }
});

test('production-like signing fails closed without a dedicated Ed25519 key', () => {
  const snapshot = envSnapshot();
  try {
    process.env.NODE_ENV = 'production';
    delete process.env.VERCEL_ENV;
    delete process.env.VERITRUST_EVIDENCE_SIGNING_PRIVATE_KEY;
    assert.throws(() => signingKeyPair(), (error) => error?.code === 'EVIDENCE_SIGNING_KEY_REQUIRED');
    process.env.VERITRUST_EVIDENCE_SIGNING_PRIVATE_KEY = KEY_A_PEM;
    const key = signingKeyPair();
    assert.equal(key.privateKey.asymmetricKeyType, 'ed25519');
    assert.equal(key.keySource, 'dedicated');
  } finally { restoreEnv(snapshot); }
});

test('key rotation preserves old signatures while issuer trust can be retired independently', () => {
  const snapshot = envSnapshot();
  try {
    const issuedA = issueWithKey(KEY_A_PEM);
    const oldSignature = issuedA.passport.signature;
    const oldPassportId = issuedA.passport.passport_id;
    const keyA = issuedA.passport.key_id;

    process.env.VERITRUST_EVIDENCE_SIGNING_PRIVATE_KEY = KEY_B_PEM;
    process.env.VERITRUST_EVIDENCE_TRUSTED_KEY_IDS = keyA;
    const issuedB = createEvidencePassport({ scanId: '33333333-3333-4333-8333-333333333333', evidence: { ...sampleEvidence(), scan_id: '33333333-3333-4333-8333-333333333333' } });
    assert.notEqual(issuedB.key_id, keyA);
    const trustedAfterRotation = trustedEvidenceKeyIds();
    assert.ok(trustedAfterRotation.includes(keyA));
    assert.ok(trustedAfterRotation.includes(issuedB.key_id));
    const oldStillTrusted = verifyEvidencePackage({ passport: issuedA.passport, evidence: issuedA.evidence }, { trustedKeyIds: trustedAfterRotation });
    assert.equal(oldStillTrusted.status, VERIFICATION_STATUS.VERIFIED);

    process.env.VERITRUST_EVIDENCE_TRUSTED_KEY_IDS = '';
    const oldRetired = verifyEvidencePackage({ passport: issuedA.passport, evidence: issuedA.evidence }, { trustedKeyIds: trustedEvidenceKeyIds() });
    assert.equal(oldRetired.signature_valid, true);
    assert.equal(oldRetired.key_id_valid, true);
    assert.equal(oldRetired.issuer_trusted, false);
    assert.equal(oldRetired.status, VERIFICATION_STATUS.UNTRUSTED_ISSUER);
    assert.equal(issuedA.passport.signature, oldSignature);
    assert.equal(issuedA.passport.passport_id, oldPassportId);
  } finally { restoreEnv(snapshot); }
});

test('Evidence Passport persistence stores exact normalized evidence and makes duplicate writes conflict-safe', async () => {
  const snapshot = envSnapshot();
  try {
    const { evidence, passport } = issueWithKey(KEY_A_PEM);
    const expected = evidencePassportRow(ORG_ID, SCAN_ID, ARTIFACT_ID, passport, { ...evidence, evidence_passport: passport });
    assert.deepEqual(expected.evidence_payload, evidence);
    assert.equal(Object.hasOwn(expected.evidence_payload, 'evidence_passport'), false);

    let postCalls = 0;
    const replay = await persistEvidencePassport(ORG_ID, SCAN_ID, ARTIFACT_ID, passport, evidence, {
      fetcher: async (_url, options = {}) => {
        if (options.method === 'POST') postCalls += 1;
        return [structuredClone(expected)];
      },
    });
    assert.equal(replay.replayed, true);
    assert.equal(postCalls, 0);

    const conflicting = structuredClone(expected);
    conflicting.evidence_sha256 = 'f'.repeat(64);
    await assert.rejects(() => persistEvidencePassport(ORG_ID, SCAN_ID, ARTIFACT_ID, passport, evidence, {
      fetcher: async () => [conflicting],
    }), (error) => error?.code === 'EVIDENCE_PASSPORT_CONFLICT');

    let firstRead = true;
    const inserted = await persistEvidencePassport(ORG_ID, SCAN_ID, ARTIFACT_ID, passport, evidence, {
      fetcher: async (_url, options = {}) => {
        if (options.method === 'POST') return [structuredClone(expected)];
        if (firstRead) { firstRead = false; return []; }
        return [structuredClone(expected)];
      },
    });
    assert.equal(inserted.replayed, false);
    assert.ok(evidencePassportRowsEqual(inserted.row, expected));

    let getCount = 0;
    const recovered = await persistEvidencePassport(ORG_ID, SCAN_ID, ARTIFACT_ID, passport, evidence, {
      fetcher: async (_url, options = {}) => {
        if (options.method === 'POST') throw Object.assign(new Error('network timeout'), { code: 'ETIMEDOUT' });
        getCount += 1;
        return getCount === 1 ? [] : [structuredClone(expected)];
      },
    });
    assert.equal(recovered.recovered_after_ambiguous_insert, true);
    assert.equal(recovered.replayed, true);

    const oversized = { ...evidence, large: 'x'.repeat(MAX_EVIDENCE_PACKAGE_BYTES + 64) };
    assert.throws(() => evidencePassportRow(ORG_ID, SCAN_ID, ARTIFACT_ID, passport, oversized), (error) => error?.code === 'EVIDENCE_PASSPORT_PAYLOAD_TOO_LARGE');
  } finally { restoreEnv(snapshot); }
});

test('hydration refuses duplicated-field drift in persisted signed records', () => {
  const snapshot = envSnapshot();
  try {
    const { evidence, passport } = issueWithKey(KEY_A_PEM);
    const row = evidencePassportRow(ORG_ID, SCAN_ID, ARTIFACT_ID, passport, evidence);
    const hydrated = hydrateEvidencePassport(row);
    assert.deepEqual(hydrated, passport);
    const drifted = structuredClone(row);
    drifted.evidence_sha256 = '0'.repeat(64);
    assert.throws(() => hydrateEvidencePassport(drifted), (error) => error?.code === 'EVIDENCE_PASSPORT_STORED_INTEGRITY_ERROR');
  } finally { restoreEnv(snapshot); }
});

test('historical exact evidence returns the original Passport across key rotation and never substitutes the active key', () => {
  const snapshot = envSnapshot();
  try {
    const { evidence, passport } = issueWithKey(KEY_A_PEM);
    const keyA = passport.key_id;
    const row = evidencePassportRow(ORG_ID, SCAN_ID, ARTIFACT_ID, passport, evidence);
    process.env.VERITRUST_EVIDENCE_SIGNING_PRIVATE_KEY = KEY_B_PEM;
    process.env.VERITRUST_EVIDENCE_TRUSTED_KEY_IDS = keyA;
    const keyB = signingKeyPair().keyId;
    assert.notEqual(keyB, keyA);

    const resolved = resolveHistoricalEvidencePackage({
      orgId: ORG_ID,
      scanId: SCAN_ID,
      artifactId: ARTIFACT_ID,
      passportRow: structuredClone(row),
    });
    assert.equal(resolved.evidence.evidence_passport.key_id, keyA);
    assert.equal(resolved.evidence.evidence_passport.signature, passport.signature);
    assert.equal(resolved.evidence.evidence_passport.passport_id, passport.passport_id);
    assert.notEqual(resolved.evidence.evidence_passport.key_id, keyB);

    process.env.VERITRUST_EVIDENCE_TRUSTED_KEY_IDS = '';
    const retiredIssuerRead = resolveHistoricalEvidencePackage({
      orgId: ORG_ID,
      scanId: SCAN_ID,
      artifactId: ARTIFACT_ID,
      passportRow: structuredClone(row),
    });
    assert.equal(retiredIssuerRead.evidence.evidence_passport.signature, passport.signature);
    assert.equal(retiredIssuerRead.evidence.evidence_passport.key_id, keyA);
  } finally { restoreEnv(snapshot); }
});

test('legacy historical rows without exact evidence are reconstructed unsigned and are not issued replacement Passports', () => {
  const snapshot = envSnapshot();
  try {
    const { evidence, passport } = issueWithKey(KEY_A_PEM);
    const row = evidencePassportRow(ORG_ID, SCAN_ID, ARTIFACT_ID, passport, evidence);
    row.evidence_payload = null;
    process.env.VERITRUST_EVIDENCE_SIGNING_PRIVATE_KEY = KEY_B_PEM;
    process.env.VERITRUST_EVIDENCE_TRUSTED_KEY_IDS = passport.key_id;

    const resolved = resolveHistoricalEvidencePackage({
      orgId: ORG_ID,
      scanId: SCAN_ID,
      artifactId: ARTIFACT_ID,
      passportRow: row,
      storedEvidence: null,
      passportSchemaAvailable: true,
    });
    assert.equal(resolved.evidence, null);
    assert.equal(resolved.evidence_integrity.status, 'RECONSTRUCTED_UNSIGNED');
    assert.equal(resolved.evidence_integrity.signed_package_available, false);
    assert.equal(resolved.evidence_integrity.limitation, 'EVIDENCE_PASSPORT_LEGACY_EXACT_EVIDENCE_UNAVAILABLE');
    assert.equal(resolved.evidence_integrity.original_passport.passport_id, passport.passport_id);
    assert.equal(resolved.evidence_integrity.original_passport.key_id, passport.key_id);
    assert.notEqual(signingKeyPair().keyId, passport.key_id);
  } finally { restoreEnv(snapshot); }
});

test('legacy idempotent evidence is accepted only when it proves the persisted Passport digest', () => {
  const snapshot = envSnapshot();
  try {
    const { evidence, passport } = issueWithKey(KEY_A_PEM);
    const row = evidencePassportRow(ORG_ID, SCAN_ID, ARTIFACT_ID, passport, evidence);
    row.evidence_payload = null;
    const storedEvidence = { ...evidence, evidence_passport: passport };
    const resolved = resolveHistoricalEvidencePackage({
      orgId: ORG_ID,
      scanId: SCAN_ID,
      artifactId: ARTIFACT_ID,
      passportRow: row,
      storedEvidence,
    });
    assert.equal(resolved.evidence, storedEvidence);

    const tampered = structuredClone(storedEvidence);
    tampered.state = 'LIKELY_BENIGN';
    assert.throws(() => resolveHistoricalEvidencePackage({
      orgId: ORG_ID,
      scanId: SCAN_ID,
      artifactId: ARTIFACT_ID,
      passportRow: row,
      storedEvidence: tampered,
    }), (error) => error?.code === 'EVIDENCE_PASSPORT_STORED_INTEGRITY_ERROR');
  } finally { restoreEnv(snapshot); }
});

test('historical rows with no Passport expose an explicit not-originally-recorded limitation', () => {
  const resolved = resolveHistoricalEvidencePackage({
    orgId: ORG_ID,
    scanId: SCAN_ID,
    artifactId: ARTIFACT_ID,
    passportRow: null,
    storedEvidence: null,
    passportSchemaAvailable: true,
  });
  assert.equal(resolved.evidence, null);
  assert.equal(resolved.evidence_integrity.status, 'NOT_ORIGINALLY_RECORDED');
  assert.equal(resolved.evidence_integrity.limitation, 'EVIDENCE_PASSPORT_NOT_ORIGINALLY_RECORDED');
});

test('browser verifier normal path sends only a public trust GET; server evidence upload occurs only via explicit fallback call', async () => {
  const snapshot = envSnapshot();
  try {
    const { evidence, passport } = issueWithKey(KEY_A_PEM);
    const calls = [];
    const fakeWindow = {
      VeriTrustEvidencePassport: browserCore,
      location: { search: '' },
      fetch: async (url, options = {}) => {
        calls.push({ url, options });
        if (url === '/api/v2/phishing/evidence-trust') {
          return { ok: true, status: 200, json: async () => ({ schema_version: 'veritrust-evidence-trust-1', trusted_key_ids: [passport.key_id] }) };
        }
        if (url === '/api/v2/phishing/verify-evidence') {
          return { ok: true, status: 200, json: async () => ({ verification: verifyEvidencePackage(JSON.parse(options.body), { trustedKeyIds: [passport.key_id] }) }) };
        }
        throw new Error(`Unexpected URL ${url}`);
      },
    };
    const fakeDocument = { querySelector: () => null, addEventListener: () => {} };
    const source = fs.readFileSync(path.join(__dirname, '../assets/js/pages/verify-evidence.js'), 'utf8');
    vm.runInNewContext(source, {
      window: fakeWindow,
      document: fakeDocument,
      URLSearchParams,
      Blob,
      JSON,
      Error,
      String,
      Array,
      Object,
      Set,
    }, { filename: 'verify-evidence.js' });

    const localResult = await fakeWindow.VeriTrustEvidenceVerifyPage.verifyPackageLocal({ passport, evidence });
    assert.equal(localResult.status, VERIFICATION_STATUS.VERIFIED);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, '/api/v2/phishing/evidence-trust');
    assert.equal(calls[0].options.method, 'GET');
    assert.equal(calls.some((call) => call.options.method === 'POST'), false);

    const fallback = await fakeWindow.VeriTrustEvidenceVerifyPage.verifyPackageOnServer({ passport, evidence });
    assert.equal(fallback.status, VERIFICATION_STATUS.VERIFIED);
    assert.equal(calls.length, 2);
    assert.equal(calls[1].url, '/api/v2/phishing/verify-evidence');
    assert.equal(calls[1].options.method, 'POST');
    assert.ok(String(calls[1].options.body).includes(passport.passport_id));
  } finally { restoreEnv(snapshot); }
});

test('browser local cryptography continues when issuer registry is unavailable and reports trust as UNKNOWN', async () => {
  const snapshot = envSnapshot();
  try {
    const { evidence, passport } = issueWithKey(KEY_A_PEM);
    const fakeWindow = {
      VeriTrustEvidencePassport: browserCore,
      location: { search: '' },
      fetch: async () => { throw new Error('registry unavailable'); },
    };
    const fakeDocument = { querySelector: () => null, addEventListener: () => {} };
    const source = fs.readFileSync(path.join(__dirname, '../assets/js/pages/verify-evidence.js'), 'utf8');
    vm.runInNewContext(source, { window: fakeWindow, document: fakeDocument, URLSearchParams, Blob, JSON, Error, String, Array, Object, Set });
    const result = await fakeWindow.VeriTrustEvidenceVerifyPage.verifyPackageLocal({ passport, evidence });
    assert.equal(result.signature_valid, true);
    assert.equal(result.evidence_hash_valid, true);
    assert.equal(result.issuer_trusted, null);
    assert.equal(result.status, VERIFICATION_STATUS.CRYPTOGRAPHICALLY_VALID_ISSUER_UNKNOWN);
    assert.equal(result.valid, false);
  } finally { restoreEnv(snapshot); }
});

test('forward migration and public contracts preserve server-only RLS and precise retention semantics', () => {
  const migration = fs.readFileSync(path.join(__dirname, '../supabase/migrations/20260914_evidence_passport_hardening.sql'), 'utf8');
  const openapi = fs.readFileSync(path.join(__dirname, '../openapi/veritrust-email-v2.yaml'), 'utf8');
  const verifierHtml = fs.readFileSync(path.join(__dirname, '../verify-evidence.html'), 'utf8');
  const verifierJs = fs.readFileSync(path.join(__dirname, '../assets/js/pages/verify-evidence.js'), 'utf8');
  const reportPdf = fs.readFileSync(path.join(__dirname, '../assets/js/core/email-report-pdf.js'), 'utf8');

  assert.match(migration, /add column if not exists evidence_payload jsonb null/iu);
  assert.doesNotMatch(migration, /update\s+public\.email_evidence_passports\s+set/iu);
  assert.match(migration, /foreign key \(scan_id, org_id\)[\s\S]*gateway_scans\(id, org_id\)/iu);
  assert.match(migration, /foreign key \(artifact_id, scan_id, org_id\)[\s\S]*gateway_artifacts\(id, scan_id, org_id\)/iu);
  assert.match(migration, /enable row level security/iu);
  assert.match(migration, /revoke all on table public\.email_evidence_passports from anon, authenticated/iu);
  assert.match(migration, /not WORM/iu);
  assert.match(migration, /raise exception/iu);

  assert.match(openapi, /\/api\/v2\/phishing\/evidence-trust:/u);
  assert.match(openapi, /FULL_PACKAGE/u);
  assert.match(openapi, /PASSPORT_ONLY/u);
  assert.match(openapi, /CRYPTOGRAPHICALLY_VALID_ISSUER_UNKNOWN/u);
  assert.match(openapi, /evidence_integrity_checked/u);
  assert.match(openapi, /manifest_integrity_checked/u);

  assert.match(verifierHtml, /aria-live="polite"/u);
  assert.match(verifierHtml, /Verification runs locally in this browser/iu);
  assert.match(verifierHtml, /server fallback/iu);
  assert.match(verifierJs, /NOT CHECKED/u);
  assert.match(verifierJs, /UNKNOWN/u);
  assert.match(reportPdf, /PDF bytes themselves are not covered by the Passport unless separately signed/iu);
});
