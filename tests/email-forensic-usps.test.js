const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');

process.env.VERITRUST_CONTENT_HMAC_KEY ||= 'test-only-veritrust-content-hmac-key-0123456789abcdef';

const { buildThreatEntities, campaignFromMatches, normalizeEntity } = require('../lib/email/campaign-memory');
const { canonicalize, createEvidencePassport, sha256, trustedEvidenceKeyIds, verifyEvidencePackage } = require('../lib/email/evidence-passport');
const { collectIocs, toCsv, toStixBundle } = require('../lib/email/ioc-export');
const { normalizeDomain } = require('../lib/email/threat-intelligence');
const { deterministicEmailRisk } = require('../lib/gateway/correlation');

function sampleEvidence() {
  return {
    schema_version: 'phishing-evidence-7',
    artifact_id: '11111111-1111-4111-8111-111111111111',
    input_mode: 'trusted_receiver_event',
    state: 'UNCERTAIN',
    completed_at: '2026-09-11T08:00:00.000Z',
    evidence_manifest: { schema_version: 'phishing-evidence-7', pipeline_version: 'mailgraph-pipeline-6', raw_sha256: 'a'.repeat(64) },
    infrastructure: [{ ip_address: '8.8.8.8', ip_classification: 'public', trust_level: 'trusted_receiver' }],
    children: [
      { type: 'url', metadata: { url: 'https://login.example.test/account', hostname: 'login.example.test' } },
      { type: 'attachment', metadata: { sha256: 'b'.repeat(64), original_filename_untrusted: 'invoice.pdf' } },
    ],
    threat_intelligence: { domain_intelligence: [{ domain: 'example.test' }], ip_reputation: [] },
  };
}

test('Evidence Passport verifies unchanged evidence and rejects tampering', () => {
  const evidence = sampleEvidence();
  const scanId = '22222222-2222-4222-8222-222222222222';
  const passport = createEvidencePassport({ scanId, evidence, decision: { risk: 0.72, severity: 'high', verdict: 'high', recommendation: 'manual_review', degraded: false, reason_codes: ['TEST'], correlation_version: 'gateway-correlation-v3' } });
  const packaged = { ...evidence, evidence_passport: passport };
  const valid = verifyEvidencePackage({ passport, evidence: packaged });
  assert.equal(valid.valid, true);
  assert.equal(valid.signature_valid, true);
  assert.equal(valid.key_id_valid, true);
  assert.equal(valid.evidence_hash_valid, true);
  assert.equal(valid.manifest_hash_valid, true);

  const tampered = structuredClone(packaged);
  tampered.state = 'LIKELY_BENIGN';
  const invalid = verifyEvidencePackage({ passport, evidence: tampered });
  assert.equal(invalid.valid, false);
  assert.equal(invalid.evidence_hash_valid, false);
  assert.ok(invalid.errors.includes('EVIDENCE_HASH_MISMATCH'));
});

test('Evidence verification rejects a self-consistent package signed by an unrecognized issuer', () => {
  const evidence = sampleEvidence();
  const scanId = '77777777-7777-4777-8777-777777777777';
  const legitimate = createEvidencePassport({ scanId, evidence });
  const signedFields = { ...legitimate };
  for (const key of ['signature_algorithm', 'key_id', 'key_source', 'public_key_jwk', 'signature']) delete signedFields[key];
  const attacker = crypto.generateKeyPairSync('ed25519');
  const attackerJwk = attacker.publicKey.export({ format: 'jwk' });
  const publicDer = attacker.publicKey.export({ format: 'der', type: 'spki' });
  const forged = {
    ...signedFields,
    signature_algorithm: 'Ed25519',
    key_id: `ed25519:${sha256(publicDer).slice(0, 24)}`,
    key_source: 'forged',
    public_key_jwk: attackerJwk,
    signature: crypto.sign(null, Buffer.from(canonicalize(signedFields), 'utf8'), attacker.privateKey).toString('base64url'),
  };
  const result = verifyEvidencePackage({ passport: forged, evidence }, { trustedKeyIds: trustedEvidenceKeyIds(), requireTrustedIssuer: true });
  assert.equal(result.signature_valid, true);
  assert.equal(result.key_id_valid, true);
  assert.equal(result.issuer_trusted, false);
  assert.equal(result.valid, false);
  assert.ok(result.errors.includes('UNTRUSTED_SIGNING_KEY'));
});

test('Campaign Memory refuses ASN-only overlap but correlates a durable URL domain', () => {
  const currentScan = '33333333-3333-4333-8333-333333333333';
  const asn = normalizeEntity('infrastructure_asn', 'AS13335');
  const weak = campaignFromMatches(currentScan, [asn], [{ scan_id: '44444444-4444-4444-8444-444444444444', ...asn, created_at: '2026-09-10T10:00:00Z' }]);
  assert.equal(weak.state, 'NO_STRONG_MATCH');
  assert.equal(weak.campaign_id, null);

  const domain = normalizeEntity('url_domain', 'credential-check.example');
  const domainOnly = campaignFromMatches(currentScan, [domain], [{ scan_id: '55555555-5555-4555-8555-555555555555', ...domain, created_at: '2026-09-10T10:00:00Z' }]);
  assert.equal(domainOnly.state, 'NO_STRONG_MATCH');

  const reply = normalizeEntity('reply_to_domain', 'reply-attacker.example');
  const priorScan = '55555555-5555-4555-8555-555555555555';
  const strong = campaignFromMatches(currentScan, [domain, reply], [
    { scan_id: priorScan, ...domain, created_at: '2026-09-10T10:00:00Z' },
    { scan_id: priorScan, ...reply, created_at: '2026-09-10T10:00:00Z' },
  ]);
  assert.equal(strong.state, 'CORRELATED');
  assert.match(strong.campaign_id, /^vt_camp_[a-f0-9]{16}$/u);
  assert.equal(strong.related_scan_count, 1);
});

test('MailGraph entities are privacy-minimized and weighted by forensic durability', () => {
  const entities = buildThreatEntities({
    parsed: { messageId: '<123@mailer.example>' },
    identity: { author: { domain: { ascii: 'brand.example' } }, replyValues: [{ domain: { ascii: 'reply.example' } }], returnValues: [], senderValues: [] },
    authObservations: [{ protocol: 'DKIM', domain: 'sign.example', result: 'PASS' }],
    extractedUrls: [{ url: 'https://login.example/path' }],
    attachments: [{ sha256: 'c'.repeat(64), filename: 'document.pdf' }],
    infrastructure: [{ ip_address: '8.8.4.4', ip_classification: 'public', trust_level: 'trusted_receiver', asn: '15169', host: 'smtp.example' }],
  });
  assert.ok(entities.some((row) => row.entity_type === 'attachment_sha256' && row.weight === 10));
  assert.ok(entities.some((row) => row.entity_type === 'url_domain' && row.weight === 7));
  assert.ok(entities.some((row) => row.entity_type === 'infrastructure_ip_trusted' && row.weight === 6));
  assert.equal(entities.some((row) => String(row.entity_value).includes('@')), false);
});

test('IOC export produces deterministic STIX 2.1 indicators and safe CSV rows', () => {
  const evidence = sampleEvidence();
  const scanId = '66666666-6666-4666-8666-666666666666';
  const iocs = collectIocs(evidence);
  assert.ok(iocs.some((item) => item.type === 'ipv4' && item.value === '8.8.8.8'));
  assert.ok(iocs.some((item) => item.type === 'sha256' && item.value === 'b'.repeat(64)));
  const stixA = toStixBundle(scanId, evidence);
  const stixB = toStixBundle(scanId, evidence);
  assert.deepEqual(stixA, stixB);
  assert.equal(stixA.type, 'bundle');
  assert.ok(stixA.objects.every((item) => item.spec_version === '2.1' && item.pattern_type === 'stix'));
  const csv = toCsv(evidence);
  assert.match(csv, /^type,value,confidence,sources\r?\n/u);
  assert.match(csv, /sha256/u);
});

test('Threat intelligence never makes domain age alone a phishing verdict', () => {
  assert.equal(normalizeDomain('Exämple.com'), 'xn--exmple-cua.com');
  assert.equal(normalizeDomain('localhost'), null);
  assert.equal(deterministicEmailRisk(['DOMAIN_REGISTERED_WITHIN_30_DAYS']), 0);
  assert.ok(deterministicEmailRisk(['DOMAIN_REGISTERED_WITHIN_30_DAYS', 'CREDENTIAL_REQUEST']) >= 0.6);
});

test('All four SIH USP surfaces and release contracts remain wired into the shipped UI/API/schema', () => {
  const fs = require('node:fs');
  const ui = fs.readFileSync(require.resolve('../assets/js/pages/email-investigation.js'), 'utf8');
  const verifierPage = fs.readFileSync(require.resolve('../verify-evidence.html'), 'utf8');
  const migration = fs.readFileSync(require.resolve('../supabase/migrations/20260911_forensic_intelligence.sql'), 'utf8');
  const openapi = fs.readFileSync(require.resolve('../openapi/veritrust-email-v2.yaml'), 'utf8');

  for (const marker of ['Evidence acquisition ladder', 'Trust-Boundary GeoTrace', 'MailGraph Campaign Memory', 'Evidence Passport']) {
    assert.match(ui, new RegExp(marker.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'u'));
  }
  assert.match(ui, /\/verify-evidence\?scan_id=/u);
  assert.match(verifierPage, /recognized VeriTrust signing issuer/u);
  assert.match(migration, /create table if not exists public\.email_threat_entities/iu);
  assert.match(migration, /create table if not exists public\.email_evidence_passports/iu);
  assert.match(migration, /alter table public\.email_threat_entities enable row level security/iu);
  assert.match(migration, /trg_veritrust_evidence_passport_immutable/iu);
  assert.match(openapi, /\/api\/v2\/phishing\/verify-evidence:/u);
  assert.match(openapi, /\/api\/v2\/phishing\/export\/\{scan_id\}\/\{format\}:/u);
  assert.match(openapi, /const: phishing-evidence-7/u);
});

test('Threat-intelligence transport rejects insecure and literal-loopback destinations before any provider request', async () => {
  const { safeJsonFetch } = require('../lib/email/threat-intelligence');
  await assert.rejects(() => safeJsonFetch('http://example.com/path'), (error) => error?.code === 'TI_URL_DENIED');
  await assert.rejects(() => safeJsonFetch('https://127.0.0.1/path'), (error) => error?.code === 'TI_DESTINATION_DENIED');
  await assert.rejects(() => safeJsonFetch('https://localhost/path'), (error) => error?.code === 'TI_DESTINATION_DENIED');
});

test('Evidence canonicalization is bounded against pathologically deep verification packages', () => {
  let value = 'leaf';
  for (let index = 0; index < 70; index += 1) value = [value];
  assert.throws(() => canonicalize(value), (error) => error?.code === 'EVIDENCE_CANONICALIZATION_LIMIT');
});

test('Security-sensitive transitive dependencies remain pinned to patched release lines', () => {
  const fs = require('node:fs');
  const packageJson = JSON.parse(fs.readFileSync(require.resolve('../package.json'), 'utf8'));
  const lock = JSON.parse(fs.readFileSync(require.resolve('../package-lock.json'), 'utf8'));
  assert.equal(packageJson.overrides?.undici, '8.10.2');
  assert.equal(packageJson.overrides?.nodemailer, '9.1.1');
  assert.equal(lock.packages?.['node_modules/undici']?.version, '8.10.2');
  assert.equal(lock.packages?.['node_modules/nodemailer']?.version, '9.1.1');
  assert.equal(lock.packages?.['node_modules/mailparser/node_modules/nodemailer'], undefined);
});

