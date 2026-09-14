const crypto = require('node:crypto');
const { getOptionalEnv, serverConfig } = require('../config');

const PASSPORT_VERSION = 'veritrust-evidence-passport-1';
const SIGNATURE_ALGORITHM = 'Ed25519';
const DERIVED_KEY_CONTEXT = 'veritrust:evidence-passport:ed25519:v1';

function canonicalize(value, depth = 0, state = { nodes: 0 }) {
  state.nodes += 1;
  if (depth > 64 || state.nodes > 50000) {
    throw Object.assign(new Error('Evidence JSON exceeds canonicalization complexity limits.'), { code: 'EVIDENCE_CANONICALIZATION_LIMIT' });
  }
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => canonicalize(item, depth + 1, state)).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key], depth + 1, state)}`).join(',')}}`;
}

function sha256(value) {
  const source = Buffer.isBuffer(value) ? value : Buffer.from(String(value), 'utf8');
  return crypto.createHash('sha256').update(source).digest('hex');
}

function keyFromConfiguredPem() {
  const configured = getOptionalEnv('VERITRUST_EVIDENCE_SIGNING_PRIVATE_KEY', '');
  if (!configured) return null;
  try {
    return crypto.createPrivateKey(configured);
  } catch {
    throw Object.assign(new Error('VERITRUST_EVIDENCE_SIGNING_PRIVATE_KEY is not a valid private key.'), { code: 'EVIDENCE_SIGNING_KEY_INVALID' });
  }
}

function derivedPrivateKey() {
  const secret = serverConfig.gatewayContentHmacKey;
  if (Buffer.byteLength(secret, 'utf8') < 32) {
    throw Object.assign(new Error('VERITRUST_CONTENT_HMAC_KEY must contain at least 32 bytes before it can back evidence signing.'), { code: 'EVIDENCE_SIGNING_SECRET_TOO_SHORT' });
  }
  const seed = crypto.createHmac('sha256', Buffer.from(secret, 'utf8')).update(DERIVED_KEY_CONTEXT).digest();
  // RFC 8410 PKCS#8 wrapper for a 32-byte Ed25519 seed.
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  return crypto.createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
}

function signingKeyPair() {
  const privateKey = keyFromConfiguredPem() || derivedPrivateKey();
  if (privateKey.asymmetricKeyType !== 'ed25519') {
    throw Object.assign(new Error('Evidence signing requires an Ed25519 private key.'), { code: 'EVIDENCE_SIGNING_KEY_TYPE_INVALID' });
  }
  const publicKey = crypto.createPublicKey(privateKey);
  const publicDer = publicKey.export({ format: 'der', type: 'spki' });
  return {
    privateKey,
    publicKey,
    publicJwk: publicKey.export({ format: 'jwk' }),
    keyId: `ed25519:${sha256(publicDer).slice(0, 24)}`,
    keySource: getOptionalEnv('VERITRUST_EVIDENCE_SIGNING_PRIVATE_KEY', '') ? 'dedicated' : 'purpose-derived',
  };
}

function configuredTrustedKeyIds() {
  return String(getOptionalEnv('VERITRUST_EVIDENCE_TRUSTED_KEY_IDS', ''))
    .split(',')
    .map((value) => value.trim())
    .filter((value) => /^ed25519:[a-f0-9]{24}$/u.test(value));
}

function trustedEvidenceKeyIds() {
  return [...new Set([signingKeyPair().keyId, ...configuredTrustedKeyIds()])];
}

function evidenceForDigest(evidence) {
  const copy = { ...(evidence || {}) };
  delete copy.evidence_passport;
  return copy;
}

function passportPayload({ scanId, evidence, decision = null }) {
  const normalizedEvidence = evidenceForDigest(evidence);
  const issuedAt = evidence?.completed_at || evidence?.evidence_manifest?.completed_at || null;
  const decisionSummary = decision ? {
    risk: decision.risk ?? null,
    severity: decision.severity ?? null,
    verdict: decision.verdict ?? null,
    recommendation: decision.recommendation ?? null,
    degraded: Boolean(decision.degraded),
    reason_codes: Array.isArray(decision.reason_codes) ? [...new Set(decision.reason_codes)].sort() : [],
    correlation_version: decision.correlation_version || null,
  } : null;
  const evidenceSha256 = sha256(canonicalize(normalizedEvidence));
  const manifestSha256 = sha256(canonicalize(evidence?.evidence_manifest || {}));
  return {
    passport_version: PASSPORT_VERSION,
    passport_id: `vt_evp_${sha256(`${scanId}:${evidenceSha256}:${manifestSha256}`).slice(0, 24)}`,
    scan_id: scanId || null,
    artifact_id: evidence?.artifact_id || null,
    evidence_schema: evidence?.schema_version || null,
    input_mode: evidence?.input_mode || null,
    issued_at: issuedAt,
    evidence_sha256: evidenceSha256,
    manifest_sha256: manifestSha256,
    decision: decisionSummary,
    statement: 'This signature verifies the integrity of the packaged VeriTrust evidence. It does not identify a person, guarantee message safety, or independently establish legal admissibility.',
  };
}

function createEvidencePassport({ scanId, evidence, decision = null }) {
  const payload = passportPayload({ scanId, evidence, decision });
  const keys = signingKeyPair();
  const signature = crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), keys.privateKey);
  return {
    ...payload,
    signature_algorithm: SIGNATURE_ALGORITHM,
    key_id: keys.keyId,
    key_source: keys.keySource,
    public_key_jwk: keys.publicJwk,
    signature: signature.toString('base64url'),
  };
}

function verifyEvidencePackage(input, options = {}) {
  const passport = input?.passport;
  if (!passport || typeof passport !== 'object' || Array.isArray(passport)) {
    return { valid: false, signature_valid: false, evidence_hash_valid: false, manifest_hash_valid: false, key_id_valid: false, errors: ['PASSPORT_REQUIRED'] };
  }
  const errors = [];
  if (passport.signature_algorithm !== SIGNATURE_ALGORITHM) errors.push('UNSUPPORTED_SIGNATURE_ALGORITHM');
  if (passport.passport_version !== PASSPORT_VERSION) errors.push('UNSUPPORTED_PASSPORT_VERSION');
  if (!passport.public_key_jwk || passport.public_key_jwk.kty !== 'OKP' || passport.public_key_jwk.crv !== 'Ed25519') errors.push('PUBLIC_KEY_INVALID');
  if (!passport.signature) errors.push('SIGNATURE_REQUIRED');
  const trustedKeyIds = Array.isArray(options.trustedKeyIds) ? options.trustedKeyIds : [];
  const issuerTrusted = trustedKeyIds.length ? trustedKeyIds.includes(passport.key_id) : null;
  if (options.requireTrustedIssuer && issuerTrusted !== true) errors.push('UNTRUSTED_SIGNING_KEY');

  const signedFields = { ...passport };
  delete signedFields.signature_algorithm;
  delete signedFields.key_id;
  delete signedFields.key_source;
  delete signedFields.public_key_jwk;
  delete signedFields.signature;

  let signatureValid = false;
  let keyIdValid = false;
  if (!errors.includes('PUBLIC_KEY_INVALID') && !errors.includes('SIGNATURE_REQUIRED') && !errors.includes('UNSUPPORTED_SIGNATURE_ALGORITHM')) {
    try {
      const publicKey = crypto.createPublicKey({ key: passport.public_key_jwk, format: 'jwk' });
      signatureValid = crypto.verify(null, Buffer.from(canonicalize(signedFields), 'utf8'), publicKey, Buffer.from(passport.signature, 'base64url'));
      if (!signatureValid) errors.push('SIGNATURE_INVALID');
      const publicDer = publicKey.export({ format: 'der', type: 'spki' });
      const expectedKeyId = `ed25519:${sha256(publicDer).slice(0, 24)}`;
      keyIdValid = passport.key_id === expectedKeyId;
      if (!keyIdValid) errors.push('KEY_ID_MISMATCH');
    } catch (error) {
      errors.push(error?.code === 'EVIDENCE_CANONICALIZATION_LIMIT' ? error.code : 'SIGNATURE_VERIFICATION_FAILED');
    }
  }

  let evidenceHashValid = null;
  let manifestHashValid = null;
  if (input?.evidence && typeof input.evidence === 'object' && !Array.isArray(input.evidence)) {
    try {
      const normalizedEvidence = evidenceForDigest(input.evidence);
      evidenceHashValid = sha256(canonicalize(normalizedEvidence)) === passport.evidence_sha256;
      manifestHashValid = sha256(canonicalize(input.evidence.evidence_manifest || {})) === passport.manifest_sha256;
      if (!evidenceHashValid) errors.push('EVIDENCE_HASH_MISMATCH');
      if (!manifestHashValid) errors.push('MANIFEST_HASH_MISMATCH');
    } catch (error) {
      evidenceHashValid = false;
      manifestHashValid = false;
      errors.push(error?.code === 'EVIDENCE_CANONICALIZATION_LIMIT' ? error.code : 'EVIDENCE_HASH_FAILED');
    }
  }

  return {
    valid: signatureValid && keyIdValid && (!options.requireTrustedIssuer || issuerTrusted === true) && evidenceHashValid !== false && manifestHashValid !== false && errors.length === 0,
    signature_valid: signatureValid,
    evidence_hash_valid: evidenceHashValid,
    manifest_hash_valid: manifestHashValid,
    key_id_valid: keyIdValid,
    issuer_trusted: issuerTrusted,
    passport_id: passport.passport_id || null,
    key_id: passport.key_id || null,
    signature_algorithm: passport.signature_algorithm || null,
    errors: [...new Set(errors)],
  };
}

module.exports = {
  PASSPORT_VERSION,
  SIGNATURE_ALGORITHM,
  canonicalize,
  createEvidencePassport,
  evidenceForDigest,
  passportPayload,
  sha256,
  signingKeyPair,
  trustedEvidenceKeyIds,
  verifyEvidencePackage,
};
