const crypto = require('node:crypto');
const { getOptionalEnv, serverConfig } = require('../config');

const PASSPORT_VERSION = 'veritrust-evidence-passport-1';
const SIGNATURE_ALGORITHM = 'Ed25519';
const DERIVED_KEY_CONTEXT = 'veritrust:evidence-passport:ed25519:v1';
const MAX_CANONICAL_DEPTH = 64;
const MAX_CANONICAL_NODES = 50000;
const MAX_EVIDENCE_PACKAGE_BYTES = 1024 * 1024;
const PASSPORT_ID_RE = /^vt_evp_[a-f0-9]{24}$/u;
const KEY_ID_RE = /^ed25519:[a-f0-9]{24}$/u;
const SHA256_RE = /^[a-f0-9]{64}$/u;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const STRICT_BASE64URL_RE = /^[A-Za-z0-9_-]+$/u;
const PUBLIC_JWK_KEYS = new Set(['kty', 'crv', 'x']);
const SIGNED_PAYLOAD_KEYS = Object.freeze([
  'passport_version',
  'passport_id',
  'scan_id',
  'artifact_id',
  'evidence_schema',
  'input_mode',
  'issued_at',
  'evidence_sha256',
  'manifest_sha256',
  'decision',
  'statement',
]);
const ENVELOPE_KEYS = new Set([...SIGNED_PAYLOAD_KEYS, 'signature_algorithm', 'key_id', 'key_source', 'public_key_jwk', 'signature']);
const VERIFICATION_SCOPES = Object.freeze({ FULL_PACKAGE: 'FULL_PACKAGE', PASSPORT_ONLY: 'PASSPORT_ONLY' });
const VERIFICATION_STATUS = Object.freeze({
  VERIFIED: 'VERIFIED',
  CRYPTOGRAPHICALLY_VALID_ISSUER_UNKNOWN: 'CRYPTOGRAPHICALLY_VALID_ISSUER_UNKNOWN',
  PASSPORT_SIGNATURE_VERIFIED_EVIDENCE_NOT_CHECKED: 'PASSPORT_SIGNATURE_VERIFIED_EVIDENCE_NOT_CHECKED',
  UNTRUSTED_ISSUER: 'UNTRUSTED_ISSUER',
  VERIFICATION_FAILED: 'VERIFICATION_FAILED',
});
const PASSPORT_STATEMENT = 'This signature verifies the integrity of the packaged VeriTrust evidence. It does not identify a person, guarantee message safety, or independently establish legal admissibility.';

let signingKeyCache = null;

function evidenceError(code, message, extra = {}) {
  return Object.assign(new Error(message), { code, ...extra });
}

function assertJsonDomain(value, depth = 0, state = { nodes: 0, seen: new Set() }) {
  state.nodes += 1;
  if (depth > MAX_CANONICAL_DEPTH || state.nodes > MAX_CANONICAL_NODES) {
    throw evidenceError('EVIDENCE_CANONICALIZATION_LIMIT', 'Evidence JSON exceeds canonicalization complexity limits.');
  }
  if (value === null) return;
  const type = typeof value;
  if (type === 'string' || type === 'boolean') return;
  if (type === 'number') {
    if (!Number.isFinite(value)) throw evidenceError('EVIDENCE_JSON_DOMAIN_INVALID', 'Evidence JSON contains a non-finite number.');
    return;
  }
  if (type !== 'object') throw evidenceError('EVIDENCE_JSON_DOMAIN_INVALID', `Evidence JSON contains unsupported ${type} data.`);
  if (state.seen.has(value)) throw evidenceError('EVIDENCE_JSON_CYCLE', 'Evidence JSON contains a cycle.');
  state.seen.add(value);
  try {
    if (Array.isArray(value)) {
      for (const item of value) assertJsonDomain(item, depth + 1, state);
      return;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw evidenceError('EVIDENCE_JSON_DOMAIN_INVALID', 'Evidence JSON contains a non-plain object.');
    }
    for (const key of Object.keys(value)) {
      if (typeof value[key] === 'undefined') throw evidenceError('EVIDENCE_JSON_DOMAIN_INVALID', `Evidence JSON field ${key} is undefined.`);
      assertJsonDomain(value[key], depth + 1, state);
    }
  } finally {
    state.seen.delete(value);
  }
}

function canonicalize(value) {
  assertJsonDomain(value);
  const walk = (item) => {
    if (item === null || typeof item !== 'object') return JSON.stringify(item);
    if (Array.isArray(item)) return `[${item.map((entry) => walk(entry)).join(',')}]`;
    return `{${Object.keys(item).sort().map((key) => `${JSON.stringify(key)}:${walk(item[key])}`).join(',')}}`;
  };
  return walk(value);
}

function sha256(value) {
  const source = Buffer.isBuffer(value) ? value : Buffer.from(String(value), 'utf8');
  return crypto.createHash('sha256').update(source).digest('hex');
}

function isProductionLike() {
  return String(process.env.NODE_ENV || '').toLowerCase() === 'production'
    || String(process.env.VERCEL_ENV || '').toLowerCase() === 'production';
}

function keyFromConfiguredPem(configured) {
  if (!configured) return null;
  try {
    return crypto.createPrivateKey(configured);
  } catch {
    throw evidenceError('EVIDENCE_SIGNING_KEY_INVALID', 'VERITRUST_EVIDENCE_SIGNING_PRIVATE_KEY is not a valid private key.');
  }
}

function derivedPrivateKey(secret) {
  if (Buffer.byteLength(secret, 'utf8') < 32) {
    throw evidenceError('EVIDENCE_SIGNING_SECRET_TOO_SHORT', 'VERITRUST_CONTENT_HMAC_KEY must contain at least 32 bytes before it can back development evidence signing.');
  }
  const seed = crypto.createHmac('sha256', Buffer.from(secret, 'utf8')).update(DERIVED_KEY_CONTEXT).digest();
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  return crypto.createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
}

function signingKeyPair() {
  const configured = getOptionalEnv('VERITRUST_EVIDENCE_SIGNING_PRIVATE_KEY', '');
  if (!configured && isProductionLike()) {
    throw evidenceError('EVIDENCE_SIGNING_KEY_REQUIRED', 'Production Evidence Passport signing requires VERITRUST_EVIDENCE_SIGNING_PRIVATE_KEY.');
  }
  const fallbackSecret = configured ? '' : serverConfig.gatewayContentHmacKey;
  const cacheKey = sha256(`${configured ? 'dedicated' : 'purpose-derived'}\u0000${configured || fallbackSecret}`);
  if (signingKeyCache?.cacheKey === cacheKey) return signingKeyCache.value;
  const privateKey = keyFromConfiguredPem(configured) || derivedPrivateKey(fallbackSecret);
  if (privateKey.asymmetricKeyType !== 'ed25519') {
    throw evidenceError('EVIDENCE_SIGNING_KEY_TYPE_INVALID', 'Evidence signing requires an Ed25519 private key.');
  }
  const publicKey = crypto.createPublicKey(privateKey);
  const publicDer = publicKey.export({ format: 'der', type: 'spki' });
  const publicJwk = publicKey.export({ format: 'jwk' });
  const value = Object.freeze({
    privateKey,
    publicKey,
    publicJwk: Object.freeze({ kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x }),
    keyId: `ed25519:${sha256(publicDer).slice(0, 24)}`,
    keySource: configured ? 'dedicated' : 'purpose-derived',
  });
  signingKeyCache = { cacheKey, value };
  return value;
}

function configuredTrustedKeyIds() {
  return String(getOptionalEnv('VERITRUST_EVIDENCE_TRUSTED_KEY_IDS', ''))
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean)
    .filter((value) => KEY_ID_RE.test(value));
}

function trustedEvidenceKeyIds() {
  const active = signingKeyPair().keyId;
  return [...new Set([active, ...configuredTrustedKeyIds()])];
}

function evidenceTrustMetadata() {
  const keys = signingKeyPair();
  return {
    schema_version: 'veritrust-evidence-trust-1',
    supported_passport_versions: [PASSPORT_VERSION],
    active_key_id: keys.keyId,
    trusted_key_ids: trustedEvidenceKeyIds(),
  };
}

function evidenceForDigest(evidence) {
  if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)) return {};
  const copy = { ...evidence };
  delete copy.evidence_passport;
  return copy;
}

function computePassportId(scanId, evidenceSha256, manifestSha256) {
  return `vt_evp_${sha256(`${scanId || ''}:${evidenceSha256}:${manifestSha256}`).slice(0, 24)}`;
}

function decisionSummary(decision) {
  if (!decision) return null;
  return {
    risk: decision.risk ?? null,
    severity: decision.severity ?? null,
    verdict: decision.verdict ?? null,
    recommendation: decision.recommendation ?? null,
    degraded: Boolean(decision.degraded),
    reason_codes: Array.isArray(decision.reason_codes) ? [...new Set(decision.reason_codes)].sort() : [],
    correlation_version: decision.correlation_version || null,
  };
}

function passportPayload({ scanId, evidence, decision = null }) {
  const normalizedEvidence = evidenceForDigest(evidence);
  assertJsonDomain(normalizedEvidence);
  const manifest = evidence?.evidence_manifest || {};
  assertJsonDomain(manifest);
  const issuedAt = evidence?.completed_at || evidence?.evidence_manifest?.completed_at || null;
  const evidenceSha256 = sha256(canonicalize(normalizedEvidence));
  const manifestSha256 = sha256(canonicalize(manifest));
  const payload = {
    passport_version: PASSPORT_VERSION,
    passport_id: computePassportId(scanId || null, evidenceSha256, manifestSha256),
    scan_id: scanId || null,
    artifact_id: evidence?.artifact_id || null,
    evidence_schema: evidence?.schema_version || null,
    input_mode: evidence?.input_mode || null,
    issued_at: issuedAt,
    evidence_sha256: evidenceSha256,
    manifest_sha256: manifestSha256,
    decision: decisionSummary(decision),
    statement: PASSPORT_STATEMENT,
  };
  assertJsonDomain(payload);
  return payload;
}

function signedPayloadFromPassport(passport) {
  return Object.fromEntries(SIGNED_PAYLOAD_KEYS.map((key) => [key, passport?.[key]]));
}

function createEvidencePassport({ scanId, evidence, decision = null }) {
  const payload = passportPayload({ scanId, evidence, decision });
  const keys = signingKeyPair();
  const signature = crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), keys.privateKey);
  return {
    ...payload,
    signature_algorithm: SIGNATURE_ALGORITHM,
    key_id: keys.keyId,
    public_key_jwk: keys.publicJwk,
    signature: signature.toString('base64url'),
  };
}

function strictBase64urlBytes(value, expectedBytes, fieldCode) {
  if (typeof value !== 'string' || !value || value.includes('=') || !STRICT_BASE64URL_RE.test(value)) {
    throw evidenceError(fieldCode, 'Value is not strict unpadded base64url.');
  }
  const expectedLength = Math.ceil((expectedBytes * 8) / 6);
  if (value.length !== expectedLength) throw evidenceError(fieldCode, `Value must encode exactly ${expectedBytes} bytes.`);
  let decoded;
  try { decoded = Buffer.from(value, 'base64url'); } catch { throw evidenceError(fieldCode, 'Value is not valid base64url.'); }
  if (decoded.length !== expectedBytes || decoded.toString('base64url') !== value) throw evidenceError(fieldCode, `Value must encode exactly ${expectedBytes} bytes.`);
  return decoded;
}

function validateNullableUuid(value, field, errors) {
  if (value === null) return;
  if (typeof value !== 'string' || !UUID_RE.test(value)) errors.push(`${field.toUpperCase()}_INVALID`);
}

function validateNullableBoundedString(value, field, errors, max = 128) {
  if (value === null) return;
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') > max) errors.push(`${field.toUpperCase()}_INVALID`);
}

function validateTimestamp(value, errors) {
  if (value === null) return;
  if (typeof value !== 'string' || value.length > 64 || !Number.isFinite(Date.parse(value))) errors.push('ISSUED_AT_INVALID');
}

function validatePassportV1(passport) {
  const errors = [];
  if (!passport || typeof passport !== 'object' || Array.isArray(passport)) return { errors: ['PASSPORT_REQUIRED'], signedPayload: null };
  try { assertJsonDomain(passport); } catch (error) { errors.push(error.code || 'PASSPORT_JSON_INVALID'); }
  for (const key of Object.keys(passport)) if (!ENVELOPE_KEYS.has(key)) errors.push('PASSPORT_UNKNOWN_FIELD');
  for (const key of SIGNED_PAYLOAD_KEYS) if (!Object.hasOwn(passport, key)) errors.push(`PASSPORT_FIELD_MISSING_${key.toUpperCase()}`);
  if (passport.passport_version !== PASSPORT_VERSION) errors.push('UNSUPPORTED_PASSPORT_VERSION');
  if (passport.signature_algorithm !== SIGNATURE_ALGORITHM) errors.push('UNSUPPORTED_SIGNATURE_ALGORITHM');
  if (typeof passport.passport_id !== 'string' || !PASSPORT_ID_RE.test(passport.passport_id)) errors.push('PASSPORT_ID_INVALID');
  if (typeof passport.evidence_sha256 !== 'string' || !SHA256_RE.test(passport.evidence_sha256)) errors.push('EVIDENCE_DIGEST_INVALID');
  if (typeof passport.manifest_sha256 !== 'string' || !SHA256_RE.test(passport.manifest_sha256)) errors.push('MANIFEST_DIGEST_INVALID');
  if (typeof passport.key_id !== 'string' || !KEY_ID_RE.test(passport.key_id)) errors.push('KEY_ID_INVALID');
  validateNullableUuid(passport.scan_id, 'scan_id', errors);
  validateNullableUuid(passport.artifact_id, 'artifact_id', errors);
  validateNullableBoundedString(passport.evidence_schema, 'evidence_schema', errors);
  validateNullableBoundedString(passport.input_mode, 'input_mode', errors, 64);
  validateTimestamp(passport.issued_at, errors);
  if (typeof passport.statement !== 'string' || !passport.statement || Buffer.byteLength(passport.statement, 'utf8') > 2048) errors.push('STATEMENT_INVALID');
  if (passport.decision !== null && (typeof passport.decision !== 'object' || Array.isArray(passport.decision))) errors.push('DECISION_INVALID');

  const jwk = passport.public_key_jwk;
  if (!jwk || typeof jwk !== 'object' || Array.isArray(jwk)) errors.push('PUBLIC_KEY_INVALID');
  else {
    if (Object.hasOwn(jwk, 'd')) errors.push('PUBLIC_KEY_PRIVATE_MATERIAL');
    if (Object.keys(jwk).some((key) => !PUBLIC_JWK_KEYS.has(key))) errors.push('PUBLIC_KEY_AMBIGUOUS_FIELDS');
    if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') errors.push('PUBLIC_KEY_INVALID');
    try { strictBase64urlBytes(jwk.x, 32, 'PUBLIC_KEY_X_INVALID'); } catch (error) { errors.push(error.code); }
  }
  try { strictBase64urlBytes(passport.signature, 64, 'SIGNATURE_ENCODING_INVALID'); } catch (error) { errors.push(error.code); }

  if (SHA256_RE.test(String(passport.evidence_sha256 || '')) && SHA256_RE.test(String(passport.manifest_sha256 || ''))) {
    const expectedId = computePassportId(passport.scan_id || null, passport.evidence_sha256, passport.manifest_sha256);
    if (passport.passport_id !== expectedId) errors.push('PASSPORT_ID_MISMATCH');
  }
  return { errors: [...new Set(errors)], signedPayload: signedPayloadFromPassport(passport) };
}

function verificationStatus({ structuralErrors, signatureValid, keyIdValid, passportIdValid, issuerTrusted, fullPackage, evidenceHashValid, manifestHashValid }) {
  const cryptoOk = structuralErrors.length === 0 && signatureValid && keyIdValid && passportIdValid;
  if (!cryptoOk || (fullPackage && (evidenceHashValid !== true || manifestHashValid !== true))) return VERIFICATION_STATUS.VERIFICATION_FAILED;
  if (issuerTrusted === false) return VERIFICATION_STATUS.UNTRUSTED_ISSUER;
  if (issuerTrusted === null) return VERIFICATION_STATUS.CRYPTOGRAPHICALLY_VALID_ISSUER_UNKNOWN;
  if (!fullPackage) return VERIFICATION_STATUS.PASSPORT_SIGNATURE_VERIFIED_EVIDENCE_NOT_CHECKED;
  return VERIFICATION_STATUS.VERIFIED;
}

function verifyEvidencePackage(input, options = {}) {
  const passport = input?.passport;
  const fullPackage = Boolean(input?.evidence && typeof input.evidence === 'object' && !Array.isArray(input.evidence));
  const verificationScope = fullPackage ? VERIFICATION_SCOPES.FULL_PACKAGE : VERIFICATION_SCOPES.PASSPORT_ONLY;
  const validation = validatePassportV1(passport);
  const errors = [...validation.errors];
  const warnings = [];
  const trustedKeyIds = Array.isArray(options.trustedKeyIds) ? options.trustedKeyIds.filter((value) => KEY_ID_RE.test(String(value))) : null;
  const issuerTrusted = trustedKeyIds ? trustedKeyIds.includes(passport?.key_id) : null;
  if (issuerTrusted === false) errors.push('UNTRUSTED_SIGNING_KEY');
  if (issuerTrusted === null) warnings.push('ISSUER_TRUST_NOT_CHECKED');

  let signatureValid = false;
  let keyIdValid = false;
  let passportIdValid = false;
  if (passport && validation.signedPayload) {
    passportIdValid = !validation.errors.includes('PASSPORT_ID_INVALID') && !validation.errors.includes('PASSPORT_ID_MISMATCH');
  }
  const cryptoBlocked = validation.errors.some((code) => [
    'UNSUPPORTED_PASSPORT_VERSION', 'UNSUPPORTED_SIGNATURE_ALGORITHM', 'PUBLIC_KEY_INVALID', 'PUBLIC_KEY_PRIVATE_MATERIAL',
    'PUBLIC_KEY_AMBIGUOUS_FIELDS', 'PUBLIC_KEY_X_INVALID', 'SIGNATURE_ENCODING_INVALID', 'EVIDENCE_JSON_DOMAIN_INVALID',
    'EVIDENCE_JSON_CYCLE', 'EVIDENCE_CANONICALIZATION_LIMIT',
  ].includes(code));
  if (passport && validation.signedPayload && !cryptoBlocked) {
    try {
      const publicKey = crypto.createPublicKey({ key: passport.public_key_jwk, format: 'jwk' });
      signatureValid = crypto.verify(null, Buffer.from(canonicalize(validation.signedPayload), 'utf8'), publicKey, strictBase64urlBytes(passport.signature, 64, 'SIGNATURE_ENCODING_INVALID'));
      if (!signatureValid) errors.push('SIGNATURE_INVALID');
      const publicDer = publicKey.export({ format: 'der', type: 'spki' });
      const expectedKeyId = `ed25519:${sha256(publicDer).slice(0, 24)}`;
      keyIdValid = passport.key_id === expectedKeyId;
      if (!keyIdValid) errors.push('KEY_ID_MISMATCH');
    } catch (error) {
      errors.push(error?.code || 'SIGNATURE_VERIFICATION_FAILED');
    }
  }

  let evidenceHashValid = null;
  let manifestHashValid = null;
  if (fullPackage) {
    try {
      const normalizedEvidence = evidenceForDigest(input.evidence);
      evidenceHashValid = sha256(canonicalize(normalizedEvidence)) === passport?.evidence_sha256;
      manifestHashValid = sha256(canonicalize(input.evidence.evidence_manifest || {})) === passport?.manifest_sha256;
      if (!evidenceHashValid) errors.push('EVIDENCE_HASH_MISMATCH');
      if (!manifestHashValid) errors.push('MANIFEST_HASH_MISMATCH');
    } catch (error) {
      evidenceHashValid = false;
      manifestHashValid = false;
      errors.push(error?.code || 'EVIDENCE_HASH_FAILED');
    }
  } else {
    warnings.push('EVIDENCE_NOT_CHECKED');
  }

  const structuralErrors = [...new Set(errors.filter((code) => !['UNTRUSTED_SIGNING_KEY'].includes(code)))];
  const status = verificationStatus({ structuralErrors, signatureValid, keyIdValid, passportIdValid, issuerTrusted, fullPackage, evidenceHashValid, manifestHashValid });
  const valid = status === VERIFICATION_STATUS.VERIFIED;
  return {
    status,
    verification_scope: verificationScope,
    valid,
    signature_valid: signatureValid,
    key_id_valid: keyIdValid,
    passport_id_valid: passportIdValid,
    issuer_trusted: issuerTrusted,
    evidence_integrity_checked: fullPackage,
    manifest_integrity_checked: fullPackage,
    evidence_hash_valid: evidenceHashValid,
    manifest_hash_valid: manifestHashValid,
    passport_id: passport?.passport_id || null,
    key_id: passport?.key_id || null,
    signature_algorithm: passport?.signature_algorithm || null,
    errors: [...new Set(errors)],
    warnings: [...new Set(warnings)],
  };
}

function hydrateEvidencePassport(row) {
  if (!row || typeof row !== 'object' || Array.isArray(row)) throw evidenceError('EVIDENCE_PASSPORT_ROW_INVALID', 'Evidence Passport database row is invalid.');
  if (!row.payload || typeof row.payload !== 'object' || Array.isArray(row.payload)) throw evidenceError('EVIDENCE_PASSPORT_STORED_INTEGRITY_ERROR', 'Stored Evidence Passport signed payload is missing or invalid.');
  const passport = {
    ...row.payload,
    signature_algorithm: row.signature_algorithm,
    key_id: row.key_id,
    public_key_jwk: row.public_key_jwk,
    signature: row.signature,
  };
  const duplicated = {
    passport_id: row.passport_id,
    passport_version: row.passport_version,
    scan_id: row.scan_id,
    artifact_id: row.artifact_id,
    evidence_sha256: row.evidence_sha256,
    manifest_sha256: row.manifest_sha256,
    issued_at: row.issued_at ?? null,
  };
  for (const [field, expected] of Object.entries(duplicated)) {
    const actual = passport[field] ?? null;
    if (field === 'issued_at' && actual !== null && expected !== null) {
      const actualTime = Date.parse(actual);
      const expectedTime = Date.parse(expected);
      if (!Number.isFinite(actualTime) || !Number.isFinite(expectedTime) || actualTime !== expectedTime) {
        throw evidenceError('EVIDENCE_PASSPORT_STORED_INTEGRITY_ERROR', `Stored Evidence Passport ${field} is inconsistent between row and signed payload.`, { field });
      }
      continue;
    }
    if (actual !== (expected ?? null)) throw evidenceError('EVIDENCE_PASSPORT_STORED_INTEGRITY_ERROR', `Stored Evidence Passport ${field} is inconsistent between row and signed payload.`, { field });
  }
  const validation = validatePassportV1(passport);
  if (validation.errors.length) throw evidenceError('EVIDENCE_PASSPORT_STORED_INTEGRITY_ERROR', 'Stored Evidence Passport failed strict validation.', { validationErrors: validation.errors });
  return passport;
}

module.exports = {
  KEY_ID_RE,
  MAX_EVIDENCE_PACKAGE_BYTES,
  PASSPORT_VERSION,
  SIGNATURE_ALGORITHM,
  VERIFICATION_SCOPES,
  VERIFICATION_STATUS,
  assertJsonDomain,
  canonicalize,
  computePassportId,
  createEvidencePassport,
  evidenceForDigest,
  evidenceTrustMetadata,
  hydrateEvidencePassport,
  passportPayload,
  sha256,
  signedPayloadFromPassport,
  signingKeyPair,
  strictBase64urlBytes,
  trustedEvidenceKeyIds,
  validatePassportV1,
  verifyEvidencePackage,
};
