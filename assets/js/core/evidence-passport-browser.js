(function initEvidencePassportBrowser(root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.VeriTrustEvidencePassport = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function evidencePassportBrowserFactory() {
  'use strict';

  const PASSPORT_VERSION = 'veritrust-evidence-passport-1';
  const SIGNATURE_ALGORITHM = 'Ed25519';
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
    'passport_version', 'passport_id', 'scan_id', 'artifact_id', 'evidence_schema', 'input_mode',
    'issued_at', 'evidence_sha256', 'manifest_sha256', 'decision', 'statement',
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
  const SPKI_ED25519_PREFIX = Uint8Array.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);

  function evidenceError(code, message) {
    const error = new Error(message);
    error.code = code;
    return error;
  }

  function utf8(value) { return new TextEncoder().encode(String(value)); }
  function hex(bytes) { return Array.from(new Uint8Array(bytes), (value) => value.toString(16).padStart(2, '0')).join(''); }

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
        value.forEach((item) => assertJsonDomain(item, depth + 1, state));
        return;
      }
      const prototype = Object.getPrototypeOf(value);
      if (prototype !== Object.prototype && prototype !== null) throw evidenceError('EVIDENCE_JSON_DOMAIN_INVALID', 'Evidence JSON contains a non-plain object.');
      Object.keys(value).forEach((key) => {
        if (typeof value[key] === 'undefined') throw evidenceError('EVIDENCE_JSON_DOMAIN_INVALID', `Evidence JSON field ${key} is undefined.`);
        assertJsonDomain(value[key], depth + 1, state);
      });
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

  async function sha256(value) {
    if (!globalThis.crypto?.subtle) throw evidenceError('BROWSER_CRYPTO_UNAVAILABLE', 'Web Crypto is not available in this browser.');
    const bytes = value instanceof Uint8Array ? value : utf8(value);
    return hex(await globalThis.crypto.subtle.digest('SHA-256', bytes));
  }

  function strictBase64urlBytes(value, expectedBytes, fieldCode) {
    if (typeof value !== 'string' || !value || value.includes('=') || !STRICT_BASE64URL_RE.test(value)) {
      throw evidenceError(fieldCode, 'Value is not strict unpadded base64url.');
    }
    const expectedLength = Math.ceil((expectedBytes * 8) / 6);
    if (value.length !== expectedLength) throw evidenceError(fieldCode, `Value must encode exactly ${expectedBytes} bytes.`);
    const padded = `${value.replace(/-/g, '+').replace(/_/g, '/')}${'='.repeat((4 - (value.length % 4)) % 4)}`;
    let binary;
    try { binary = globalThis.atob(padded); } catch { throw evidenceError(fieldCode, 'Value is not valid base64url.'); }
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    if (bytes.length !== expectedBytes) throw evidenceError(fieldCode, `Value must encode exactly ${expectedBytes} bytes.`);
    const roundTrip = globalThis.btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/u, '');
    if (roundTrip !== value) throw evidenceError(fieldCode, 'Value is not canonical base64url.');
    return bytes;
  }

  function evidenceForDigest(evidence) {
    if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)) return {};
    const copy = { ...evidence };
    delete copy.evidence_passport;
    return copy;
  }

  function signedPayloadFromPassport(passport) {
    return Object.fromEntries(SIGNED_PAYLOAD_KEYS.map((key) => [key, passport?.[key]]));
  }

  async function computePassportId(scanId, evidenceSha256, manifestSha256) {
    return `vt_evp_${(await sha256(`${scanId || ''}:${evidenceSha256}:${manifestSha256}`)).slice(0, 24)}`;
  }

  function nullableUuid(value, field, errors) {
    if (value !== null && (typeof value !== 'string' || !UUID_RE.test(value))) errors.push(`${field.toUpperCase()}_INVALID`);
  }

  function nullableBoundedString(value, field, errors, max = 128) {
    if (value !== null && (typeof value !== 'string' || utf8(value).length > max)) errors.push(`${field.toUpperCase()}_INVALID`);
  }

  async function validatePassportV1(passport) {
    const errors = [];
    if (!passport || typeof passport !== 'object' || Array.isArray(passport)) return { errors: ['PASSPORT_REQUIRED'], signedPayload: null };
    try { assertJsonDomain(passport); } catch (error) { errors.push(error.code || 'PASSPORT_JSON_INVALID'); }
    Object.keys(passport).forEach((key) => { if (!ENVELOPE_KEYS.has(key)) errors.push('PASSPORT_UNKNOWN_FIELD'); });
    SIGNED_PAYLOAD_KEYS.forEach((key) => { if (!Object.hasOwn(passport, key)) errors.push(`PASSPORT_FIELD_MISSING_${key.toUpperCase()}`); });
    if (passport.passport_version !== PASSPORT_VERSION) errors.push('UNSUPPORTED_PASSPORT_VERSION');
    if (passport.signature_algorithm !== SIGNATURE_ALGORITHM) errors.push('UNSUPPORTED_SIGNATURE_ALGORITHM');
    if (typeof passport.passport_id !== 'string' || !PASSPORT_ID_RE.test(passport.passport_id)) errors.push('PASSPORT_ID_INVALID');
    if (typeof passport.evidence_sha256 !== 'string' || !SHA256_RE.test(passport.evidence_sha256)) errors.push('EVIDENCE_DIGEST_INVALID');
    if (typeof passport.manifest_sha256 !== 'string' || !SHA256_RE.test(passport.manifest_sha256)) errors.push('MANIFEST_DIGEST_INVALID');
    if (typeof passport.key_id !== 'string' || !KEY_ID_RE.test(passport.key_id)) errors.push('KEY_ID_INVALID');
    nullableUuid(passport.scan_id, 'scan_id', errors);
    nullableUuid(passport.artifact_id, 'artifact_id', errors);
    nullableBoundedString(passport.evidence_schema, 'evidence_schema', errors);
    nullableBoundedString(passport.input_mode, 'input_mode', errors, 64);
    if (passport.issued_at !== null && (typeof passport.issued_at !== 'string' || passport.issued_at.length > 64 || !Number.isFinite(Date.parse(passport.issued_at)))) errors.push('ISSUED_AT_INVALID');
    if (typeof passport.statement !== 'string' || !passport.statement || utf8(passport.statement).length > 2048) errors.push('STATEMENT_INVALID');
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
      const expectedId = await computePassportId(passport.scan_id || null, passport.evidence_sha256, passport.manifest_sha256);
      if (passport.passport_id !== expectedId) errors.push('PASSPORT_ID_MISMATCH');
    }
    return { errors: [...new Set(errors)], signedPayload: signedPayloadFromPassport(passport) };
  }

  async function deriveKeyId(publicJwk) {
    const raw = strictBase64urlBytes(publicJwk.x, 32, 'PUBLIC_KEY_X_INVALID');
    const spki = new Uint8Array(SPKI_ED25519_PREFIX.length + raw.length);
    spki.set(SPKI_ED25519_PREFIX, 0);
    spki.set(raw, SPKI_ED25519_PREFIX.length);
    return `ed25519:${(await sha256(spki)).slice(0, 24)}`;
  }

  function statusFor({ structuralErrors, signatureValid, keyIdValid, passportIdValid, issuerTrusted, fullPackage, evidenceHashValid, manifestHashValid }) {
    const cryptoOk = structuralErrors.length === 0 && signatureValid && keyIdValid && passportIdValid;
    if (!cryptoOk || (fullPackage && (evidenceHashValid !== true || manifestHashValid !== true))) return VERIFICATION_STATUS.VERIFICATION_FAILED;
    if (issuerTrusted === false) return VERIFICATION_STATUS.UNTRUSTED_ISSUER;
    if (issuerTrusted === null) return VERIFICATION_STATUS.CRYPTOGRAPHICALLY_VALID_ISSUER_UNKNOWN;
    if (!fullPackage) return VERIFICATION_STATUS.PASSPORT_SIGNATURE_VERIFIED_EVIDENCE_NOT_CHECKED;
    return VERIFICATION_STATUS.VERIFIED;
  }

  async function verifyEvidencePackage(input, options = {}) {
    const passport = input?.passport;
    const fullPackage = Boolean(input?.evidence && typeof input.evidence === 'object' && !Array.isArray(input.evidence));
    const validation = await validatePassportV1(passport);
    const errors = [...validation.errors];
    const warnings = [];
    const trustedKeyIds = Array.isArray(options.trustedKeyIds) ? options.trustedKeyIds.filter((value) => KEY_ID_RE.test(String(value))) : null;
    const issuerTrusted = trustedKeyIds ? trustedKeyIds.includes(passport?.key_id) : null;
    if (issuerTrusted === false) errors.push('UNTRUSTED_SIGNING_KEY');
    if (issuerTrusted === null) warnings.push('ISSUER_TRUST_NOT_CHECKED');

    let signatureValid = false;
    let keyIdValid = false;
    let passportIdValid = false;
    if (passport && validation.signedPayload) passportIdValid = !validation.errors.includes('PASSPORT_ID_INVALID') && !validation.errors.includes('PASSPORT_ID_MISMATCH');
    const cryptoBlocked = validation.errors.some((code) => [
      'UNSUPPORTED_PASSPORT_VERSION', 'UNSUPPORTED_SIGNATURE_ALGORITHM', 'PUBLIC_KEY_INVALID', 'PUBLIC_KEY_PRIVATE_MATERIAL',
      'PUBLIC_KEY_AMBIGUOUS_FIELDS', 'PUBLIC_KEY_X_INVALID', 'SIGNATURE_ENCODING_INVALID', 'EVIDENCE_JSON_DOMAIN_INVALID',
      'EVIDENCE_JSON_CYCLE', 'EVIDENCE_CANONICALIZATION_LIMIT',
    ].includes(code));

    if (passport && validation.signedPayload && !cryptoBlocked) {
      try {
        if (!globalThis.crypto?.subtle) throw evidenceError('BROWSER_CRYPTO_UNAVAILABLE', 'Web Crypto is unavailable.');
        let publicKey;
        try {
          publicKey = await globalThis.crypto.subtle.importKey('jwk', passport.public_key_jwk, { name: 'Ed25519' }, false, ['verify']);
        } catch (error) {
          if (error?.name === 'NotSupportedError') throw evidenceError('BROWSER_ED25519_UNAVAILABLE', 'This browser does not support Ed25519 verification with Web Crypto.');
          throw error;
        }
        signatureValid = await globalThis.crypto.subtle.verify(
          { name: 'Ed25519' },
          publicKey,
          strictBase64urlBytes(passport.signature, 64, 'SIGNATURE_ENCODING_INVALID'),
          utf8(canonicalize(validation.signedPayload)),
        );
        if (!signatureValid) errors.push('SIGNATURE_INVALID');
        keyIdValid = passport.key_id === await deriveKeyId(passport.public_key_jwk);
        if (!keyIdValid) errors.push('KEY_ID_MISMATCH');
      } catch (error) {
        if (error?.code === 'BROWSER_ED25519_UNAVAILABLE' || error?.code === 'BROWSER_CRYPTO_UNAVAILABLE') throw error;
        errors.push(error?.code || 'SIGNATURE_VERIFICATION_FAILED');
      }
    }

    let evidenceHashValid = null;
    let manifestHashValid = null;
    if (fullPackage) {
      try {
        evidenceHashValid = await sha256(canonicalize(evidenceForDigest(input.evidence))) === passport?.evidence_sha256;
        manifestHashValid = await sha256(canonicalize(input.evidence.evidence_manifest || {})) === passport?.manifest_sha256;
        if (!evidenceHashValid) errors.push('EVIDENCE_HASH_MISMATCH');
        if (!manifestHashValid) errors.push('MANIFEST_HASH_MISMATCH');
      } catch (error) {
        evidenceHashValid = false;
        manifestHashValid = false;
        errors.push(error?.code || 'EVIDENCE_HASH_FAILED');
      }
    } else warnings.push('EVIDENCE_NOT_CHECKED');

    const structuralErrors = [...new Set(errors.filter((code) => code !== 'UNTRUSTED_SIGNING_KEY'))];
    const status = statusFor({ structuralErrors, signatureValid, keyIdValid, passportIdValid, issuerTrusted, fullPackage, evidenceHashValid, manifestHashValid });
    return {
      status,
      verification_scope: fullPackage ? VERIFICATION_SCOPES.FULL_PACKAGE : VERIFICATION_SCOPES.PASSPORT_ONLY,
      valid: status === VERIFICATION_STATUS.VERIFIED,
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

  return {
    MAX_EVIDENCE_PACKAGE_BYTES,
    PASSPORT_VERSION,
    SIGNATURE_ALGORITHM,
    VERIFICATION_SCOPES,
    VERIFICATION_STATUS,
    assertJsonDomain,
    canonicalize,
    computePassportId,
    deriveKeyId,
    evidenceForDigest,
    sha256,
    strictBase64urlBytes,
    validatePassportV1,
    verifyEvidencePackage,
  };
}));
