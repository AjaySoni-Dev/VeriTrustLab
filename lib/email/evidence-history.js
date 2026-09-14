const {
  canonicalize,
  hydrateEvidencePassport,
  signedPayloadFromPassport,
  trustedEvidenceKeyIds,
  verifyEvidencePackage,
} = require('./evidence-passport');

function storedPassportFieldsMatch(left, right) {
  if (!left || !right) return false;
  const scalarFields = [
    'passport_id', 'passport_version', 'scan_id', 'artifact_id', 'signature_algorithm', 'key_id',
    'signature', 'evidence_sha256', 'manifest_sha256',
  ];
  if (!scalarFields.every((field) => (left[field] ?? null) === (right[field] ?? null))) return false;
  try {
    return canonicalize(left.public_key_jwk) === canonicalize(right.public_key_jwk)
      && canonicalize(signedPayloadFromPassport(left)) === canonicalize(signedPayloadFromPassport(right));
  } catch {
    return false;
  }
}

function assertStoredPackageIntegrity(passport, evidence) {
  const verification = verifyEvidencePackage({ passport, evidence }, { trustedKeyIds: trustedEvidenceKeyIds() });
  const cryptographicallyIntact = verification.signature_valid === true
    && verification.key_id_valid === true
    && verification.passport_id_valid === true
    && verification.evidence_hash_valid === true
    && verification.manifest_hash_valid === true
    && !verification.errors.some((code) => code !== 'UNTRUSTED_SIGNING_KEY');
  if (!cryptographicallyIntact) {
    const error = new Error('Stored Evidence Passport data failed integrity verification; historical evidence was not repaired or re-signed.');
    error.code = 'EVIDENCE_PASSPORT_STORED_INTEGRITY_ERROR';
    error.verification = verification;
    throw error;
  }
  return verification;
}

function reconstructedIntegrity(passportRow, schemaAvailable) {
  if (passportRow) {
    let metadata = null;
    try {
      const passport = hydrateEvidencePassport(passportRow);
      metadata = {
        passport_id: passport.passport_id,
        passport_version: passport.passport_version,
        issued_at: passport.issued_at,
        key_id: passport.key_id,
        signature_algorithm: passport.signature_algorithm,
        evidence_sha256: passport.evidence_sha256,
        manifest_sha256: passport.manifest_sha256,
      };
    } catch {
      metadata = { passport_id: passportRow.passport_id || null };
    }
    return {
      status: 'RECONSTRUCTED_UNSIGNED',
      signed_package_available: false,
      limitation: 'EVIDENCE_PASSPORT_LEGACY_EXACT_EVIDENCE_UNAVAILABLE',
      original_passport: metadata,
    };
  }
  return {
    status: 'NOT_ORIGINALLY_RECORDED',
    signed_package_available: false,
    limitation: schemaAvailable === false ? 'EVIDENCE_PASSPORT_SCHEMA_NOT_APPLIED' : 'EVIDENCE_PASSPORT_NOT_ORIGINALLY_RECORDED',
    original_passport: null,
  };
}

function resolveHistoricalEvidencePackage({
  orgId,
  scanId,
  artifactId,
  passportRow,
  storedEvidence = null,
  passportSchemaAvailable = true,
}) {
  if (passportRow) {
    if (passportRow.org_id !== orgId || passportRow.scan_id !== scanId || passportRow.artifact_id !== artifactId) {
      const error = new Error('Stored Evidence Passport tenant/scan/artifact relationship is inconsistent.');
      error.code = 'EVIDENCE_PASSPORT_STORED_INTEGRITY_ERROR';
      throw error;
    }
    const passport = hydrateEvidencePassport(passportRow);
    if (passportRow.evidence_payload) {
      const exactEvidence = passportRow.evidence_payload;
      assertStoredPackageIntegrity(passport, exactEvidence);
      return { evidence: { ...exactEvidence, evidence_passport: passport }, evidence_integrity: null };
    }
    if (storedEvidence?.schema_version && storedEvidence?.evidence_passport
      && storedPassportFieldsMatch(passport, storedEvidence.evidence_passport)) {
      assertStoredPackageIntegrity(passport, storedEvidence);
      return { evidence: storedEvidence, evidence_integrity: null };
    }
  }
  return {
    evidence: null,
    evidence_integrity: reconstructedIntegrity(passportRow, passportSchemaAvailable),
  };
}

module.exports = {
  assertStoredPackageIntegrity,
  reconstructedIntegrity,
  resolveHistoricalEvidencePackage,
  storedPassportFieldsMatch,
};
