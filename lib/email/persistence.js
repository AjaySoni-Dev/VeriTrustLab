const { eq, supabaseFetch } = require('../supabase-server');
const { MAX_EVIDENCE_PACKAGE_BYTES, canonicalize, evidenceForDigest, signedPayloadFromPassport } = require('./evidence-passport');

async function updateEmailArtifactStorage(orgId, scanId, artifactId, values) {
  const rows = await supabaseFetch(`/rest/v1/gateway_artifacts?id=eq.${eq(artifactId)}&scan_id=eq.${eq(scanId)}&org_id=eq.${eq(orgId)}&select=*`, {
    method: 'PATCH',
    service: true,
    body: values,
    headers: { Prefer: 'return=representation' },
  });
  return rows?.[0] || null;
}

async function createChildArtifacts(orgId, scanId, parentArtifactId, children) {
  if (!children.length) return [];
  const existing = await supabaseFetch(`/rest/v1/gateway_artifacts?scan_id=eq.${eq(scanId)}&org_id=eq.${eq(orgId)}&parent_artifact_id=eq.${eq(parentArtifactId)}&select=*&order=ordinal.asc`, { service: true });
  if (existing?.length) return existing;
  return supabaseFetch('/rest/v1/gateway_artifacts?select=*', {
    method: 'POST',
    service: true,
    body: children.map((child) => ({
      org_id: orgId,
      scan_id: scanId,
      parent_artifact_id: parentArtifactId,
      ordinal: child.ordinal,
      artifact_type: child.type,
      status: 'ready',
      content_hmac: child.content_hmac,
      mime_type: child.mime_type,
      size_bytes: child.size_bytes,
      retention: 'metadata_only',
      retention_until: null,
      metadata: child.metadata || {},
    })),
    headers: { Prefer: 'return=representation' },
  });
}

async function persistEmailDetails(orgId, scanId, artifactId, parsed, identity, urlCount, extraMetadata = {}) {
  const author = identity.author;
  const reply = identity.replyValues.length === 1 ? identity.replyValues[0] : null;
  const returnPath = identity.returnValues.length === 1 ? identity.returnValues[0] : null;
  const sender = identity.senderValues.length === 1 ? identity.senderValues[0] : null;
  const body = {
    org_id: orgId,
    scan_id: scanId,
    artifact_id: artifactId,
    message_id: parsed.messageId,
    subject_hash: parsed.subjectHash,
    from_address: author?.address || null,
    from_domain: author?.domain?.ascii || null,
    reply_to_address: reply?.address || null,
    reply_to_domain: reply?.domain?.ascii || null,
    return_path: returnPath?.address || null,
    return_path_domain: returnPath?.domain?.ascii || null,
    sender_address: sender?.address || null,
    sender_domain: sender?.domain?.ascii || null,
    message_date: parsed.date,
    received_header_count: parsed.headerLines.filter((row) => String(row.key || '').toLowerCase() === 'received').length,
    mime_part_count: parsed.mimePartCount,
    attachment_count: parsed.attachments.length,
    url_count: urlCount,
    parser_version: parsed.parserVersion,
    parse_state: parsed.parseState,
    body_text_hash: parsed.bodyTextHash,
    body_html_hash: parsed.bodyHtmlHash,
    header_bytes: parsed.headerBytes,
    decoded_bytes: parsed.decodedBytes,
    limitations: [...new Set([...parsed.limitations, ...identity.limitations])],
    metadata: {
      raw_sha256: parsed.rawSha256,
      raw_bytes: parsed.rawBytes,
      mime_depth_estimate: parsed.mimeDepthEstimate,
      from_count: identity.fromValues.length,
      reply_to_count: identity.replyValues.length,
      display_names: {
        from: author?.name || null,
        reply_to: reply?.name || null,
        return_path: returnPath?.name || null,
        sender: sender?.name || null,
      },
      psl_version: author?.domain?.psl_version || null,
      raw_body_persisted_in_table: false,
      ...extraMetadata,
    },
  };
  const rows = await supabaseFetch('/rest/v1/email_artifact_details?on_conflict=artifact_id&select=*', {
    method: 'POST', service: true, body, headers: { Prefer: 'resolution=ignore-duplicates,return=representation' },
  });
  return rows?.[0] || null;
}

async function persistAuthObservations(orgId, scanId, artifactId, observations) {
  if (!observations.length) return [];
  return supabaseFetch('/rest/v1/email_auth_observations?select=*', {
    method: 'POST', service: true,
    body: observations.map((item) => ({ org_id: orgId, scan_id: scanId, artifact_id: artifactId, ...item })),
    headers: { Prefer: 'return=representation' },
  });
}

async function persistIdentityEdges(orgId, scanId, artifactId, edges) {
  if (!edges.length) return [];
  return supabaseFetch('/rest/v1/email_identity_edges?on_conflict=artifact_id,producer_version,edge_type,source_type,source_value,target_type,target_value,evidence_source&select=*', {
    method: 'POST', service: true,
    body: edges.map((item) => ({ org_id: orgId, scan_id: scanId, artifact_id: artifactId, ...item })),
    headers: { Prefer: 'resolution=ignore-duplicates,return=representation' },
  });
}

async function persistInfrastructure(orgId, scanId, artifactId, hops) {
  if (!hops.length) return [];
  return supabaseFetch('/rest/v1/email_infrastructure_hops?on_conflict=artifact_id,hop_index,received_header_hash&select=*', {
    method: 'POST', service: true,
    body: hops.map((item) => ({ org_id: orgId, scan_id: scanId, artifact_id: artifactId, ...item })),
    headers: { Prefer: 'resolution=ignore-duplicates,return=representation' },
  });
}


function isOptionalSchemaMissing(error) {
  const status = Number(error?.status || 0);
  const text = `${error?.message || ''} ${JSON.stringify(error?.details || '')}`.toLowerCase();
  return status === 404 || text.includes('does not exist') || text.includes('schema cache') || text.includes('pgrst205') || text.includes('42p01');
}

async function persistThreatEntities(orgId, scanId, artifactId, entities) {
  if (!entities.length) return { available: true, rows: [] };
  try {
    const rows = await supabaseFetch('/rest/v1/email_threat_entities?on_conflict=org_id,scan_id,entity_type,value_hash&select=*', {
      method: 'POST', service: true,
      body: entities.map((item) => ({ org_id: orgId, scan_id: scanId, artifact_id: artifactId, ...item })),
      headers: { Prefer: 'resolution=merge-duplicates,return=representation' },
    });
    return { available: true, rows: rows || [] };
  } catch (error) {
    if (isOptionalSchemaMissing(error)) return { available: false, rows: [], limitation: 'CAMPAIGN_MEMORY_SCHEMA_NOT_APPLIED' };
    throw error;
  }
}

async function matchingThreatEntities(orgId, scanId, entities) {
  const hashes = [...new Set((entities || []).map((item) => item.value_hash).filter((value) => /^[a-f0-9]{64}$/u.test(value)))];
  if (!hashes.length) return { available: true, rows: [] };
  try {
    const rows = await supabaseFetch(`/rest/v1/email_threat_entities?org_id=eq.${eq(orgId)}&scan_id=neq.${eq(scanId)}&value_hash=in.(${hashes.join(',')})&select=scan_id,entity_type,entity_value,value_hash,weight,trust_level,created_at&order=created_at.desc&limit=500`, { service: true });
    return { available: true, rows: rows || [] };
  } catch (error) {
    if (isOptionalSchemaMissing(error)) return { available: false, rows: [], limitation: 'CAMPAIGN_MEMORY_SCHEMA_NOT_APPLIED' };
    throw error;
  }
}

function evidencePassportRow(orgId, scanId, artifactId, passport, evidencePayload) {
  if (!passport) return null;
  const exactEvidence = evidenceForDigest(evidencePayload);
  const serialized = Buffer.from(canonicalize(exactEvidence), 'utf8');
  if (serialized.length > MAX_EVIDENCE_PACKAGE_BYTES) {
    const error = new Error(`Signed evidence exceeds the ${MAX_EVIDENCE_PACKAGE_BYTES}-byte Evidence Passport persistence limit.`);
    error.code = 'EVIDENCE_PASSPORT_PAYLOAD_TOO_LARGE';
    throw error;
  }
  return {
    org_id: orgId,
    scan_id: scanId,
    artifact_id: artifactId,
    passport_id: passport.passport_id,
    passport_version: passport.passport_version,
    signature_algorithm: passport.signature_algorithm,
    key_id: passport.key_id,
    public_key_jwk: passport.public_key_jwk,
    signature: passport.signature,
    evidence_sha256: passport.evidence_sha256,
    manifest_sha256: passport.manifest_sha256,
    issued_at: passport.issued_at,
    payload: signedPayloadFromPassport(passport),
    evidence_payload: exactEvidence,
  };
}

const PASSPORT_AUTHORITATIVE_FIELDS = Object.freeze([
  'org_id', 'scan_id', 'artifact_id', 'passport_id', 'passport_version', 'signature_algorithm', 'key_id',
  'public_key_jwk', 'signature', 'evidence_sha256', 'manifest_sha256', 'issued_at', 'payload', 'evidence_payload',
]);

function evidencePassportRowsEqual(left, right) {
  if (!left || !right) return false;
  return PASSPORT_AUTHORITATIVE_FIELDS.every((field) => {
    const a = left[field] ?? null;
    const b = right[field] ?? null;
    if (field === 'issued_at') {
      if (a === null || b === null) return a === b;
      const aTime = Date.parse(a);
      const bTime = Date.parse(b);
      return Number.isFinite(aTime) && Number.isFinite(bTime) && aTime === bTime;
    }
    if (a && typeof a === 'object') return canonicalize(a) === canonicalize(b);
    return a === b;
  });
}

function passportConflict(scanId) {
  const error = new Error(`A different Evidence Passport already exists for scan ${scanId}. Issued Passports are never overwritten.`);
  error.code = 'EVIDENCE_PASSPORT_CONFLICT';
  return error;
}

async function readEvidencePassport(orgId, scanId, options = {}) {
  const fetcher = options.fetcher || supabaseFetch;
  try {
    const rows = await fetcher(`/rest/v1/email_evidence_passports?org_id=eq.${eq(orgId)}&scan_id=eq.${eq(scanId)}&select=*&limit=1`, { service: true });
    return { available: true, row: rows?.[0] || null };
  } catch (error) {
    if (isOptionalSchemaMissing(error)) return { available: false, row: null, limitation: 'EVIDENCE_PASSPORT_SCHEMA_NOT_APPLIED' };
    throw error;
  }
}

async function persistEvidencePassport(orgId, scanId, artifactId, passport, evidencePayload, options = {}) {
  if (!passport) return { available: true, row: null, replayed: false };
  const fetcher = options.fetcher || supabaseFetch;
  const expected = evidencePassportRow(orgId, scanId, artifactId, passport, evidencePayload);
  const existing = await readEvidencePassport(orgId, scanId, { fetcher });
  if (existing.available === false) return existing;
  if (existing.row) {
    if (evidencePassportRowsEqual(existing.row, expected)) return { available: true, row: existing.row, replayed: true };
    throw passportConflict(scanId);
  }

  try {
    const rows = await fetcher('/rest/v1/email_evidence_passports?select=*', {
      method: 'POST',
      service: true,
      body: expected,
      headers: { Prefer: 'return=representation' },
    });
    const row = rows?.[0] || null;
    if (row && evidencePassportRowsEqual(row, expected)) return { available: true, row, replayed: false };
    if (row) throw passportConflict(scanId);
    // A proxy can occasionally suppress a representation. Prove the write before accepting it.
    const committed = await readEvidencePassport(orgId, scanId, { fetcher });
    if (committed.row && evidencePassportRowsEqual(committed.row, expected)) return { available: true, row: committed.row, replayed: false };
    if (committed.row) throw passportConflict(scanId);
    const error = new Error('Evidence Passport insert returned without a provable committed row.');
    error.code = 'EVIDENCE_PASSPORT_COMMIT_UNCONFIRMED';
    throw error;
  } catch (error) {
    if (isOptionalSchemaMissing(error)) return { available: false, row: null, limitation: 'EVIDENCE_PASSPORT_SCHEMA_NOT_APPLIED' };
    if (error?.code === 'EVIDENCE_PASSPORT_CONFLICT') throw error;
    // A timeout/connection failure can be ambiguous. Read back by the scan key before retrying or failing.
    try {
      const committed = await readEvidencePassport(orgId, scanId, { fetcher });
      if (committed.row && evidencePassportRowsEqual(committed.row, expected)) return { available: true, row: committed.row, replayed: true, recovered_after_ambiguous_insert: true };
      if (committed.row) throw passportConflict(scanId);
    } catch (readError) {
      if (readError?.code === 'EVIDENCE_PASSPORT_CONFLICT') throw readError;
    }
    throw error;
  }
}

async function emailRecordsForScan(orgId, scanId) {
  const filter = `scan_id=eq.${eq(scanId)}&org_id=eq.${eq(orgId)}`;
  const [details, auth, edges, infrastructure, passport] = await Promise.all([
    supabaseFetch(`/rest/v1/email_artifact_details?${filter}&select=*&limit=1`, { service: true }),
    supabaseFetch(`/rest/v1/email_auth_observations?${filter}&select=*&order=created_at.asc`, { service: true }),
    supabaseFetch(`/rest/v1/email_identity_edges?${filter}&select=*&order=created_at.asc`, { service: true }),
    supabaseFetch(`/rest/v1/email_infrastructure_hops?${filter}&select=*&order=hop_index.asc`, { service: true }),
    readEvidencePassport(orgId, scanId),
  ]);
  return { details: details?.[0] || null, auth: auth || [], edges: edges || [], infrastructure: infrastructure || [], passport: passport?.row || null, passport_schema_available: passport?.available !== false };
}

module.exports = {
  createChildArtifacts,
  isOptionalSchemaMissing,
  matchingThreatEntities,
  evidencePassportRow,
  evidencePassportRowsEqual,
  persistEvidencePassport,
  persistThreatEntities,
  readEvidencePassport,
  emailRecordsForScan,
  persistAuthObservations,
  persistEmailDetails,
  persistIdentityEdges,
  persistInfrastructure,
  updateEmailArtifactStorage,
};
