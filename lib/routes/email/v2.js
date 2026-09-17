const crypto = require('crypto');
const { serverConfig } = require('../../config');
const { validateOptionalUuid, validatePlainTextInput, validateReceiverEvent, validateTrustedReceiverMetadata, MAX_RAW_EML_BYTES } = require('../../email/contracts');
const { analyzeEmail, emailEvidenceReport } = require('../../email/service');
const { trustedEvidenceKeyIds, verifyEvidencePackage } = require('../../email/evidence-passport');
const { toCsv, toStixBundle, collectIocs } = require('../../email/ioc-export');
const { requestIdentifiers, requireIdempotencyKey } = require('../../gateway/idempotency');
const { authenticate, scanReport } = require('../../gateway/persistence');
const { downloadObject } = require('../../gateway/storage');
const { HttpError, parseJsonBody } = require('../../veritrust-api');
const { validateJsonContentType } = require('../../validators');

function header(req, name) {
  const value = req.headers?.[String(name).toLowerCase()];
  return Array.isArray(value) ? value[0] : String(value || '');
}


function parentScanId(req) {
  return validateOptionalUuid(header(req, 'x-veritrust-parent-scan-id'), 'X-VeriTrust-Parent-Scan-Id');
}

function readRawBuffer(req, maxBytes = MAX_RAW_EML_BYTES) {
  if (Buffer.isBuffer(req.body)) {
    if (req.body.length > maxBytes) throw new HttpError(413, 'Raw email exceeds the 10 MiB endpoint limit.', { code: 'UNSUPPORTED_LIMIT' });
    return Promise.resolve(req.body);
  }
  if (typeof req.body === 'string') {
    const value = Buffer.from(req.body, 'utf8');
    if (value.length > maxBytes) throw new HttpError(413, 'Raw email exceeds the 10 MiB endpoint limit.', { code: 'UNSUPPORTED_LIMIT' });
    return Promise.resolve(value);
  }
  return new Promise((resolve, reject) => {
    const chunks = [];
    let bytes = 0;
    let rejected = false;
    req.on('data', (chunk) => {
      if (rejected) return;
      bytes += chunk.length;
      if (bytes > maxBytes) {
        rejected = true;
        reject(new HttpError(413, 'Raw email exceeds the 10 MiB endpoint limit.', { code: 'UNSUPPORTED_LIMIT' }));
        req.resume();
        return;
      }
      chunks.push(Buffer.from(chunk));
    });
    req.on('end', () => { if (!rejected) resolve(Buffer.concat(chunks, bytes)); });
    req.on('error', reject);
  });
}

function requireMessageRfc822(req) {
  const contentType = header(req, 'content-type').split(';')[0].trim().toLowerCase();
  if (contentType !== 'message/rfc822') throw new HttpError(415, 'Use Content-Type: message/rfc822 for raw email analysis.', { code: 'EMAIL_CONTENT_TYPE_REQUIRED' });
  const retention = header(req, 'x-retention-policy').trim().toLowerCase();
  if (retention && !['ephemeral_24h', 'temporary_file'].includes(retention)) {
    throw new HttpError(400, 'X-Retention-Policy must be ephemeral_24h or temporary_file.', { code: 'EMAIL_RETENTION_INVALID' });
  }
}

function requireReceiverSecret(req) {
  const supplied = Buffer.from(header(req, 'x-veritrust-receiver-secret'));
  const expected = Buffer.from(serverConfig.emailReceiverSecret);
  if (supplied.length !== expected.length || supplied.length < 32 || !crypto.timingSafeEqual(supplied, expected)) {
    throw new HttpError(401, 'Trusted receiver authorization failed.', { code: 'RECEIVER_UNAUTHORIZED' });
  }
}

function parseRawReference(value, orgId) {
  const raw = String(value || '').trim();
  const prefix = 'gateway-uploads:';
  if (!raw.startsWith(prefix)) throw new HttpError(400, 'raw_eml_ref must reference gateway-uploads.', { code: 'RAW_EML_REF_INVALID' });
  const path = raw.slice(prefix.length).replace(/^\/+/, '');
  if (!path.startsWith(`${orgId}/`)) throw new HttpError(403, 'raw_eml_ref is outside the authenticated organization.', { code: 'RAW_EML_REF_TENANT_MISMATCH' });
  if (path.includes('..') || path.includes('\\')) throw new HttpError(400, 'raw_eml_ref contains an invalid path.', { code: 'RAW_EML_REF_INVALID' });
  return path;
}

async function analyzeText(req, onProgress = () => {}) {
  const ids = requestIdentifiers(req);
  const auth = await authenticate(req, 'gateway:scan');
  const idempotencyKey = requireIdempotencyKey(req);
  validateJsonContentType(req);
  const text = validatePlainTextInput(await parseJsonBody(req, 32768));
  if (text.org_id && text.org_id !== auth.organization.id) throw new HttpError(403, 'org_id does not match the authenticated organization.', { code: 'ORG_MISMATCH' });
  onProgress('validation', 'completed', 'Email input and workspace access validated.');
  return analyzeEmail({ auth, mode: 'plain_text', text, parentScanId: text.parent_scan_id, integrationId: text.integration_id, idempotencyKey, requestId: ids.requestId, traceId: ids.traceId, onProgress });
}

async function analyzeEml(req, onProgress = () => {}) {
  const ids = requestIdentifiers(req);
  const auth = await authenticate(req, 'gateway:scan');
  const idempotencyKey = requireIdempotencyKey(req);
  requireMessageRfc822(req);
  const raw = await readRawBuffer(req);
  onProgress('validation', 'completed', 'Original email received and workspace access validated.');
  return analyzeEmail({ auth, mode: 'raw_eml', raw, parentScanId: parentScanId(req), idempotencyKey, requestId: ids.requestId, traceId: ids.traceId, onProgress });
}


function trustedReceiverMetadata(req) {
  return validateTrustedReceiverMetadata({
    client_ip: header(req, 'x-veritrust-client-ip'),
    mail_from: header(req, 'x-veritrust-mail-from'),
    helo: header(req, 'x-veritrust-helo'),
    receiver_id: header(req, 'x-veritrust-receiver-id'),
    authserv_id: header(req, 'x-veritrust-authserv-id'),
    received_at: header(req, 'x-veritrust-received-at'),
    event_id: header(req, 'x-veritrust-receiver-event-id'),
    integration_id: header(req, 'x-veritrust-integration-id') || null,
  });
}

async function receiverEml(req, onProgress = () => {}) {
  const ids = requestIdentifiers(req);
  requireReceiverSecret(req);
  const auth = await authenticate(req, 'gateway:scan');
  const idempotencyKey = requireIdempotencyKey(req);
  requireMessageRfc822(req);
  const receiver = { ...trustedReceiverMetadata(req), trust_authentication_results_headers: false };
  const raw = await readRawBuffer(req);
  onProgress('validation', 'completed', 'Trusted SMTP receiver facts and original email bytes validated.');
  return analyzeEmail({
    auth,
    mode: 'trusted_receiver_event',
    raw,
    receiver,
    parentScanId: parentScanId(req),
    integrationId: receiver.integration_id,
    idempotencyKey,
    requestId: ids.requestId,
    traceId: ids.traceId,
    onProgress,
  });
}

async function receiverEvent(req) {
  const ids = requestIdentifiers(req);
  requireReceiverSecret(req);
  const auth = await authenticate(req, 'gateway:scan');
  const idempotencyKey = requireIdempotencyKey(req);
  validateJsonContentType(req);
  const receiver = { ...validateReceiverEvent(await parseJsonBody(req, 32768)), trust_authentication_results_headers: true };
  if (receiver.org_id !== auth.organization.id) throw new HttpError(403, 'Receiver event organization does not match authentication.', { code: 'ORG_MISMATCH' });
  const path = parseRawReference(receiver.raw_eml_ref, auth.organization.id);
  const object = await downloadObject('gateway-uploads', path);
  if (object.buffer.length > MAX_RAW_EML_BYTES) throw new HttpError(413, 'Raw email exceeds the 10 MiB endpoint limit.', { code: 'UNSUPPORTED_LIMIT' });
  return analyzeEmail({ auth, mode: 'trusted_receiver_event', raw: object.buffer, receiver, integrationId: receiver.integration_id, idempotencyKey, requestId: ids.requestId, traceId: ids.traceId });
}

async function evidence(req, scanId) {
  const auth = await authenticate(req, 'gateway:read');
  const [report, gateway] = await Promise.all([
    emailEvidenceReport(auth.organization.id, scanId),
    scanReport(auth.organization.id, scanId),
  ]);
  if (!report) throw new HttpError(404, 'Email evidence was not found.', { code: 'EMAIL_EVIDENCE_NOT_FOUND' });
  const storedDecision = gateway.scan?.response_body?.gateway_decision || null;
  const latestDecision = [...(gateway.decisions || [])].sort((a, b) => Number(b.sequence || 0) - Number(a.sequence || 0))[0] || null;
  const gatewayDecision = storedDecision || (latestDecision ? {
    // gateway_decisions persists the numeric score as risk_score. Keep the public
    // V2 contract stable as gateway_decision.risk when reconstructing saved scans.
    risk: latestDecision.risk_score ?? latestDecision.risk ?? null,
    severity: latestDecision.severity,
    verdict: latestDecision.verdict,
    recommendation: latestDecision.recommendation,
    degraded: Boolean(latestDecision.degraded),
    reason_codes: latestDecision.reason_codes || [],
    correlation_version: latestDecision.correlation_version || null,
  } : null);
  return { status: 200, body: { ok: true, scan_id: scanId, status: gateway.scan?.status || 'completed', gateway_decision: gatewayDecision, evidence: report }, replayed: false };
}

async function exportEvidence(req, scanId, format = 'json') {
  const auth = await authenticate(req, 'gateway:read');
  const report = await emailEvidenceReport(auth.organization.id, scanId);
  if (!report) throw new HttpError(404, 'Email evidence was not found.', { code: 'EMAIL_EVIDENCE_NOT_FOUND' });
  const normalized = String(format || 'json').toLowerCase();
  if (normalized === 'stix') return { contentType: 'application/stix+json; charset=utf-8', filename: `veritrust-${scanId}-stix.json`, body: JSON.stringify(toStixBundle(scanId, report), null, 2) };
  if (normalized === 'csv') return { contentType: 'text/csv; charset=utf-8', filename: `veritrust-${scanId}-iocs.csv`, body: toCsv(report) };
  if (normalized === 'iocs') return { contentType: 'application/json; charset=utf-8', filename: `veritrust-${scanId}-iocs.json`, body: JSON.stringify({ schema_version: 'veritrust-ioc-export-1', scan_id: scanId, iocs: collectIocs(report) }, null, 2) };
  if (normalized === 'json') return { contentType: 'application/json; charset=utf-8', filename: `veritrust-${scanId}-evidence.json`, body: JSON.stringify({ scan_id: scanId, evidence: report }, null, 2) };
  throw new HttpError(400, 'format must be json, iocs, csv, or stix.', { code: 'EMAIL_EXPORT_FORMAT_INVALID' });
}

async function verifyPassport(req) {
  validateJsonContentType(req);
  const body = await parseJsonBody(req, 1024 * 1024);
  const unknown = Object.keys(body || {}).filter((key) => !['passport', 'evidence'].includes(key));
  if (unknown.length) throw new HttpError(400, `Unsupported fields: ${unknown.sort().join(', ')}.`, { code: 'EVIDENCE_VERIFY_SCHEMA_INVALID' });
  const verification = verifyEvidencePackage(body, { trustedKeyIds: trustedEvidenceKeyIds(), requireTrustedIssuer: true });
  return { status: verification.valid ? 200 : 422, body: { ok: verification.valid, verification } };
}

module.exports = { analyzeEml, analyzeText, evidence, exportEvidence, readRawBuffer, receiverEml, receiverEvent, trustedReceiverMetadata, verifyPassport };
