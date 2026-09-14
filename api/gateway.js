const {
  HttpError,
  handleOptions,
  parseJsonBody,
  sendJson,
} = require('../lib/veritrust-api');
const { validateJsonContentType } = require('../lib/validators');
const { validateGatewaySubmission } = require('../lib/gateway/contracts');
const { requestIdentifiers, requireIdempotencyKey } = require('../lib/gateway/idempotency');
const { orchestrateSubmission, publicReport } = require('../lib/gateway/orchestrator');
const { completeUpload, registerUpload } = require('../lib/gateway/uploads');
const {
  activatePolicy,
  createPolicy,
  createWebhook,
  disableWebhook,
  listPolicies,
  listReviews,
  listWebhooks,
  operations,
  resolveReview,
  testWebhook,
} = require('../lib/gateway/management');
const {
  authenticate,
  cancelScan,
  listScans,
  scanReport,
} = require('../lib/gateway/persistence');
const serverlessWorker = require('../lib/routes/gateway/worker');
const { hasDispatchSignatureHeaders } = require('../lib/gateway/worker-auth');
const { isModuleEnabled } = require('../lib/modules');
const emailV2 = require('../lib/routes/email/v2');
const { analysisProgress } = require('../lib/analysis-stream');

function route(req) {
  const url = new URL(req.url || '/', 'http://localhost');
  return {
    resource: url.searchParams.get('resource') || '',
    id: url.searchParams.get('id') || '',
    action: url.searchParams.get('action') || '',
    limit: url.searchParams.get('limit') || '',
    format: url.searchParams.get('format') || '',
  };
}

function requireMethod(req, allowed) {
  if (!allowed.includes(req.method)) {
    throw new HttpError(405, `Use ${allowed.join(' or ')} for this endpoint.`, { code: 'METHOD_NOT_ALLOWED' });
  }
}

function gatewayError(error) {
  if (error instanceof HttpError) return error;
  const text = `${error?.message || ''} ${JSON.stringify(error?.details || '')}`;
  if (text.includes('GATEWAY_IDEMPOTENCY_CONFLICT')) return new HttpError(409, 'Idempotency-Key was already used with different content.', { code: 'IDEMPOTENCY_CONFLICT' });
  if (text.includes('GATEWAY_QUOTA_EXCEEDED')) return new HttpError(429, 'Gateway scan quota exceeded.', { code: 'GATEWAY_QUOTA_EXCEEDED' });
  if (text.toLowerCase().includes('gateway is not enabled')) return new HttpError(403, 'The unified gateway is not enabled for this organization.', { code: 'GATEWAY_NOT_ENABLED' });
  if (text.toLowerCase().includes('active gateway integration')) return new HttpError(403, 'The selected gateway integration is unavailable.', { code: 'INTEGRATION_ACTION_DENIED' });
  return error;
}

function sendError(res, error, requestId) {
  const normalized = gatewayError(error);
  const status = Math.max(400, Math.min(599, Number(normalized.status || 500)));
  const code = normalized.code || normalized.extra?.code || (status >= 500 ? 'INTERNAL_ERROR' : 'GATEWAY_REQUEST_FAILED');
  const message = status >= 500 ? 'The gateway request could not be completed.' : normalized.message;
  if (status >= 500) console.error(JSON.stringify({ timestamp: new Date().toISOString(), level: 'error', service: 'veritrust-gateway', event: 'gateway.http.error', request_id: requestId, status, error_code: code }));
  sendJson(res, status, { ok: false, request_id: requestId, error: { code, message }, ...(normalized.extra?.meta ? { meta: normalized.extra.meta } : {}) });
}

module.exports = async function handler(req, res) {
  if (!isModuleEnabled('gateway')) {
    sendJson(res, 404, { ok: false, error: { code: 'NOT_FOUND', message: 'The requested resource was not found.' } });
    return;
  }
  const target = route(req);
  if (target.resource === 'worker') {
    if (req.method === 'POST' && !hasDispatchSignatureHeaders(req)) {
      const ids = requestIdentifiers(req);
      sendJson(res, 401, { ok: false, request_id: ids.requestId, error: { code: 'UNAUTHORIZED', message: 'Worker authorization failed.' } });
      return;
    }
    return serverlessWorker(req, res);
  }
  if (handleOptions(req, res)) return;
  const ids = requestIdentifiers(req);

  const progress = ['email-text', 'email-eml', 'email-receiver-eml'].includes(target.resource) ? analysisProgress(req, res) : undefined;

  try {
    if (target.resource === 'email-text') {
      requireMethod(req, ['POST']);
      const result = await emailV2.analyzeText(req, progress);
      if (!res.headersSent) res.setHeader('X-Idempotent-Replayed', result.replayed ? 'true' : 'false');
      sendJson(res, result.status, result.body);
      return;
    }

    if (target.resource === 'email-eml') {
      requireMethod(req, ['POST']);
      const result = await emailV2.analyzeEml(req, progress);
      if (!res.headersSent) res.setHeader('X-Idempotent-Replayed', result.replayed ? 'true' : 'false');
      sendJson(res, result.status, result.body);
      return;
    }


    if (target.resource === 'email-receiver-eml') {
      requireMethod(req, ['POST']);
      const result = await emailV2.receiverEml(req, progress);
      if (!res.headersSent) res.setHeader('X-Idempotent-Replayed', result.replayed ? 'true' : 'false');
      sendJson(res, result.status, result.body);
      return;
    }

    if (target.resource === 'email-receiver') {
      requireMethod(req, ['POST']);
      const result = await emailV2.receiverEvent(req);
      res.setHeader('X-Idempotent-Replayed', result.replayed ? 'true' : 'false');
      sendJson(res, result.status, result.body);
      return;
    }

    if (target.resource === 'email-evidence' && target.id) {
      requireMethod(req, ['GET']);
      const result = await emailV2.evidence(req, target.id);
      sendJson(res, result.status, result.body);
      return;
    }

    if (target.resource === 'email-export' && target.id) {
      requireMethod(req, ['GET']);
      const result = await emailV2.exportEvidence(req, target.id, target.format || 'json');
      res.statusCode = 200;
      res.setHeader('Content-Type', result.contentType);
      res.setHeader('Content-Disposition', `attachment; filename="${result.filename}"`);
      res.setHeader('Cache-Control', 'no-store');
      res.end(result.body);
      return;
    }

    if (target.resource === 'email-passport-verify') {
      requireMethod(req, ['POST']);
      const result = await emailV2.verifyPassport(req);
      sendJson(res, result.status, result.body);
      return;
    }

    if (target.resource === 'scans' && !target.id) {
      requireMethod(req, ['GET', 'POST']);
      if (req.method === 'GET') {
        const auth = await authenticate(req, 'gateway:read');
        const scans = await listScans(auth.organization.id, { limit: target.limit });
        sendJson(res, 200, { ok: true, request_id: ids.requestId, schema_version: '1.0', scans });
        return;
      }
      const auth = await authenticate(req, 'gateway:scan');
      const idempotencyKey = requireIdempotencyKey(req);
      validateJsonContentType(req);
      const body = await parseJsonBody(req, 262144);
      const submission = validateGatewaySubmission(body);
      const result = await orchestrateSubmission({
        auth,
        submission,
        idempotencyKey,
        requestId: ids.requestId,
        traceId: ids.traceId,
      });
      res.setHeader('X-Idempotent-Replayed', result.replayed ? 'true' : 'false');
      sendJson(res, result.status, result.body);
      return;
    }

    if (target.resource === 'uploads' && !target.id) {
      requireMethod(req, ['POST']);
      const auth = await authenticate(req, 'gateway:scan');
      validateJsonContentType(req);
      const body = await parseJsonBody(req, 16384);
      const upload = await registerUpload(auth, auth.integration, body);
      sendJson(res, 201, { ok: true, request_id: ids.requestId, ...upload });
      return;
    }

    if (target.resource === 'uploads' && target.id && target.action === 'complete') {
      requireMethod(req, ['POST']);
      const auth = await authenticate(req, 'gateway:scan');
      const upload = await completeUpload(auth, target.id);
      sendJson(res, 200, { ok: true, request_id: ids.requestId, ...upload });
      return;
    }

    if (target.resource === 'scans' && target.id && target.action === 'cancel') {
      requireMethod(req, ['POST']);
      const auth = await authenticate(req, 'gateway:cancel');
      const status = await cancelScan(auth.organization.id, target.id);
      sendJson(res, 200, { ok: true, request_id: ids.requestId, scan_id: target.id, status });
      return;
    }

    if (target.resource === 'scans' && target.id) {
      requireMethod(req, ['GET']);
      const auth = await authenticate(req, 'gateway:read');
      const report = publicReport(await scanReport(auth.organization.id, target.id));
      sendJson(res, 200, { ok: true, ...report, request_id: ids.requestId });
      return;
    }

    if (target.resource === 'reports' && target.id) {
      requireMethod(req, ['GET']);
      const auth = await authenticate(req, 'gateway:read');
      const report = publicReport(await scanReport(auth.organization.id, target.id));
      sendJson(res, 200, { ok: true, request_id: ids.requestId, report });
      return;
    }

    if (target.resource === 'policies' && !target.id) {
      requireMethod(req, ['GET', 'POST']);
      const action = req.method === 'GET' ? 'gateway:policy:read' : 'gateway:policy:write';
      const auth = await authenticate(req, action);
      if (req.method === 'GET') {
        sendJson(res, 200, { ok: true, request_id: ids.requestId, policies: await listPolicies(auth) });
      } else {
        validateJsonContentType(req);
        sendJson(res, 201, { ok: true, request_id: ids.requestId, ...(await createPolicy(auth, await parseJsonBody(req, 262144))) });
      }
      return;
    }

    if (target.resource === 'policies' && target.id && target.action === 'activate') {
      requireMethod(req, ['POST']);
      const auth = await authenticate(req, 'gateway:policy:write');
      sendJson(res, 200, { ok: true, request_id: ids.requestId, ...(await activatePolicy(auth, target.id)) });
      return;
    }

    if (target.resource === 'webhooks' && !target.id) {
      requireMethod(req, ['GET', 'POST']);
      const auth = await authenticate(req, 'gateway:webhook:manage');
      if (req.method === 'GET') sendJson(res, 200, { ok: true, request_id: ids.requestId, webhooks: await listWebhooks(auth) });
      else {
        validateJsonContentType(req);
        sendJson(res, 201, { ok: true, request_id: ids.requestId, ...(await createWebhook(auth, await parseJsonBody(req, 32768))) });
      }
      return;
    }

    if (target.resource === 'webhooks' && target.id && ['disable', 'test'].includes(target.action)) {
      requireMethod(req, ['POST']);
      const auth = await authenticate(req, 'gateway:webhook:manage');
      const result = target.action === 'disable' ? await disableWebhook(auth, target.id) : await testWebhook(auth, target.id);
      sendJson(res, 200, { ok: true, request_id: ids.requestId, ...result });
      return;
    }

    if (target.resource === 'reviews' && target.id && target.action === 'resolve') {
      requireMethod(req, ['POST']);
      const auth = await authenticate(req, 'gateway:policy:write');
      validateJsonContentType(req);
      sendJson(res, 200, { ok: true, request_id: ids.requestId, ...(await resolveReview(auth, target.id, await parseJsonBody(req, 16384))) });
      return;
    }

    if (target.resource === 'reviews' && !target.id) {
      requireMethod(req, ['GET']);
      const auth = await authenticate(req, 'gateway:read');
      sendJson(res, 200, { ok: true, request_id: ids.requestId, reviews: await listReviews(auth) });
      return;
    }

    if (target.resource === 'operations') {
      requireMethod(req, ['GET']);
      const auth = await authenticate(req, 'gateway:policy:read');
      sendJson(res, 200, { ok: true, request_id: ids.requestId, operations: await operations(auth) });
      return;
    }

    throw new HttpError(404, 'Unknown gateway endpoint.', { code: 'NOT_FOUND' });
  } catch (error) {
    sendError(res, error, ids.requestId);
  }
};

module.exports.config = {
  api: {
    bodyParser: false,
  },
};
