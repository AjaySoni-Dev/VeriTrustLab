const {
  validateLinkModel,
} = require('../../link-intelligence');
const {
  externalApiError,
  recordApiUsage,
  requestId,
  requireApiKey,
} = require('../../api-keys');
const { applyEntitlementHeaders } = require('../../entitlements');
const { runLinkDetection } = require('../../detection-service');
const {
  handleOptions,
  parseJsonBody,
  requireMethod,
  sendJson,
} = require('../../veritrust-api');
const { validateJsonContentType } = require('../../validators');

module.exports = async function handler(req, res) {
  if (handleOptions(req, res)) return;
  const request_id = requestId(req);
  const started = Date.now();
  let auth = null;

  try {
    requireMethod(req, 'POST');
    auth = await requireApiKey(req, 'link:scan', {
      requestId: request_id,
      endpoint: '/api/v1/link-check',
    });
    applyEntitlementHeaders(res, auth.entitlement);
    validateJsonContentType(req);

    const body = await parseJsonBody(req, 16000);
    const modelKey = validateLinkModel(body.model);
    const createdAt = new Date().toISOString();
    const { payload } = await runLinkDetection({
      url: body.url,
      text: body.text,
      context: body.context,
      modelKey,
      createdAt,
    });
    const usage = await recordApiUsage(auth, {
      endpoint: '/api/v1/link-check',
      scan_type: 'link',
      status: 'success',
      request_id,
      latency_ms: Date.now() - started,
    });

    sendJson(res, 200, {
      ok: true,
      request_id,
      scan_type: 'link',
      created_at: createdAt,
      model: payload.model,
      result: payload.result,
      scores: payload.scores || [],
      usage: usage || auth.usage,
    });
  } catch (error) {
    if (auth) {
      await recordApiUsage(auth, {
        endpoint: '/api/v1/link-check',
        scan_type: 'link',
        status: 'error',
        request_id,
        latency_ms: Date.now() - started,
        error_code: error.code || error.extra?.code || 'INTERNAL_ERROR',
      });
    }
    externalApiError(res, error, 'Link analysis failed.', request_id);
  }
};
