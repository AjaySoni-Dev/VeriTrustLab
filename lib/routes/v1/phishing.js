const {
  externalApiError,
  recordApiUsage,
  requestId,
  requireApiKey,
} = require('../../api-keys');
const { applyEntitlementHeaders } = require('../../entitlements');
const { externalModelKey, runPhishingDetection } = require('../../detection-service');
const {
  PHISHING_MODELS,
  handleOptions,
  parseJsonBody,
  requireMethod,
  sendJson,
} = require('../../veritrust-api');
const {
  validateJsonContentType,
  validateModelKey,
  validatePhishingText,
} = require('../../validators');

module.exports = async function handler(req, res) {
  if (handleOptions(req, res)) return;
  const request_id = requestId(req);
  const started = Date.now();
  let auth = null;

  try {
    requireMethod(req, 'POST');
    auth = await requireApiKey(req, 'phishing:scan', {
      requestId: request_id,
      endpoint: '/api/v1/phishing',
    });
    applyEntitlementHeaders(res, auth.entitlement);
    validateJsonContentType(req);
    const body = await parseJsonBody(req, 16000);
    const text = validatePhishingText(body.text);
    const modelKey = validateModelKey(externalModelKey('phishing', body.model), PHISHING_MODELS, 'phishing');
    const createdAt = new Date().toISOString();
    const { payload } = await runPhishingDetection({ text, modelKey, createdAt });
    const usage = await recordApiUsage(auth, {
      endpoint: '/api/v1/phishing',
      scan_type: 'phishing',
      status: 'success',
      request_id,
      latency_ms: Date.now() - started,
    });

    sendJson(res, 200, {
      ok: true,
      request_id,
      scan_type: 'phishing',
      created_at: createdAt,
      model: payload.model,
      result: payload.result,
      scores: payload.scores || [],
      usage: usage || auth.usage,
    });
  } catch (error) {
    if (auth) {
      await recordApiUsage(auth, {
        endpoint: '/api/v1/phishing',
        scan_type: 'phishing',
        status: 'error',
        request_id,
        latency_ms: Date.now() - started,
        error_code: error.code || error.extra?.code || 'INTERNAL_ERROR',
      });
    }
    externalApiError(res, error, 'Phishing analysis failed.', request_id);
  }
};
