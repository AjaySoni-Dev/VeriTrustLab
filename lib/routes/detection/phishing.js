// Private route implementation; api/detection.js is the Vercel entrypoint.
const {
  PHISHING_MODELS,
  handleApiError,
  handleOptions,
  parseJsonBody,
  requireMethod,
  sendJson,
} = require('../../veritrust-api');
const { runPhishingDetection } = require('../../detection-service');
const { enforceRateLimit } = require('../../rate-limit');
const {
  getProfileContext,
  requireServiceRole,
  runScanLifecycle,
  scanIdempotencyKey,
  textHash,
} = require('../../supabase-server');
const {
  validateJsonContentType,
  validateModelKey,
  validatePhishingText,
} = require('../../validators');

module.exports = async function handler(req, res) {
  if (handleOptions(req, res)) return;

  try {
    requireMethod(req, 'POST');
    requireServiceRole();
    validateJsonContentType(req);

    const body = await parseJsonBody(req, 16000);
    const modelKey = validateModelKey(body.model || 'mailguard', PHISHING_MODELS, 'phishing');
    const text = validatePhishingText(body.text);
    const context = await getProfileContext(req, body.org_id || null);
    await enforceRateLimit({ req, endpoint: 'phishing', context });

    const { payload } = await runScanLifecycle(context, {
      scanType: 'phishing',
      inputKind: 'text',
      modelKey,
      projectId: body.project_id || null,
      textPreview: text.slice(0, 500),
      textHash: textHash(text),
      metadata: {
        length: text.length,
        retain_text: Boolean(body.retain_text),
      },
      endpoint: '/api/phishing',
      requestId: scanIdempotencyKey(req, 'phishing'),
    }, (scanId) => runPhishingDetection({
      text,
      modelKey,
      scanId,
      context,
      createdAt: new Date().toISOString(),
    }));
    sendJson(res, 200, payload);
  } catch (error) {
    handleApiError(res, error, 'Phishing analysis failed.');
  }
};
