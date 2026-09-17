// Private route implementation; api/detection.js is the Vercel entrypoint.
const { analysisProgress } = require('../../analysis-stream');
const {
  validateLinkInput,
  validateLinkModel,
} = require('../../link-intelligence');
const { enforceRateLimit } = require('../../rate-limit');
const { runLinkDetection } = require('../../detection-service');
const {
  getProfileContext,
  requireServiceRole,
  runScanLifecycle,
  scanIdempotencyKey,
  textHash,
} = require('../../supabase-server');
const {
  handleApiError,
  handleOptions,
  parseJsonBody,
  requireMethod,
  sendJson,
} = require('../../veritrust-api');
const { validateJsonContentType } = require('../../validators');

module.exports = async function handler(req, res) {
  if (handleOptions(req, res)) return;
  const progress = analysisProgress(req, res);

  try {
    requireMethod(req, 'POST');
    requireServiceRole();
    validateJsonContentType(req);

    const body = await parseJsonBody(req, 16000);
    const modelKey = validateLinkModel(body.model);
    const linkInput = validateLinkInput({
      url: body.url,
      text: body.text,
      context: body.context,
    });

    const context = await getProfileContext(req, body.org_id || null);
    await enforceRateLimit({ req, endpoint: 'link', context });
    progress('validation', 'completed', 'URL, workspace access, and request limits validated.');

    const { payload } = await runScanLifecycle(context, {
      scanType: 'link',
      onProgress: progress,
      inputKind: 'url',
      modelKey,
      projectId: body.project_id || null,
      textPreview: `${linkInput.url}${linkInput.context ? ` ${linkInput.context}` : ''}`.slice(0, 500),
      textHash: textHash(`${linkInput.url}\n${linkInput.context || ''}`),
      metadata: {
        normalized_url: linkInput.url,
        urls_found: linkInput.urls_found,
        context_length: linkInput.context.length,
      },
      endpoint: '/api/link-check',
      requestId: scanIdempotencyKey(req, 'link'),
    }, (scanId) => runLinkDetection({
      url: body.url,
      onProgress: progress,
      text: body.text,
      context: body.context,
      modelKey,
      scanId,
      workspaceContext: context,
      createdAt: new Date().toISOString(),
    }));
    sendJson(res, 200, payload);
  } catch (error) {
    handleApiError(res, error, 'Link analysis failed.');
  }
};
