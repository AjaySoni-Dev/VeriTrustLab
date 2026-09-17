// Private route implementation; api/detection.js is the Vercel entrypoint.
const crypto = require('node:crypto');
const { analysisProgress } = require('../../analysis-stream');
const {
  DEEPFAKE_MODELS,
  handleApiError,
  handleOptions,
  parseMultipart,
  requireMethod,
  sendJson,
} = require('../../veritrust-api');
const { runDeepfakeDetection } = require('../../detection-service');
const { enforceRateLimit } = require('../../rate-limit');
const {
  getProfileContext,
  requireServiceRole,
  runScanLifecycle,
  scanIdempotencyKey,
} = require('../../supabase-server');
const { validateImageUpload, validateModelKey } = require('../../validators');

module.exports = async function handler(req, res) {
  if (handleOptions(req, res)) return;
  const progress = analysisProgress(req, res);

  try {
    requireMethod(req, 'POST');
    requireServiceRole();

    const { fields, files } = await parseMultipart(req);
    const modelKey = validateModelKey(fields.model || 'pixel', DEEPFAKE_MODELS, 'deepfake');
    const upload = validateImageUpload(files.image);
    const context = await getProfileContext(req, fields.org_id || null);
    await enforceRateLimit({ req, endpoint: 'deepfake', context });
    progress('validation', 'completed', 'Image, workspace access, and request limits validated.');

    const inputMetadata = {
      filename: upload.filename,
      mime_type: upload.mimeType,
      size_bytes: upload.size,
      retain_file: String(fields.retain_file || 'false') === 'true',
    };
    const { payload } = await runScanLifecycle(context, {
      scanType: 'deepfake',
      onProgress: progress,
      inputKind: 'image',
      modelKey,
      projectId: fields.project_id || null,
      textHash: crypto.createHash('sha256').update(upload.buffer).digest('hex'),
      metadata: inputMetadata,
      endpoint: '/api/deepfake',
      requestId: scanIdempotencyKey(req, 'deepfake'),
    }, (scanId) => runDeepfakeDetection({
      upload,
      onProgress: progress,
      modelKey,
      scanId,
      context,
      metadata: inputMetadata,
      createdAt: new Date().toISOString(),
    }));
    sendJson(res, 200, payload);
  } catch (error) {
    handleApiError(res, error, 'Deepfake analysis failed.');
  }
};
