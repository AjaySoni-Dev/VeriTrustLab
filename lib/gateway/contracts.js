const { HttpError } = require('../veritrust-api');

const GATEWAY_SCHEMA_VERSION = '1.0';
const CORRELATION_VERSION = 'gateway-correlation-v3';
const PROCESSING_MODES = Object.freeze(['synchronous', 'asynchronous', 'hybrid']);
const ARTIFACT_TYPES = Object.freeze(['text', 'url', 'image', 'audio', 'video', 'email', 'attachment']);
const EVIDENCE_STATUSES = Object.freeze(['pending', 'completed', 'failed', 'timed_out', 'not_applicable']);
const RECOMMENDATIONS = Object.freeze(['allow', 'warn', 'manual_review', 'quarantine', 'block', 'hold']);
const MAX_TEXT_CHARS = 12000;
const MAX_URLS = 20;
const MAX_MEDIA = 10;
const MAX_METADATA_BYTES = 16384;

function fail(status, code, message, meta) {
  throw new HttpError(status, message, { code, ...(meta ? { meta } : {}) });
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function assertPlainObject(value, field) {
  if (!isPlainObject(value)) fail(400, 'GATEWAY_SCHEMA_INVALID', `${field} must be a JSON object.`);
  return value;
}

function assertAllowedKeys(value, allowed, field) {
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
  if (unknown.length) {
    fail(400, 'GATEWAY_SCHEMA_UNKNOWN_FIELD', `${field} contains unsupported fields.`, {
      field,
      unknown_fields: unknown.sort(),
    });
  }
}

function optionalString(value, field, maxLength) {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value !== 'string') fail(400, 'GATEWAY_SCHEMA_INVALID', `${field} must be a string.`);
  const result = value.trim();
  if (!result || result.length > maxLength) {
    fail(400, 'GATEWAY_SCHEMA_INVALID', `${field} must contain 1 to ${maxLength} characters.`);
  }
  return result;
}

function optionalUuid(value, field) {
  const result = optionalString(value, field, 64);
  if (result && !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(result)) {
    fail(400, 'GATEWAY_SCHEMA_INVALID', `${field} must be a UUID.`);
  }
  return result;
}

function canonicalizeUrl(value) {
  if (typeof value !== 'string' || !value.trim()) fail(400, 'GATEWAY_URL_INVALID', 'Each URL must be a non-empty string.');
  let parsed;
  try {
    parsed = new URL(value.trim());
  } catch {
    fail(400, 'GATEWAY_URL_INVALID', 'A submitted URL is invalid.');
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    fail(400, 'GATEWAY_URL_SCHEME_DENIED', 'Only HTTP and HTTPS URLs can be analyzed.');
  }
  if (parsed.username || parsed.password) {
    fail(400, 'GATEWAY_URL_CREDENTIALS_DENIED', 'URLs containing embedded credentials are not accepted.');
  }
  parsed.hash = '';
  parsed.hostname = parsed.hostname.toLowerCase();
  if ((parsed.protocol === 'https:' && parsed.port === '443') || (parsed.protocol === 'http:' && parsed.port === '80')) parsed.port = '';
  return parsed.toString();
}

function validateMetadata(value) {
  const metadata = value === undefined ? {} : assertPlainObject(value, 'metadata');
  const bytes = Buffer.byteLength(JSON.stringify(metadata), 'utf8');
  if (bytes > MAX_METADATA_BYTES) fail(413, 'GATEWAY_METADATA_TOO_LARGE', `metadata must be ${MAX_METADATA_BYTES} bytes or smaller.`);
  return metadata;
}

function validateGatewaySubmission(input) {
  const body = assertPlainObject(input, 'request body');
  assertAllowedKeys(body, ['source', 'content', 'policy_id', 'callback', 'metadata', 'processing_mode'], 'request body');

  const source = assertPlainObject(body.source || {}, 'source');
  assertAllowedKeys(source, ['integration_id', 'external_event_id', 'kind'], 'source');
  const content = assertPlainObject(body.content || {}, 'content');
  assertAllowedKeys(content, ['text', 'urls', 'media'], 'content');

  let text = null;
  if (content.text !== undefined && content.text !== null) {
    if (typeof content.text !== 'string') fail(400, 'GATEWAY_SCHEMA_INVALID', 'content.text must be a string.');
    text = content.text.trim();
    if (!text) text = null;
    if (text && text.length > MAX_TEXT_CHARS) fail(413, 'GATEWAY_TEXT_TOO_LARGE', `content.text must be ${MAX_TEXT_CHARS} characters or shorter.`);
  }

  const rawUrls = content.urls === undefined ? [] : content.urls;
  if (!Array.isArray(rawUrls)) fail(400, 'GATEWAY_SCHEMA_INVALID', 'content.urls must be an array.');
  if (rawUrls.length > MAX_URLS) fail(413, 'GATEWAY_TOO_MANY_URLS', `A scan can contain at most ${MAX_URLS} explicit URLs.`);
  const urls = [...new Set(rawUrls.map(canonicalizeUrl))].sort();

  const rawMedia = content.media === undefined ? [] : content.media;
  if (!Array.isArray(rawMedia)) fail(400, 'GATEWAY_SCHEMA_INVALID', 'content.media must be an array.');
  if (rawMedia.length > MAX_MEDIA) fail(413, 'GATEWAY_TOO_MANY_MEDIA', `A scan can contain at most ${MAX_MEDIA} media items.`);
  const media = rawMedia.map((item, index) => {
    const value = assertPlainObject(item, `content.media[${index}]`);
    assertAllowedKeys(value, ['upload_id', 'kind'], `content.media[${index}]`);
    const kind = optionalString(value.kind, `content.media[${index}].kind`, 16);
    if (!['image', 'audio', 'video'].includes(kind)) fail(400, 'GATEWAY_MEDIA_KIND_INVALID', 'Media kind must be image, audio, or video.');
    const uploadId = optionalUuid(value.upload_id, `content.media[${index}].upload_id`);
    if (!uploadId) fail(400, 'GATEWAY_UPLOAD_REQUIRED', 'Every media item must reference a completed registered upload.');
    return { upload_id: uploadId, kind };
  });
  if (new Set(media.map((item) => item.upload_id)).size !== media.length) fail(400, 'GATEWAY_UPLOAD_DUPLICATE', 'The same upload cannot appear more than once in a scan.');

  if (!text && !urls.length && !media.length) fail(400, 'GATEWAY_CONTENT_REQUIRED', 'Submit text, one or more URLs, or registered media.');

  const callback = body.callback === undefined ? null : assertPlainObject(body.callback, 'callback');
  if (callback) assertAllowedKeys(callback, ['webhook_endpoint_id'], 'callback');
  const processingMode = optionalString(body.processing_mode, 'processing_mode', 32) || 'hybrid';
  if (!PROCESSING_MODES.includes(processingMode)) fail(400, 'GATEWAY_PROCESSING_MODE_INVALID', 'processing_mode is not supported.');

  return {
    schema_version: GATEWAY_SCHEMA_VERSION,
    processing_mode: processingMode,
    source: {
      integration_id: optionalUuid(source.integration_id, 'source.integration_id'),
      external_event_id: optionalString(source.external_event_id, 'source.external_event_id', 255),
      kind: optionalString(source.kind, 'source.kind', 64) || 'api',
    },
    content: { text, urls, media },
    policy_id: optionalUuid(body.policy_id, 'policy_id'),
    callback: callback ? { webhook_endpoint_id: optionalUuid(callback.webhook_endpoint_id, 'callback.webhook_endpoint_id') } : null,
    metadata: validateMetadata(body.metadata),
  };
}

module.exports = {
  ARTIFACT_TYPES,
  CORRELATION_VERSION,
  EVIDENCE_STATUSES,
  GATEWAY_SCHEMA_VERSION,
  PROCESSING_MODES,
  RECOMMENDATIONS,
  assertAllowedKeys,
  assertPlainObject,
  canonicalizeUrl,
  isPlainObject,
  validateGatewaySubmission,
};
