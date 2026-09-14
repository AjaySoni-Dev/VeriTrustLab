const crypto = require('crypto');
const { canonicalizeUrl } = require('./contracts');

const URL_PATTERN = /https?:\/\/[^\s<>"'`]+/giu;

function extractUrls(text) {
  const matches = String(text || '').match(URL_PATTERN) || [];
  const normalized = [];
  for (const raw of matches) {
    const candidate = raw.replace(/[),.;!?\]}]+$/u, '');
    try {
      normalized.push(canonicalizeUrl(candidate));
    } catch {
      // Invalid text fragments are ignored; explicit URLs are rejected by the request validator.
    }
  }
  return [...new Set(normalized)];
}

function contentHmac(key, tenantId, type, content) {
  if (!key || Buffer.byteLength(String(key), 'utf8') < 32) {
    const error = new Error('CONTENT_HMAC (or VERITRUST_CONTENT_HMAC_KEY) must contain at least 32 bytes.');
    error.status = 500;
    error.code = 'SERVER_CONFIG_ERROR';
    throw error;
  }
  if (!tenantId) {
    const error = new Error('A tenant identifier is required for content matching.');
    error.status = 500;
    error.code = 'TENANT_CONTEXT_REQUIRED';
    throw error;
  }
  const tenantKey = crypto.createHmac('sha256', key).update(`veritrust-tenant\u0000${tenantId}`, 'utf8').digest();
  return crypto.createHmac('sha256', tenantKey).update(`${type}\u0000${content}`, 'utf8').digest('hex');
}

function safeUrlMetadata(url) {
  const parsed = new URL(url);
  return {
    scheme: parsed.protocol.slice(0, -1),
    hostname: parsed.hostname,
    port: parsed.port || null,
    path: parsed.pathname || '/',
    query_present: Boolean(parsed.search),
  };
}

function buildArtifacts(submission, hmacKey, tenantId) {
  const artifacts = [];
  const urls = [...new Set([...submission.content.urls, ...extractUrls(submission.content.text)])];
  if (submission.content.text) {
    artifacts.push({
      ordinal: artifacts.length,
      type: 'text',
      content: submission.content.text,
      content_hmac: contentHmac(hmacKey, tenantId, 'text', submission.content.text),
      size_bytes: Buffer.byteLength(submission.content.text, 'utf8'),
      mime_type: 'text/plain',
      metadata: {
        character_count: submission.content.text.length,
        extracted_url_count: urls.length,
      },
    });
  }
  for (const url of urls) {
    artifacts.push({
      ordinal: artifacts.length,
      type: 'url',
      content: url,
      content_hmac: contentHmac(hmacKey, tenantId, 'url', url),
      size_bytes: Buffer.byteLength(url, 'utf8'),
      mime_type: 'text/uri-list',
      metadata: safeUrlMetadata(url),
    });
  }
  for (const media of submission.content.media) {
    artifacts.push({
      ordinal: artifacts.length,
      type: media.kind,
      content: null,
      upload_id: media.upload_id,
      content_hmac: null,
      size_bytes: null,
      mime_type: null,
      metadata: { upload_id: media.upload_id },
    });
  }
  return artifacts;
}

function persistenceArtifact(artifact) {
  return {
    ordinal: artifact.ordinal,
    artifact_type: artifact.type,
    status: artifact.content === null ? 'pending' : 'ready',
    content_hmac: artifact.content_hmac,
    mime_type: artifact.mime_type,
    size_bytes: artifact.size_bytes,
    storage_bucket: artifact.storage_bucket || null,
    storage_path: artifact.storage_path || null,
    retention: artifact.retention || 'metadata_only',
    retention_until: artifact.retention_until || null,
    metadata: artifact.metadata,
  };
}

module.exports = {
  buildArtifacts,
  contentHmac,
  extractUrls,
  persistenceArtifact,
  safeUrlMetadata,
};
