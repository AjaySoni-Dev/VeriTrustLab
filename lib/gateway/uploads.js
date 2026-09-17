const { HttpError } = require('../veritrust-api');
const { eq, supabaseFetch } = require('../supabase-server');
const { createSignedUpload, objectInfo } = require('./storage');

const LIMITS = Object.freeze({ image: 10 * 1024 * 1024, audio: 25 * 1024 * 1024, video: 100 * 1024 * 1024 });
const MIME = Object.freeze({
  image: new Set(['image/jpeg', 'image/png', 'image/webp', 'image/bmp']),
  audio: new Set(['audio/mpeg', 'audio/wav', 'audio/ogg', 'audio/mp4']),
  video: new Set(['video/mp4', 'video/webm', 'video/quicktime']),
});

function validateUploadRequest(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new HttpError(400, 'Upload request must be a JSON object.', { code: 'UPLOAD_SCHEMA_INVALID' });
  const kind = String(body.kind || '').toLowerCase();
  const mimeType = String(body.mime_type || '').toLowerCase();
  const sizeBytes = Number(body.size_bytes);
  if (!Object.prototype.hasOwnProperty.call(LIMITS, kind)) throw new HttpError(400, 'Upload kind must be image, audio, or video.', { code: 'UPLOAD_KIND_INVALID' });
  if (!MIME[kind].has(mimeType)) throw new HttpError(415, 'Upload MIME type is not supported for this media kind.', { code: 'UPLOAD_MIME_UNSUPPORTED' });
  if (!Number.isInteger(sizeBytes) || sizeBytes < 1 || sizeBytes > LIMITS[kind]) throw new HttpError(413, `Upload exceeds the ${kind} size limit.`, { code: 'UPLOAD_TOO_LARGE' });
  return { kind, mimeType, sizeBytes };
}

async function registerUpload(auth, integration, body) {
  const value = validateUploadRequest(body);
  const registered = await supabaseFetch('/rest/v1/rpc/gateway_register_upload', {
    method: 'POST', service: true, body: {
      target_org_id: auth.organization.id,
      target_integration_id: integration.id,
      target_artifact_type: value.kind,
      target_mime_type: value.mimeType,
      target_size_bytes: value.sizeBytes,
      target_created_by: auth.user?.id || null,
      target_ttl_seconds: 900,
    },
  });
  const row = Array.isArray(registered) ? registered[0] : registered;
  let signed;
  try {
    signed = await createSignedUpload(row.bucket, row.path);
  } catch (error) {
    await supabaseFetch(`/rest/v1/gateway_uploads?id=eq.${eq(row.upload_id)}&status=eq.pending`, {
      method: 'PATCH', service: true, body: { status: 'deleted' },
    }).catch(() => null);
    throw error;
  }
  const signedUrl = signed.url || signed.signedURL || signed.signedUrl || null;
  if (!signedUrl) throw new HttpError(502, 'Supabase Storage did not return a signed upload URL.', { code: 'SIGNED_UPLOAD_UNAVAILABLE' });
  return {
    upload_id: row.upload_id,
    bucket: row.bucket,
    path: row.path,
    expires_at: row.expires_at,
    signed_upload: { token: signed.token || null, url: signedUrl },
    required_headers: { 'Content-Type': value.mimeType },
  };
}

async function completeUpload(auth, uploadId) {
  const rows = await supabaseFetch(`/rest/v1/gateway_uploads?id=eq.${eq(uploadId)}&org_id=eq.${eq(auth.organization.id)}&status=eq.pending&select=*&limit=1`, { service: true });
  const upload = rows?.[0];
  if (!upload) throw new HttpError(404, 'Pending gateway upload was not found.', { code: 'UPLOAD_NOT_FOUND' });
  const info = await objectInfo(upload.storage_bucket, upload.staging_path);
  const metadata = info?.metadata || info;
  const size = Number(metadata?.size ?? metadata?.contentLength ?? metadata?.content_length ?? info?.size);
  const mimeType = String(metadata?.mimetype || metadata?.contentType || metadata?.content_type || upload.declared_mime_type).toLowerCase();
  if (!Number.isInteger(size) || size < 1 || size !== Number(upload.declared_size_bytes)) throw new HttpError(409, 'Stored object size does not match its declared size.', { code: 'UPLOAD_SIZE_MISMATCH' });
  if (!MIME[upload.artifact_type]?.has(mimeType)) throw new HttpError(415, 'Stored object MIME type is not permitted.', { code: 'UPLOAD_MIME_MISMATCH' });
  const completed = await supabaseFetch('/rest/v1/rpc/gateway_complete_upload', {
    method: 'POST', service: true, body: {
      target_upload_id: upload.id,
      target_detected_mime_type: mimeType,
      target_actual_size_bytes: size,
      target_content_sha256: null,
    },
  });
  if (!(Array.isArray(completed) ? completed[0] : completed)) throw new HttpError(409, 'Upload could not be completed or has expired.', { code: 'UPLOAD_STATE_CONFLICT' });
  return { upload_id: upload.id, status: 'uploaded', kind: upload.artifact_type, mime_type: mimeType, size_bytes: size };
}

module.exports = { LIMITS, MIME, completeUpload, registerUpload, validateUploadRequest };
