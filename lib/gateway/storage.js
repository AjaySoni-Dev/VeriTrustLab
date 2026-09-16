const { serverConfig } = require('../config');
const { HttpError } = require('../veritrust-api');

async function storageRequest(path, options = {}) {
  const key = serverConfig.supabaseServiceRoleKey;
  const response = await fetch(`${serverConfig.supabaseUrl}/storage/v1${path}`, {
    method: options.method || 'GET',
    headers: {
      apikey: key,
      Authorization: `Bearer ${key}`,
      ...(options.body ? { 'Content-Type': options.contentType || 'application/json' } : {}),
      ...(options.headers || {}),
    },
    body: options.body
      ? (options.rawBody ? options.body : JSON.stringify(options.body))
      : undefined,
    signal: AbortSignal.timeout(options.timeoutMs || 30000),
  });
  if (options.raw && response.ok) return response;
  const text = await response.text();
  let data;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!response.ok) throw new HttpError(response.status, 'Supabase Storage request failed.', { code: 'STORAGE_REQUEST_FAILED', provider_status: response.status });
  return data;
}

function encodedPath(bucket, path) {
  return `${encodeURIComponent(bucket)}/${String(path).split('/').map(encodeURIComponent).join('/')}`;
}

async function createSignedUpload(bucket, path) {
  return storageRequest(`/object/upload/sign/${encodedPath(bucket, path)}`, { method: 'POST', body: {} });
}

async function createSignedDownload(bucket, path, expiresIn = 300) {
  const safeExpiry = Math.max(60, Math.min(3600, Number(expiresIn) || 300));
  const signed = await storageRequest(`/object/sign/${encodedPath(bucket, path)}`, {
    method: 'POST',
    body: { expiresIn: safeExpiry },
  });
  const value = signed?.signedURL || signed?.signedUrl || signed?.signed_url;
  if (!value || !String(value).startsWith('/')) return signed;
  return {
    ...signed,
    signedURL: `${serverConfig.supabaseUrl}/storage/v1${value}`,
  };
}

async function uploadObject(bucket, path, body, contentType = 'application/octet-stream', options = {}) {
  const payload = Buffer.isBuffer(body) ? body : Buffer.from(body);
  return storageRequest(`/object/${encodedPath(bucket, path)}`, {
    method: 'POST',
    body: payload,
    rawBody: true,
    contentType,
    headers: { 'x-upsert': options.upsert ? 'true' : 'false' },
    timeoutMs: 120000,
  });
}

async function objectInfo(bucket, path) {
  return storageRequest(`/object/info/${encodedPath(bucket, path)}`);
}

async function downloadObject(bucket, path) {
  const response = await storageRequest(`/object/${encodedPath(bucket, path)}`, { raw: true, timeoutMs: 120000 });
  return {
    buffer: Buffer.from(await response.arrayBuffer()),
    mimeType: String(response.headers.get('content-type') || 'application/octet-stream').split(';')[0].toLowerCase(),
  };
}

async function moveObject(bucket, sourcePath, destinationPath) {
  return storageRequest('/object/move', {
    method: 'POST',
    body: { bucketId: bucket, sourceKey: sourcePath, destinationKey: destinationPath },
    timeoutMs: 60000,
  });
}

async function deleteObject(bucket, path) {
  return storageRequest(`/object/${encodeURIComponent(bucket)}`, {
    method: 'DELETE',
    body: { prefixes: [path] },
    timeoutMs: 60000,
  });
}

async function deleteObjects(bucket, paths) {
  const prefixes = [...new Set((paths || []).filter(Boolean))];
  if (!prefixes.length) return [];
  return storageRequest(`/object/${encodeURIComponent(bucket)}`, {
    method: 'DELETE', body: { prefixes }, timeoutMs: 60000,
  });
}

module.exports = {
  createSignedUpload,
  createSignedDownload,
  deleteObject,
  deleteObjects,
  downloadObject,
  moveObject,
  objectInfo,
  uploadObject,
};
