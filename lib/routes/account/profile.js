const {
  getProfileContext,
  supabaseFetch,
} = require('../../supabase-server');
const { serverConfig } = require('../../config');
const {
  HttpError,
  handleApiError,
  handleOptions,
  parseJsonBody,
  parseMultipart,
  sendJson,
} = require('../../veritrust-api');
const {
  detectedImageType,
  validateImageUpload,
  validateJsonContentType,
} = require('../../validators');

const AVATAR_TYPES = new Set(['image/jpeg', 'image/png', 'image/webp']);
const MAX_AVATAR_BYTES = 1024 * 1024;

function actionName(req) {
  return new URL(req.url || '/', 'http://localhost').searchParams.get('action') || 'update';
}

function avatarUrl(path, operation = '') {
  const safePath = String(path || '').split('/').map(encodeURIComponent).join('/');
  const prefix = operation ? `${operation}/` : '';
  return `${serverConfig.supabaseUrl}/storage/v1/object/${prefix}avatars/${safePath}`;
}

function storageHeaders(token, contentType = '') {
  return {
    apikey: serverConfig.supabaseAnonKey,
    Authorization: `Bearer ${token}`,
    ...(contentType ? { 'Content-Type': contentType } : {}),
  };
}

async function updateProfile(req, res) {
  const context = await getProfileContext(req);
  validateJsonContentType(req);
  const body = await parseJsonBody(req, 4096);
  const fullName = String(body.full_name || '').trim();
  const username = body.username === null || body.username === undefined ? null : String(body.username).trim().toLowerCase();
  if (!fullName || fullName.length > 120) throw new HttpError(400, 'Display name must contain 1 to 120 characters.', { code: 'PROFILE_NAME_INVALID' });
  if (username && !/^[a-z0-9][a-z0-9_.-]{2,31}$/u.test(username)) {
    throw new HttpError(400, 'Username must contain 3 to 32 lowercase letters, numbers, dots, dashes, or underscores.', { code: 'PROFILE_USERNAME_INVALID' });
  }
  const rows = await supabaseFetch('/rest/v1/rpc/update_my_profile', {
    method: 'POST',
    accessToken: context.token,
    body: { profile_patch: { full_name: fullName, username } },
  });
  sendJson(res, 200, { ok: true, profile: Array.isArray(rows) ? rows[0] : rows });
}

async function uploadAvatar(req, res) {
  const context = await getProfileContext(req);
  const { files } = await parseMultipart(req, {
    fileField: 'avatar',
    maxFileBytes: MAX_AVATAR_BYTES,
    allowedTypes: AVATAR_TYPES,
  });
  const upload = validateImageUpload(files.avatar, {
    maxBytes: MAX_AVATAR_BYTES,
    allowedTypes: AVATAR_TYPES,
  });
  const objectPath = `${context.user.id}/avatar`;
  const response = await fetch(avatarUrl(objectPath), {
    method: 'POST',
    headers: {
      ...storageHeaders(context.token, upload.mimeType),
      'x-upsert': 'true',
    },
    body: upload.buffer,
    signal: AbortSignal.timeout(30000),
  });
  if (!response.ok) throw new HttpError(502, 'Unable to store the profile photo.', { code: 'AVATAR_UPLOAD_FAILED' });
  await supabaseFetch('/rest/v1/rpc/update_my_profile', {
    method: 'POST',
    accessToken: context.token,
    body: { profile_patch: { avatar_url: objectPath } },
  });
  sendJson(res, 200, { ok: true, path: objectPath });
}

async function readBoundedBody(response, maxBytes) {
  if (!response.body?.getReader) {
    const buffer = Buffer.from(await response.arrayBuffer());
    if (buffer.length > maxBytes) throw new HttpError(413, 'Stored profile photo is too large.', { code: 'AVATAR_TOO_LARGE' });
    return buffer;
  }
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new HttpError(413, 'Stored profile photo is too large.', { code: 'AVATAR_TOO_LARGE' });
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks, total);
}

async function serveAvatar(req, res) {
  const context = await getProfileContext(req);
  const path = context.profile?.avatar_url;
  if (!path || !String(path).startsWith(`${context.user.id}/`)) throw new HttpError(404, 'Profile photo was not found.', { code: 'AVATAR_NOT_FOUND' });
  const response = await fetch(avatarUrl(path, 'authenticated'), {
    headers: storageHeaders(context.token),
    cache: 'no-store',
    signal: AbortSignal.timeout(30000),
  });
  if (!response.ok) throw new HttpError(404, 'Profile photo was not found.', { code: 'AVATAR_NOT_FOUND' });
  const declaredSize = Number(response.headers.get('content-length') || 0);
  if (declaredSize > MAX_AVATAR_BYTES) throw new HttpError(413, 'Stored profile photo is too large.', { code: 'AVATAR_TOO_LARGE' });
  const buffer = await readBoundedBody(response, MAX_AVATAR_BYTES);
  const detectedType = detectedImageType(buffer);
  if (!buffer.length || !detectedType || !AVATAR_TYPES.has(detectedType)) {
    throw new HttpError(415, 'Stored profile photo is invalid.', { code: 'AVATAR_INVALID' });
  }
  res.statusCode = 200;
  res.setHeader('Content-Type', detectedType);
  res.setHeader('Content-Length', String(buffer.length));
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.end(buffer);
}

module.exports = async function handler(req, res) {
  if (handleOptions(req, res)) return;
  try {
    const action = actionName(req);
    if (action === 'avatar' && req.method === 'GET') return serveAvatar(req, res);
    if (action === 'avatar' && req.method === 'POST') return uploadAvatar(req, res);
    if (action === 'update' && req.method === 'POST') return updateProfile(req, res);
    throw new HttpError(405, 'Use the documented profile method.', { code: 'METHOD_NOT_ALLOWED' });
  } catch (error) {
    handleApiError(res, error, 'Profile request failed.');
  }
};

module.exports.MAX_AVATAR_BYTES = MAX_AVATAR_BYTES;
