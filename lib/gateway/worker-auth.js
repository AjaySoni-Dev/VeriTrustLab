const crypto = require('crypto');

const ALLOWED_SOURCES = new Set(['job_insert', 'cron', 'manual', 'recovery']);
const ALLOWED_QUEUES = new Set(['gateway_media', 'gateway_webhooks', 'gateway_retention']);

function requestHeader(req, name) {
  const headers = req?.headers;
  if (headers && typeof headers.get === 'function') return String(headers.get(name) || '').trim();
  return String(headers?.[name] || headers?.[name.toLowerCase()] || '').trim();
}

function hasDispatchSignatureHeaders(req) {
  return /^\d{10}$/.test(requestHeader(req, 'x-veritrust-dispatch-timestamp'))
    && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(requestHeader(req, 'x-veritrust-dispatch-nonce'))
    && /^v1=[0-9a-f]{64}$/i.test(requestHeader(req, 'x-veritrust-dispatch-signature'));
}

function constantTimeEqual(left, right) {
  const leftDigest = crypto.createHash('sha256').update(String(left || ''), 'utf8').digest();
  const rightDigest = crypto.createHash('sha256').update(String(right || ''), 'utf8').digest();
  return crypto.timingSafeEqual(leftDigest, rightDigest) && Boolean(left) && Boolean(right);
}

function signingMessage(dispatch, timestamp, nonce) {
  return [
    'v1',
    String(timestamp),
    String(nonce || '').toLowerCase(),
    dispatch.source,
    dispatch.jobId || '',
    dispatch.queue || '',
  ].join('\n');
}

function verifyDispatchSignature(req, secret, dispatch, now = Date.now()) {
  if (!hasDispatchSignatureHeaders(req)) return false;
  const timestamp = requestHeader(req, 'x-veritrust-dispatch-timestamp');
  const nonce = requestHeader(req, 'x-veritrust-dispatch-nonce').toLowerCase();
  const signature = requestHeader(req, 'x-veritrust-dispatch-signature').toLowerCase();
  const ageSeconds = Math.floor(now / 1000) - Number(timestamp);
  if (ageSeconds < -30 || ageSeconds > 300) return false;
  const expected = `v1=${crypto.createHmac('sha256', String(secret || '')).update(signingMessage(dispatch, timestamp, nonce), 'utf8').digest('hex')}`;
  return constantTimeEqual(signature, expected);
}

function parseDispatchPayload(body) {
  let payload = body;
  if (Buffer.isBuffer(payload)) payload = payload.toString('utf8');
  if (typeof payload === 'string') {
    if (Buffer.byteLength(payload, 'utf8') > 4096) throw Object.assign(new Error('Dispatch payload is too large.'), { code: 'PAYLOAD_TOO_LARGE' });
    try { payload = payload ? JSON.parse(payload) : {}; } catch { throw Object.assign(new Error('Dispatch payload must be valid JSON.'), { code: 'INVALID_JSON' }); }
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw Object.assign(new Error('Dispatch payload must be a JSON object.'), { code: 'INVALID_PAYLOAD' });
  }
  if (Buffer.byteLength(JSON.stringify(payload), 'utf8') > 4096) {
    throw Object.assign(new Error('Dispatch payload is too large.'), { code: 'PAYLOAD_TOO_LARGE' });
  }
  const unknown = Object.keys(payload).filter((key) => !['source', 'queue_name', 'job_id'].includes(key));
  if (unknown.length) throw Object.assign(new Error('Dispatch payload contains unsupported fields.'), { code: 'INVALID_PAYLOAD' });

  const source = String(payload.source || 'manual').trim();
  const queue = payload.queue_name === null || payload.queue_name === undefined ? null : String(payload.queue_name).trim();
  const jobId = payload.job_id === null || payload.job_id === undefined ? null : String(payload.job_id).trim();
  if (!ALLOWED_SOURCES.has(source)) throw Object.assign(new Error('Dispatch source is invalid.'), { code: 'INVALID_SOURCE' });
  if (queue && !ALLOWED_QUEUES.has(queue)) throw Object.assign(new Error('Dispatch queue is invalid.'), { code: 'INVALID_QUEUE' });
  if (jobId && !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(jobId)) {
    throw Object.assign(new Error('Dispatch job id is invalid.'), { code: 'INVALID_JOB_ID' });
  }
  return { source, queue, jobId };
}

module.exports = { constantTimeEqual, hasDispatchSignatureHeaders, parseDispatchPayload, requestHeader, signingMessage, verifyDispatchSignature };
