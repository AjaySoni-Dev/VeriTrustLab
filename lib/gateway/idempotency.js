const crypto = require('crypto');
const { HttpError } = require('../veritrust-api');

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === 'object') {
    return Object.keys(value).sort().reduce((result, key) => {
      if (value[key] !== undefined) result[key] = stableValue(value[key]);
      return result;
    }, {});
  }
  return value;
}

function stableStringify(value) {
  return JSON.stringify(stableValue(value));
}

function sha256(value) {
  return crypto.createHash('sha256').update(String(value), 'utf8').digest('hex');
}

function canonicalRequestHash(request) {
  return sha256(stableStringify(request));
}

function requireIdempotencyKey(req) {
  const value = String(req.headers['idempotency-key'] || '').trim();
  if (!value) throw new HttpError(400, 'Idempotency-Key is required.', { code: 'IDEMPOTENCY_KEY_REQUIRED' });
  if (value.length > 200 || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new HttpError(400, 'Idempotency-Key must contain 1 to 200 printable characters.', { code: 'IDEMPOTENCY_KEY_INVALID' });
  }
  return value;
}

function requestIdentifiers(req) {
  const clean = (value, prefix) => {
    const candidate = String(value || '').trim();
    if (candidate && /^[A-Za-z0-9._:-]{1,128}$/.test(candidate)) return candidate;
    return `${prefix}_${crypto.randomBytes(16).toString('hex')}`;
  };
  return {
    requestId: clean(req.headers['x-request-id'], 'vt_req'),
    traceId: clean(req.headers['x-trace-id'], 'vt_trace'),
  };
}

module.exports = {
  canonicalRequestHash,
  requestIdentifiers,
  requireIdempotencyKey,
  sha256,
  stableStringify,
};
