const crypto = require('node:crypto');
const { ConfigError, getOptionalEnv, serverConfig } = require('./config');
const {
  ALLOWED_IMAGE_TYPES,
  MAX_IMAGE_BYTES,
} = require('./validators');

const DEEPFAKE_MODELS = {
  pixel: {
    key: 'pixel',
    display_name: 'VeriTrust Pixel',
    model_path_key: 'deepfake_pixel',
    provider: 'hf-inference',
  },
  prism: {
    key: 'prism',
    display_name: 'VeriTrust Prism',
    model_path_key: 'deepfake_prism',
    provider: 'hf-inference',
  },
};

const PHISHING_MODELS = {
  mailguard: {
    key: 'mailguard',
    display_name: 'VeriTrust MailGuard',
    model_path_key: 'phishing_mailguard',
    provider: 'hf-inference',
  },
  cortex: {
    key: 'cortex',
    display_name: 'VeriTrust Cortex',
    model_path_key: 'phishing_cortex',
    provider: 'featherless-ai',
  },
};

class HttpError extends Error {
  constructor(status, message, extra = {}) {
    super(message);
    this.status = status;
    this.code = extra.code;
    this.extra = extra;
  }
}

function sendJson(res, status, payload) {
  if (res.analysisStream?.started) {
    const safe = JSON.parse(JSON.stringify(payload, (key, value) => {
      if (['hf_model', 'hfmodel', 'model_path', 'modelpath', 'provider_model', 'providermodel'].includes(String(key).toLowerCase())) return undefined;
      return value;
    }));
    res.analysisStream.finish(status, safe);
    return;
  }
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Pragma', 'no-cache');
  res.end(JSON.stringify(payload, (key, value) => {
    if (['hf_model', 'hfmodel', 'model_path', 'modelpath', 'provider_model', 'providermodel'].includes(String(key).toLowerCase())) return undefined;
    return value;
  }));
}

function normalizeOrigin(origin) {
  try {
    const parsed = new URL(String(origin || '').trim());
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) return '';
    return parsed.origin;
  } catch {
    return '';
  }
}

function requestOrigin(req) {
  const proto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim()
    || (req.headers['x-forwarded-ssl'] === 'on' ? 'https' : 'http');
  const host = String(req.headers['x-forwarded-host'] || req.headers.host || '').split(',')[0].trim();
  return host ? `${proto}://${host}` : '';
}

function isAllowedOrigin(req, origin) {
  if (!origin) return true;
  const normalized = normalizeOrigin(origin);
  if (!normalized) return false;
  if (normalized === normalizeOrigin(requestOrigin(req))) return true;

  const allowed = serverConfig.allowedOrigins.map(normalizeOrigin).filter(Boolean);
  return allowed.includes(normalized);
}

function applyCors(req, res) {
  const origin = req.headers.origin;
  if (origin) {
    if (!isAllowedOrigin(req, origin)) {
      return false;
    }
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type, Idempotency-Key, Prefer, X-Requested-With, X-Request-Id, X-Trace-Id, X-VeriTrust-Signature, X-VeriTrust-Timestamp, X-VeriTrust-Parent-Scan-Id');
  return true;
}

function handleOptions(req, res) {
  if (!applyCors(req, res)) {
    sendJson(res, 403, {
      ok: false,
      error: {
        code: 'CORS_ORIGIN_DENIED',
        message: 'This origin is not allowed to access the VeriTrust API.',
      },
    });
    return true;
  }

  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    res.end();
    return true;
  }
  return false;
}

function requireMethod(req, method) {
  if (req.method !== method) {
    throw new HttpError(405, `Use ${method} for this endpoint.`);
  }
}

function statusCodeForError(error) {
  const status = Number(error.status || 500);
  if (status < 400 || status > 599) return 500;
  return status;
}

function codeForError(error, status) {
  if (error instanceof ConfigError) return 'SERVER_CONFIG_ERROR';
  if (error.code) return String(error.code);
  if (status === 400) return 'BAD_REQUEST';
  if (status === 401) return 'UNAUTHORIZED';
  if (status === 403) return 'FORBIDDEN';
  if (status === 404) return 'NOT_FOUND';
  if (status === 405) return 'METHOD_NOT_ALLOWED';
  if (status === 413) return 'PAYLOAD_TOO_LARGE';
  if (status === 415) return 'UNSUPPORTED_MEDIA_TYPE';
  if (status === 429) return 'RATE_LIMIT_EXCEEDED';
  if (status === 502) return 'UPSTREAM_ERROR';
  return 'INTERNAL_ERROR';
}

function messageForError(error, status, fallback) {
  if (error instanceof ConfigError || error.code === 'SERVER_CONFIG_ERROR') {
    return 'Server configuration is incomplete.';
  }
  if (error.name === 'SupabaseError' && error.details !== null) {
    if (status === 401) return 'Sign in to continue.';
    if (status === 403) return 'You do not have access to this resource.';
    if (status === 404) return 'Requested resource was not found.';
    return fallback || 'Request failed.';
  }
  if (status >= 500 && status !== 502) return fallback || 'Request failed.';

  const rawMessage = String(error.message || fallback);
  return rawMessage.includes('timed out')
    ? 'The analysis service took too long to respond. Please try again.'
    : rawMessage;
}

function logApiError(error, status, code) {
  if (status < 500 && code !== 'RATE_LIMIT_EXCEEDED') return;
  console.error('VeriTrust API error', {
    code,
    status,
    name: error?.name,
    env: error instanceof ConfigError ? error.envName : undefined,
    upstreamStatus: error?.extra?.status,
    message: error?.message,
  });
}

function handleApiError(res, error, fallback = 'Request failed.') {
  const status = statusCodeForError(error);
  const code = codeForError(error, status);
  const message = messageForError(error, status, fallback);
  logApiError(error, status, code);

  sendJson(res, status, {
    ok: false,
    error: {
      code,
      message,
    },
    ...(error.extra?.meta ? { meta: error.extra.meta } : {}),
  });
}

function findHfToken() {
  const token = getOptionalEnv('HF_TOKEN') || getOptionalEnv('HF_ACCESS_TOKEN');
  return token && token.trim() ? token.trim() : null;
}

function readHfToken() {
  return serverConfig.hfToken;
}

function contains(haystack, needle) {
  return String(haystack).includes(needle);
}

function clamp01(value) {
  return Math.max(0, Math.min(1, Number(value) || 0));
}

function scoreItem(label, score) {
  return { label, score: clamp01(score) };
}

function constantTimeEqual(leftValue, rightValue) {
  const left = Buffer.from(String(leftValue || ''), 'utf8');
  const right = Buffer.from(String(rightValue || ''), 'utf8');
  if (!left.length || left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function modelPathFor(model) {
  if (!model?.model_path_key) throw new ConfigError('HF model mapping', { invalid: true });
  return serverConfig.modelPath(model.model_path_key);
}

function encodeModelId(modelId) {
  return modelId.split('/').map(encodeURIComponent).join('/');
}

function hfModelUrls(provider, modelId) {
  const encodedModel = encodeModelId(modelId);
  return [`https://router.huggingface.co/${provider}/models/${encodedModel}`];
}

const hfAvailabilityCache = new Map();

async function assertHfModelAvailable(provider, modelId, contract, timeoutMs = 5000) {
  if (!contract?.revision_sha) return;
  const cacheKey = `${provider}:${modelId}:${contract.revision_sha}:${contract.task || ''}`;
  const cached = hfAvailabilityCache.get(cacheKey);
  if (cached?.expiresAt > Date.now()) return;
  if (cached?.promise) return cached.promise;

  const promise = (async () => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), Math.max(1000, Math.min(timeoutMs, 10000)));
    try {
      const response = await fetch(`https://huggingface.co/api/models/${encodeModelId(modelId)}?expand=sha&expand=inferenceProviderMapping`, {
        headers: { Authorization: `Bearer ${readHfToken()}`, Accept: 'application/json' },
        signal: controller.signal,
      });
      if ([401, 403].includes(response.status)) {
        throw new HttpError(503, 'Hugging Face authorization failed.', { code: 'HF_AUTH_FAILED', status: response.status });
      }
      if (response.status === 404) {
        throw new HttpError(503, 'The configured Hugging Face model was not found.', { code: 'HF_MODEL_NOT_FOUND', status: response.status });
      }
      if (!response.ok) {
        throw new HttpError(503, 'Hugging Face model metadata is unavailable.', { code: response.status === 429 ? 'HF_RATE_LIMITED' : 'HF_METADATA_UNAVAILABLE', status: response.status });
      }
      const metadata = await response.json();
      if (String(metadata.sha || '').toLowerCase() !== String(contract.revision_sha).toLowerCase()) {
        throw new HttpError(503, 'The configured Hugging Face model has moved beyond the qualified revision.', { code: 'HF_MODEL_REVISION_DRIFT' });
      }
      const mapping = metadata.inferenceProviderMapping?.[provider];
      if (!mapping || mapping.status !== 'live') {
        throw new HttpError(503, 'The configured model is not live on the selected Hugging Face provider.', { code: 'HF_MODEL_PROVIDER_UNAVAILABLE' });
      }
      if (contract.task && mapping.task !== contract.task) {
        throw new HttpError(503, 'The Hugging Face provider task does not match the model contract.', { code: 'HF_MODEL_TASK_MISMATCH' });
      }
      hfAvailabilityCache.set(cacheKey, { expiresAt: Date.now() + 5 * 60 * 1000 });
    } catch (error) {
      hfAvailabilityCache.delete(cacheKey);
      if (error instanceof HttpError) throw error;
      throw new HttpError(503, 'Hugging Face model metadata could not be verified.', {
        code: error.name === 'AbortError' ? 'HF_METADATA_TIMEOUT' : 'HF_METADATA_UNAVAILABLE',
      });
    } finally {
      clearTimeout(timer);
    }
  })();
  hfAvailabilityCache.set(cacheKey, { promise });
  return promise;
}

async function hfRequest(url, headers, body, timeoutMs = 20000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers,
      body,
      signal: controller.signal,
    });
    const maximumResponseBytes = 2 * 1024 * 1024;
    const contentLength = Number(response.headers.get('content-length') || 0);
    if (contentLength > maximumResponseBytes) throw new Error('Inference response exceeded the size limit.');
    const reader = response.body?.getReader();
    const chunks = [];
    let total = 0;
    if (reader) {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > maximumResponseBytes) {
          await reader.cancel();
          throw new Error('Inference response exceeded the size limit.');
        }
        chunks.push(Buffer.from(value));
      }
    }
    const raw = reader ? Buffer.concat(chunks, total).toString('utf8') : '';
    let json = null;
    try {
      json = raw ? JSON.parse(raw) : null;
    } catch {
      json = null;
    }

    return {
      ok: response.ok,
      status: response.status,
      raw,
      json,
      error: null,
      retryAfterMs: Math.max(0, Number(response.headers.get('retry-after') || 0) * 1000),
    };
  } catch (error) {
    return {
      ok: false,
      status: 0,
      raw: '',
      json: null,
      error: error.name === 'AbortError' ? 'Hugging Face request timed out.' : error.message,
    };
  } finally {
    clearTimeout(timer);
  }
}

function retryableHfResult(result) {
  return !result?.ok && (!result?.status || [408, 425, 429, 500, 502, 503, 504].includes(result.status));
}

async function hfRequestWithRetry(url, headers, body, timeoutMs = 20000) {
  const deadline = Date.now() + Math.max(1000, timeoutMs);
  let last = null;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    const remaining = deadline - Date.now();
    if (remaining < 1000) break;
    last = await hfRequest(url, headers, body, remaining);
    if (!retryableHfResult(last) || attempt === 3) return last;
    const delay = Math.min(1500, Math.max(last.retryAfterMs || 0, 150 * (2 ** (attempt - 1))));
    if (deadline - Date.now() <= delay + 1000) return last;
    await new Promise((resolve) => setTimeout(resolve, delay));
  }
  return last || { ok: false, status: 0, json: null, raw: '', error: 'Inference deadline expired.' };
}

async function hfBinaryInference(provider, modelId, buffer, mimeType, timeoutMs = 20000) {
  const token = readHfToken();
  const headers = {
    Authorization: `Bearer ${token}`,
    Accept: 'application/json',
    'Content-Type': mimeType,
    'X-Wait-For-Model': 'true',
  };

  const urls = hfModelUrls(provider, modelId);
  const attemptTimeoutMs = Math.max(1000, Math.floor(timeoutMs / urls.length));
  let last = null;
  for (const url of urls) {
    const result = await hfRequestWithRetry(url, headers, buffer, attemptTimeoutMs);
    if (result.ok) return result;
    last = result;
  }
  return last || { ok: false, status: 0, json: null, raw: '', error: 'No endpoint attempted.' };
}

async function hfJsonInference(provider, modelId, payload, timeoutMs = 20000, contract = null) {
  const token = readHfToken();
  const started = Date.now();
  await assertHfModelAvailable(provider, modelId, contract, Math.min(4000, Math.floor(timeoutMs / 4)));
  const headers = {
    Authorization: `Bearer ${token}`,
    Accept: 'application/json',
    'Content-Type': 'application/json',
    'X-Wait-For-Model': 'true',
  };
  const body = JSON.stringify(payload);

  const urls = hfModelUrls(provider, modelId);
  const remainingMs = Math.max(1000, timeoutMs - (Date.now() - started));
  const attemptTimeoutMs = Math.max(1000, Math.floor(remainingMs / urls.length));
  let last = null;
  for (const url of urls) {
    const result = await hfRequestWithRetry(url, headers, body, attemptTimeoutMs);
    if (result.ok) return result;
    last = result;
  }
  return last || { ok: false, status: 0, json: null, raw: '', error: 'No endpoint attempted.' };
}

async function hfChatCompletion(modelId, messages, timeoutMs = 20000) {
  const token = readHfToken();
  return hfRequest(
    'https://router.huggingface.co/featherless-ai/v1/chat/completions',
    {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
    JSON.stringify({
      model: modelId,
      messages,
      temperature: 0,
      max_tokens: 128,
    }),
    timeoutMs
  );
}

function flattenScores(raw) {
  if (!raw || typeof raw !== 'object') return [];
  if (raw.error) return [];
  if (Array.isArray(raw) && Array.isArray(raw[0]) && raw[0][0] && typeof raw[0][0] === 'object') {
    return raw[0];
  }
  if (Array.isArray(raw) && raw[0] && Object.prototype.hasOwnProperty.call(raw[0], 'label')) {
    return raw;
  }
  return [];
}

function readRawBody(req, maxBytes = 64000) {
  if (req.body && typeof req.body === 'object') {
    return Promise.resolve(req.body);
  }
  if (typeof req.body === 'string') {
    return Promise.resolve(req.body);
  }

  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > maxBytes) {
        reject(new HttpError(413, 'Request payload is too large.'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

async function parseJsonBody(req, maxBytes = 64000) {
  const body = await readRawBody(req, maxBytes);
  if (!body) return {};
  if (typeof body === 'object') {
    if (Buffer.byteLength(JSON.stringify(body), 'utf8') > maxBytes) {
      throw new HttpError(413, 'Request payload is too large.');
    }
    return body;
  }

  const contentType = String(req.headers['content-type'] || '').toLowerCase();
  if (contentType.includes('application/x-www-form-urlencoded')) {
    return Object.fromEntries(new URLSearchParams(body));
  }

  try {
    return JSON.parse(body);
  } catch {
    throw new HttpError(400, 'Request body must be valid JSON.', { code: 'INVALID_INPUT' });
  }
}

function parseMultipart(req, options = {}) {
  const {
    fileField = 'image',
    maxFileBytes = MAX_IMAGE_BYTES,
    allowedTypes = ALLOWED_IMAGE_TYPES,
  } = options;

  return new Promise((resolve, reject) => {
    let busboy;
    try {
      const Busboy = require('busboy');
      busboy = Busboy({
        headers: req.headers,
        limits: {
          fields: 20,
          fileSize: maxFileBytes,
          files: 1,
        },
      });
    } catch {
      reject(new HttpError(400, 'Request must be multipart/form-data.'));
      return;
    }

    const fields = {};
    const files = {};
    let fileTooLarge = false;
    let parseFailed = false;

    busboy.on('field', (name, value) => {
      fields[name] = value;
    });

    busboy.on('file', (name, file, info) => {
      const { filename, mimeType } = info;
      const chunks = [];
      let size = 0;

      if (name !== fileField) {
        file.resume();
        return;
      }

      if (!allowedTypes.has(mimeType)) {
        parseFailed = true;
        file.resume();
        reject(new HttpError(400, 'Unsupported image type. Use JPG, PNG, WEBP, or BMP.'));
        return;
      }

      file.on('data', (chunk) => {
        size += chunk.length;
        chunks.push(chunk);
      });
      file.on('limit', () => {
        fileTooLarge = true;
        file.resume();
      });
      file.on('end', () => {
        if (!fileTooLarge && !parseFailed) {
          files[name] = {
            buffer: Buffer.concat(chunks),
            filename: filename || 'uploaded-image',
            mimeType,
            size,
          };
        }
      });
    });

    busboy.on('finish', () => {
      if (parseFailed) return;
      if (fileTooLarge) {
        reject(new HttpError(413, 'Image must be 4 MB or smaller for Vercel inference.'));
        return;
      }
      resolve({ fields, files });
    });

    busboy.on('error', (error) => reject(new HttpError(400, error.message)));
    req.pipe(busboy);
  });
}

module.exports = {
  ALLOWED_IMAGE_TYPES,
  DEEPFAKE_MODELS,
  MAX_IMAGE_BYTES,
  PHISHING_MODELS,
  HttpError,
  clamp01,
  constantTimeEqual,
  contains,
  findHfToken,
  flattenScores,
  assertHfModelAvailable,
  handleApiError,
  handleOptions,
  hfBinaryInference,
  hfChatCompletion,
  hfJsonInference,
  modelPathFor,
  parseJsonBody,
  parseMultipart,
  requireMethod,
  scoreItem,
  sendJson,
};
