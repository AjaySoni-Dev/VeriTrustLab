const net = require('node:net');

function env(name, fallback = '') {
  const value = process.env[name];
  return value === undefined || value === null || String(value).trim() === '' ? fallback : String(value).trim();
}

function integer(name, fallback, min, max) {
  const value = Number(env(name, String(fallback)));
  if (!Number.isInteger(value) || value < min || value > max) throw new Error(`${name} must be an integer between ${min} and ${max}.`);
  return value;
}

function boolean(name, fallback = false) {
  const value = env(name, fallback ? 'true' : 'false').toLowerCase();
  if (!['true', 'false', '1', '0', 'yes', 'no'].includes(value)) throw new Error(`${name} must be true or false.`);
  return ['true', '1', 'yes'].includes(value);
}

function csv(name) {
  return env(name, '').split(',').map((value) => value.trim().toLowerCase()).filter(Boolean);
}

function loopbackHost(host) {
  return ['127.0.0.1', '::1', 'localhost'].includes(String(host).toLowerCase());
}

function loadConfig() {
  const baseUrl = env('VERITRUST_API_BASE_URL', 'https://www.veritrustlab.in').replace(/\/$/u, '');
  const parsed = new URL(baseUrl);
  const allowHttp = boolean('VERITRUST_API_ALLOW_HTTP', false);
  if (parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash || (!allowHttp && parsed.protocol !== 'https:') || !['https:', 'http:'].includes(parsed.protocol)) {
    throw new Error('VERITRUST_API_BASE_URL must be a safe HTTPS origin. Use VERITRUST_API_ALLOW_HTTP=true only for local development.');
  }

  const apiKey = env('VERITRUST_API_KEY');
  if (!/^vtg_(?:live|test)_[A-Za-z0-9_-]{20,}$/u.test(apiKey)) throw new Error('VERITRUST_API_KEY is missing or has an invalid format.');
  const receiverSecret = env('VERITRUST_RECEIVER_SECRET');
  if (Buffer.byteLength(receiverSecret, 'utf8') < 32) throw new Error('VERITRUST_RECEIVER_SECRET must be at least 32 bytes.');

  const listenHost = env('VERITRUST_SMTP_LISTEN_HOST', '127.0.0.1');
  const allowedClientIps = new Set(csv('VERITRUST_SMTP_ALLOWED_CLIENT_IPS'));
  for (const clientIp of allowedClientIps) { if (!net.isIP(clientIp)) throw new Error('VERITRUST_SMTP_ALLOWED_CLIENT_IPS must contain only IPv4/IPv6 addresses.'); }
  const requireAuth = boolean('VERITRUST_SMTP_REQUIRE_AUTH', !loopbackHost(listenHost) && allowedClientIps.size === 0);
  const authUsername = env('VERITRUST_SMTP_AUTH_USERNAME');
  const authPassword = env('VERITRUST_SMTP_AUTH_PASSWORD');
  if (requireAuth && (!authUsername || Buffer.byteLength(authPassword, 'utf8') < 12)) throw new Error('SMTP AUTH requires VERITRUST_SMTP_AUTH_USERNAME and a password of at least 12 bytes.');
  if (!loopbackHost(listenHost) && !requireAuth && allowedClientIps.size === 0) throw new Error('A non-loopback listener must require SMTP AUTH or configure VERITRUST_SMTP_ALLOWED_CLIENT_IPS.');

  const allowedRecipients = new Set(csv('VERITRUST_SMTP_ALLOWED_RECIPIENTS'));
  const allowedRecipientDomains = new Set(csv('VERITRUST_SMTP_ALLOWED_RECIPIENT_DOMAINS'));
  const allowAllRecipients = boolean('VERITRUST_SMTP_ALLOW_ALL_RECIPIENTS', false);
  if (!loopbackHost(listenHost) && !allowAllRecipients && !allowedRecipients.size && !allowedRecipientDomains.size) {
    throw new Error('A non-loopback listener requires an explicit recipient allowlist or VERITRUST_SMTP_ALLOW_ALL_RECIPIENTS=true.');
  }

  const startTls = env('VERITRUST_SMTP_UPSTREAM_STARTTLS', 'auto').toLowerCase();
  if (!['off', 'auto', 'required'].includes(startTls)) throw new Error('VERITRUST_SMTP_UPSTREAM_STARTTLS must be off, auto, or required.');
  const forwardActions = new Set(csv('VERITRUST_SMTP_FORWARD_ACTIONS').length ? csv('VERITRUST_SMTP_FORWARD_ACTIONS') : ['allow', 'warn']);
  const deferActions = new Set(csv('VERITRUST_SMTP_DEFER_ACTIONS').length ? csv('VERITRUST_SMTP_DEFER_ACTIONS') : ['manual_review', 'hold']);
  const degradedMode = env('VERITRUST_SMTP_DEGRADED_MODE', 'defer').toLowerCase();
  if (!['policy', 'defer', 'reject'].includes(degradedMode)) throw new Error('VERITRUST_SMTP_DEGRADED_MODE must be policy, defer, or reject.');
  const apiFailureMode = env('VERITRUST_SMTP_API_FAILURE_MODE', 'defer').toLowerCase();
  if (!['defer', 'reject'].includes(apiFailureMode)) throw new Error('VERITRUST_SMTP_API_FAILURE_MODE must be defer or reject.');

  return {
    api: {
      baseUrl,
      apiKey,
      receiverSecret,
      integrationId: env('VERITRUST_INTEGRATION_ID'),
      receiverId: env('VERITRUST_SMTP_RECEIVER_ID', 'veritrust-smtp-gateway'),
      authservId: env('VERITRUST_SMTP_AUTHSERV_ID', 'veritrust-smtp-gateway'),
      timeoutMs: integer('VERITRUST_SMTP_ANALYSIS_TIMEOUT_MS', 90000, 1000, 180000),
    },
    inbound: {
      host: listenHost,
      port: integer('VERITRUST_SMTP_LISTEN_PORT', 2525, 1, 65535),
      hostname: env('VERITRUST_SMTP_RECEIVER_ID', 'veritrust-smtp-gateway'),
      maxMessageBytes: integer('VERITRUST_SMTP_MAX_MESSAGE_BYTES', (10 * 1024 * 1024) - 4096, 1024, (10 * 1024 * 1024) - 4096),
      connectionTimeoutMs: integer('VERITRUST_SMTP_CONNECTION_TIMEOUT_MS', 300000, 10000, 1800000),
      maxConnections: integer('VERITRUST_SMTP_MAX_CONNECTIONS', 100, 1, 1000),
      requireAuth,
      allowedClientIps,
      authUsername,
      authPassword,
      allowAllRecipients,
      allowedRecipients,
      allowedRecipientDomains,
    },
    upstream: {
      host: env('VERITRUST_SMTP_UPSTREAM_HOST'),
      port: integer('VERITRUST_SMTP_UPSTREAM_PORT', 25, 1, 65535),
      secure: boolean('VERITRUST_SMTP_UPSTREAM_SECURE', false),
      startTls,
      username: env('VERITRUST_SMTP_UPSTREAM_USERNAME'),
      password: env('VERITRUST_SMTP_UPSTREAM_PASSWORD'),
      ehloName: env('VERITRUST_SMTP_RECEIVER_ID', 'veritrust-smtp-gateway'),
      tlsServername: env('VERITRUST_SMTP_UPSTREAM_TLS_SERVERNAME'),
      rejectUnauthorized: !boolean('VERITRUST_SMTP_UPSTREAM_ALLOW_INVALID_TLS', false),
      timeoutMs: integer('VERITRUST_SMTP_UPSTREAM_TIMEOUT_MS', 30000, 1000, 120000),
    },
    decisions: {
      forwardActions,
      deferActions,
      degradedMode,
      apiFailureMode,
      addHeaders: boolean('VERITRUST_SMTP_ADD_DECISION_HEADERS', true),
    },
  };
}

function clientAllowed(address, inbound) {
  let normalized = String(address || '').trim().toLowerCase();
  if (normalized.startsWith('::ffff:')) normalized = normalized.slice(7);
  if (!inbound.allowedClientIps || inbound.allowedClientIps.size === 0) return true;
  return inbound.allowedClientIps.has(normalized);
}

function recipientAllowed(address, inbound) {
  const normalized = String(address || '').trim().toLowerCase();
  if (!normalized || /[\r\n]/u.test(normalized)) return false;
  if (inbound.allowAllRecipients) return true;
  if (inbound.allowedRecipients.has(normalized)) return true;
  const at = normalized.lastIndexOf('@');
  const domain = at === -1 ? '' : normalized.slice(at + 1);
  return domain && inbound.allowedRecipientDomains.has(domain);
}

module.exports = { boolean, clientAllowed, csv, env, integer, loadConfig, loopbackHost, recipientAllowed };
