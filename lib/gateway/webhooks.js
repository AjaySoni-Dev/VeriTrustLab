const crypto = require('crypto');
const dns = require('node:dns').promises;
const net = require('node:net');
const { getOptionalEnv } = require('../config');

function webhookError(code, message) {
  const error = new Error(message);
  error.status = 400;
  error.code = code;
  return error;
}

function webhookAllowedHosts() {
  return getOptionalEnv('VERITRUST_WEBHOOK_ALLOWED_HOSTS', '')
    .split(',')
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean);
}

function hostMatchesPattern(hostname, pattern) {
  if (pattern.startsWith('*.')) {
    const suffix = pattern.slice(1);
    return hostname.endsWith(suffix) && hostname.length > suffix.length;
  }
  return hostname === pattern;
}

function assertAllowedWebhookHost(hostname) {
  const allowedHosts = webhookAllowedHosts();
  if (!allowedHosts.length) {
    if (process.env.NODE_ENV === 'production' || process.env.VERCEL) {
      const error = webhookError('WEBHOOK_ALLOWLIST_MISSING', 'Webhook delivery is disabled until an allowed-host list is configured.');
      error.status = 503;
      throw error;
    }
    return;
  }
  if (!allowedHosts.some((pattern) => hostMatchesPattern(hostname, pattern))) {
    throw webhookError('WEBHOOK_HOST_NOT_ALLOWED', 'Webhook destination is not on the configured allowed-host list.');
  }
}

function validateSecret(secret) {
  const value = String(secret || '');
  if (Buffer.byteLength(value, 'utf8') < 32) throw webhookError('WEBHOOK_SECRET_INVALID', 'Webhook signing secrets must contain at least 32 bytes.');
  return value;
}

function signaturePayload(timestamp, rawBody) {
  if (!Number.isInteger(Number(timestamp)) || Number(timestamp) <= 0) throw webhookError('WEBHOOK_TIMESTAMP_INVALID', 'Webhook timestamp is invalid.');
  const body = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(String(rawBody || ''), 'utf8');
  return Buffer.concat([Buffer.from(`${Number(timestamp)}.`, 'utf8'), body]);
}

function signWebhook(secret, timestamp, rawBody) {
  return `v1=${crypto.createHmac('sha256', validateSecret(secret)).update(signaturePayload(timestamp, rawBody)).digest('hex')}`;
}

function verifyWebhook(options) {
  const now = Number(options.nowSeconds || Math.floor(Date.now() / 1000));
  const timestamp = Number(options.timestamp);
  const replayWindow = Math.max(30, Math.min(3600, Number(options.replayWindowSeconds || 300)));
  if (!Number.isInteger(timestamp) || Math.abs(now - timestamp) > replayWindow) return { valid: false, code: 'WEBHOOK_REPLAY_WINDOW_EXCEEDED' };
  let expected;
  try {
    expected = signWebhook(options.secret, timestamp, options.rawBody);
  } catch (error) {
    return { valid: false, code: error.code || 'WEBHOOK_SIGNATURE_INVALID' };
  }
  const actual = String(options.signature || '');
  const expectedBuffer = Buffer.from(expected, 'utf8');
  const actualBuffer = Buffer.from(actual, 'utf8');
  if (expectedBuffer.length !== actualBuffer.length) return { valid: false, code: 'WEBHOOK_SIGNATURE_INVALID' };
  return crypto.timingSafeEqual(expectedBuffer, actualBuffer)
    ? { valid: true, code: 'OK' }
    : { valid: false, code: 'WEBHOOK_SIGNATURE_INVALID' };
}

function validateWebhookUrl(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw webhookError('WEBHOOK_URL_INVALID', 'Webhook URL is invalid.');
  }
  if (parsed.protocol !== 'https:') throw webhookError('WEBHOOK_HTTPS_REQUIRED', 'Production webhook URLs must use HTTPS.');
  if (parsed.username || parsed.password) throw webhookError('WEBHOOK_URL_CREDENTIALS_DENIED', 'Webhook URLs cannot contain embedded credentials.');
  if (parsed.port && parsed.port !== '443') throw webhookError('WEBHOOK_PORT_DENIED', 'Webhook URLs must use the standard HTTPS port.');
  const hostname = parsed.hostname.toLowerCase();
  if (net.isIP(hostname)) throw webhookError('WEBHOOK_IP_LITERAL_DENIED', 'Webhook URLs must use an allowlisted DNS hostname.');
  if (hostname === 'localhost' || hostname.endsWith('.localhost') || hostname.endsWith('.local')) {
    throw webhookError('WEBHOOK_DESTINATION_DENIED', 'Local webhook destinations are not allowed.');
  }
  assertAllowedWebhookHost(hostname);
  return parsed.toString();
}

function isPrivateAddress(address) {
  if (net.isIPv4(address)) {
    const parts = address.split('.').map(Number);
    return parts[0] === 10 || parts[0] === 127 || parts[0] === 0
      || (parts[0] === 169 && parts[1] === 254)
      || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31)
      || (parts[0] === 192 && parts[1] === 168)
      || (parts[0] === 192 && parts[1] === 0)
      || (parts[0] === 192 && parts[1] === 2)
      || (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127)
      || (parts[0] === 198 && (parts[1] === 18 || parts[1] === 19))
      || (parts[0] === 198 && parts[1] === 51 && parts[2] === 100)
      || (parts[0] === 203 && parts[1] === 0 && parts[2] === 113)
      || parts[0] >= 224;
  }
  const value = address.toLowerCase();
  const mapped = value.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPrivateAddress(mapped[1]);
  return value === '::1' || value === '::' || value.startsWith('fc') || value.startsWith('fd')
    || value.startsWith('fe8') || value.startsWith('fe9') || value.startsWith('fea') || value.startsWith('feb')
    || value.startsWith('ff') || value.startsWith('2001:db8:') || value.startsWith('100:');
}

async function assertPublicWebhookDestination(value) {
  const validated = validateWebhookUrl(value);
  const parsed = new URL(validated);
  const addresses = await dns.lookup(parsed.hostname, { all: true, verbatim: true });
  if (!addresses.length || addresses.some((entry) => isPrivateAddress(entry.address))) {
    throw webhookError('WEBHOOK_DESTINATION_DENIED', 'Webhook destination resolves to a non-public address.');
  }
  return validated;
}

module.exports = {
  assertPublicWebhookDestination,
  assertAllowedWebhookHost,
  hostMatchesPattern,
  isPrivateAddress,
  signWebhook,
  validateWebhookUrl,
  verifyWebhook,
};
