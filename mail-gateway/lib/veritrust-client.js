const crypto = require('node:crypto');

function headerSafe(value, name, max = 512) {
  const text = String(value ?? '').trim();
  if (/[\r\n\u0000-\u001f\u007f]/u.test(text) || text.length > max) throw new Error(`${name} is not safe for an HTTP header.`);
  return text;
}

function assertDecision(body) {
  if (!body || body.ok !== true || !body.scan_id || !body.gateway_decision || !body.evidence) {
    throw new Error('VeriTrust returned an incomplete trusted-receiver decision.');
  }
  const action = String(body.gateway_decision.recommendation || '');
  if (!['allow', 'warn', 'manual_review', 'hold', 'quarantine', 'block'].includes(action)) {
    throw new Error('VeriTrust returned an unsupported Gateway recommendation.');
  }
  return body;
}

async function analyzeTrustedReceiver(raw, envelope, config) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.timeoutMs);
  timer.unref?.();
  const eventId = envelope.eventId || crypto.randomUUID();
  const headers = {
    Authorization: `Bearer ${config.apiKey}`,
    'Content-Type': 'message/rfc822',
    'Idempotency-Key': `smtp-${eventId}`,
    'X-VeriTrust-Receiver-Secret': config.receiverSecret,
    'X-VeriTrust-Client-IP': headerSafe(envelope.clientIp, 'client IP', 64),
    'X-VeriTrust-Mail-From': headerSafe(envelope.mailFrom || '<>', 'MAIL FROM', 320) || '<>',
    'X-VeriTrust-Helo': headerSafe(envelope.helo, 'HELO', 255),
    'X-VeriTrust-Receiver-Id': headerSafe(config.receiverId, 'receiver ID', 255),
    'X-VeriTrust-Authserv-Id': headerSafe(config.authservId, 'authserv ID', 255),
    'X-VeriTrust-Received-At': headerSafe(envelope.receivedAt, 'received timestamp', 64),
    'X-VeriTrust-Receiver-Event-Id': headerSafe(eventId, 'receiver event ID', 200),
  };
  if (config.integrationId) headers['X-VeriTrust-Integration-Id'] = headerSafe(config.integrationId, 'integration ID', 64);

  try {
    const response = await fetch(`${config.baseUrl}/internal/v2/phishing/receiver-eml`, {
      method: 'POST',
      headers,
      body: raw,
      redirect: 'error',
      signal: controller.signal,
    });
    const text = await response.text();
    let body;
    try { body = text ? JSON.parse(text) : null; } catch { body = null; }
    if (!response.ok) {
      const code = body?.error?.code || `HTTP_${response.status}`;
      const message = body?.error?.message || 'VeriTrust trusted-receiver API rejected the message.';
      const error = new Error(`${code}: ${message}`);
      error.code = code;
      error.status = response.status;
      throw error;
    }
    return assertDecision(body);
  } catch (error) {
    if (error.name === 'AbortError') {
      const timeout = new Error('VeriTrust trusted-receiver analysis timed out.');
      timeout.code = 'VERITRUST_ANALYSIS_TIMEOUT';
      throw timeout;
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

module.exports = { analyzeTrustedReceiver, assertDecision, headerSafe };
