const { serverConfig } = require('../../lib/config');
const { decryptSecret } = require('../../lib/gateway/secrets');
const { assertPublicWebhookDestination, signWebhook } = require('../../lib/gateway/webhooks');
const { recordWebhookAttempt, webhookDelivery } = require('../../lib/gateway/worker-store');

module.exports = async function handleWebhook(job) {
  const delivery = await webhookDelivery(job.payload?.event_id);
  if (!delivery?.event || !delivery.endpoint || !delivery.secret || delivery.endpoint.status !== 'active') {
    if (delivery?.event) await recordWebhookAttempt(delivery.event.id, { outcome: 'failed', errorCode: 'WEBHOOK_CONFIGURATION_MISSING' });
    return;
  }
  const endpoint = delivery.endpoint;
  const url = await assertPublicWebhookDestination(endpoint.url);
  const rawBody = JSON.stringify(delivery.event.payload);
  const timestamp = Math.floor(Date.now() / 1000);
  const secret = decryptSecret(delivery.secret, serverConfig.gatewayWebhookEncryptionKey);
  const started = Date.now();
  let response;
  try {
    response = await fetch(url, {
      method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(endpoint.timeout_ms),
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'VeriTrust-Gateway/1.0',
        'X-VeriTrust-Event-Id': delivery.event.id,
        'X-VeriTrust-Schema-Version': delivery.event.schema_version,
        'X-VeriTrust-Timestamp': String(timestamp),
        'X-VeriTrust-Signature': signWebhook(secret, timestamp, rawBody),
      },
      body: rawBody,
    });
  } catch (cause) {
    const error = new Error('Webhook delivery failed.');
    error.code = cause.name === 'TimeoutError' ? 'WEBHOOK_TIMEOUT' : 'WEBHOOK_NETWORK_ERROR';
    error.retrySeconds = Math.min(3600, 2 ** Math.min(10, Number(job.attempt_count || 1)));
    await recordWebhookAttempt(delivery.event.id, { outcome: 'retry', latencyMs: Date.now() - started, retryAt: new Date(Date.now() + error.retrySeconds * 1000).toISOString(), errorCode: error.code });
    throw error;
  }
  response.body?.cancel().catch(() => null);
  const latencyMs = Date.now() - started;
  if (response.status >= 200 && response.status < 300) {
    await recordWebhookAttempt(delivery.event.id, { outcome: 'delivered', responseCode: response.status, latencyMs });
    return;
  }
  if ([408, 425, 429].includes(response.status) || response.status >= 500) {
    const error = new Error('Webhook destination returned a transient status.');
    error.code = 'WEBHOOK_TRANSIENT_STATUS';
    error.retrySeconds = Math.min(3600, 2 ** Math.min(10, Number(job.attempt_count || 1)));
    await recordWebhookAttempt(delivery.event.id, { outcome: 'retry', responseCode: response.status, latencyMs, retryAt: new Date(Date.now() + error.retrySeconds * 1000).toISOString(), errorCode: error.code });
    throw error;
  }
  await recordWebhookAttempt(delivery.event.id, { outcome: 'failed', responseCode: response.status, latencyMs, errorCode: 'WEBHOOK_TERMINAL_STATUS' });
};
