#!/usr/bin/env node
const crypto = require('node:crypto');
const { clientAllowed, loadConfig, recipientAllowed } = require('./config');
const { addDecisionHeaders, addReceivedHeader, normalizeIp, stripSpoofableVeriTrustHeaders } = require('./lib/message');
const { createSmtpServer } = require('./lib/smtp-server');
const { relayMessage, SmtpResponseError } = require('./lib/smtp-client');
const { analyzeTrustedReceiver } = require('./lib/veritrust-client');

function log(level, event, data = {}) {
  process.stdout.write(`${JSON.stringify({ timestamp: new Date().toISOString(), level, service: 'veritrust-smtp-gateway', event, ...data })}\n`);
}

function dispositionForDecision(response, decisions) {
  const decision = response.gateway_decision || {};
  if (decision.degraded && decisions.degradedMode !== 'policy') return decisions.degradedMode;
  const action = String(decision.recommendation || '').toLowerCase();
  if (decisions.forwardActions.has(action)) return 'forward';
  if (decisions.deferActions.has(action)) return 'defer';
  return 'reject';
}

function riskPercent(response) {
  const risk = Number(response?.gateway_decision?.risk);
  return Number.isFinite(risk) ? Math.round(risk * 1000) / 10 : null;
}

function conciseDecision(response) {
  const pct = riskPercent(response);
  return `scan=${response.scan_id} action=${response.gateway_decision.recommendation}${pct === null ? '' : ` risk=${pct}%`}`;
}

function createGateway(config, dependencies = {}) {
  const analyze = dependencies.analyze || analyzeTrustedReceiver;
  const relay = dependencies.relay || relayMessage;
  return createSmtpServer({
    ...config.inbound,
    isClientAllowed: (address) => clientAllowed(address, config.inbound),
    isRecipientAllowed: (address) => recipientAllowed(address, config.inbound),
    onSessionError: (error, session) => log('error', 'smtp.session.error', { session_id: session?.sessionId, error_code: error.code || error.name || 'SMTP_SESSION_ERROR' }),
    onMessage: async (envelope) => {
      const eventId = crypto.randomUUID();
      const clientIp = normalizeIp(envelope.clientIp);
      const receiverEnvelope = { ...envelope, eventId, clientIp, receiverId: config.api.receiverId };
      const receivedRaw = addReceivedHeader(envelope.raw, receiverEnvelope);
      let response;
      try {
        response = await analyze(receivedRaw, receiverEnvelope, config.api);
      } catch (error) {
        log('error', 'mail.analysis.failed', { event_id: eventId, session_id: envelope.sessionId, error_code: error.code || error.name || 'ANALYSIS_FAILED' });
        if (config.decisions.apiFailureMode === 'reject') return { code: 550, enhanced: '5.7.1', message: 'Message rejected because VeriTrust analysis was unavailable' };
        return { code: 451, enhanced: '4.7.1', message: 'Message deferred because VeriTrust analysis was unavailable' };
      }

      const disposition = dispositionForDecision(response, config.decisions);
      log('info', 'mail.analysis.completed', {
        event_id: eventId,
        session_id: envelope.sessionId,
        scan_id: response.scan_id,
        recommendation: response.gateway_decision.recommendation,
        risk: response.gateway_decision.risk,
        degraded: Boolean(response.gateway_decision.degraded),
        disposition,
      });

      if (disposition === 'defer') return { code: 451, enhanced: '4.7.1', message: `Message deferred by VeriTrust policy; ${conciseDecision(response)}` };
      if (disposition === 'reject') return { code: 550, enhanced: '5.7.1', message: `Message rejected by VeriTrust policy; ${conciseDecision(response)}` };

      if (!config.upstream.host) return { code: 451, enhanced: '4.4.0', message: `Message passed VeriTrust but no upstream SMTP server is configured; ${conciseDecision(response)}` };
      let relayRaw = stripSpoofableVeriTrustHeaders(receivedRaw);
      if (config.decisions.addHeaders) relayRaw = addDecisionHeaders(relayRaw, response);
      try {
        await relay(config.upstream, envelope, relayRaw);
        log('info', 'mail.relay.completed', { event_id: eventId, scan_id: response.scan_id, recipient_count: envelope.recipients.length });
        return { code: 250, enhanced: '2.0.0', message: `Message accepted after VeriTrust inspection; ${conciseDecision(response)}` };
      } catch (error) {
        const upstreamCode = error instanceof SmtpResponseError ? error.smtpCode : 0;
        log('error', 'mail.relay.failed', { event_id: eventId, scan_id: response.scan_id, upstream_code: upstreamCode, error_code: error.code || error.name || 'UPSTREAM_RELAY_FAILED' });
        if (upstreamCode >= 500) return { code: 550, enhanced: '5.4.0', message: `Upstream receiver rejected the message after VeriTrust passed it; ${conciseDecision(response)}` };
        return { code: 451, enhanced: '4.4.0', message: `Temporary upstream delivery failure after VeriTrust passed the message; ${conciseDecision(response)}` };
      }
    },
  });
}

async function main() {
  const config = loadConfig();
  const server = createGateway(config);
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(config.inbound.port, config.inbound.host, resolve);
  });
  log('info', 'gateway.started', {
    listen_host: config.inbound.host,
    listen_port: config.inbound.port,
    receiver_id: config.api.receiverId,
    upstream_host: config.upstream.host || null,
    upstream_port: config.upstream.host ? config.upstream.port : null,
    require_auth: config.inbound.requireAuth,
  });

  const shutdown = (signal) => {
    log('info', 'gateway.stopping', { signal });
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 10000).unref?.();
  };
  process.once('SIGINT', () => shutdown('SIGINT'));
  process.once('SIGTERM', () => shutdown('SIGTERM'));
}

if (require.main === module) main().catch((error) => {
  log('error', 'gateway.start.failed', { error_code: error.code || error.name || 'START_FAILED', message: error.message });
  process.exitCode = 1;
});

module.exports = { conciseDecision, createGateway, dispositionForDecision, riskPercent };
