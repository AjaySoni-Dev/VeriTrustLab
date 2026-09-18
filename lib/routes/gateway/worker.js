// Private route implementation; api/gateway.js is the Vercel entrypoint.
const crypto = require('crypto');
const { serverConfig } = require('../../config');
const logger = require('../../gateway/logging');
const { hasDispatchSignatureHeaders, parseDispatchPayload, verifyDispatchSignature } = require('../../gateway/worker-auth');
const { tick } = require('../../../worker');

function send(res, status, body) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(body));
}

module.exports = async function handler(req, res) {
  const requestId = String(req.headers['x-vercel-id'] || crypto.randomUUID()).slice(0, 160);
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    send(res, 405, { ok: false, request_id: requestId, error: { code: 'METHOD_NOT_ALLOWED', message: 'Use POST for this endpoint.' } });
    return;
  }
  if (!hasDispatchSignatureHeaders(req)) {
    logger.warn('gateway.serverless.unsigned', { request_id: requestId });
    send(res, 401, { ok: false, request_id: requestId, error: { code: 'UNAUTHORIZED', message: 'Worker authorization failed.' } });
    return;
  }

  let expectedSecret;
  try {
    expectedSecret = serverConfig.gatewayDispatchSecret;
  } catch (error) {
    logger.error('gateway.serverless.config_missing', { request_id: requestId, error_code: error.code || 'CONFIG_MISSING' });
    send(res, 503, { ok: false, request_id: requestId, error: { code: 'WORKER_NOT_CONFIGURED', message: 'The gateway worker is not configured.' } });
    return;
  }
  try {
    const dispatch = parseDispatchPayload(req.body);
    if (!verifyDispatchSignature(req, expectedSecret, dispatch)) {
      logger.warn('gateway.serverless.unauthorized', { request_id: requestId });
      send(res, 401, { ok: false, request_id: requestId, error: { code: 'UNAUTHORIZED', message: 'Worker authorization failed.' } });
      return;
    }
    const report = await tick({
      workerId: `vercel:${process.env.VERCEL_REGION || 'unknown'}:${requestId}`,
      queues: dispatch.queue || undefined,
      limit: serverConfig.gatewayServerlessBatch,
      visibilitySeconds: 240,
      maintenance: dispatch.source !== 'job_insert',
      report: true,
    });
    logger.info('gateway.serverless.completed', {
      request_id: requestId,
      source: dispatch.source,
      queue: dispatch.queue,
      job_id: dispatch.jobId,
      processed: report.processed,
    });
    send(res, 200, { ok: true, request_id: requestId, source: dispatch.source, report });
  } catch (error) {
    const clientError = ['PAYLOAD_TOO_LARGE', 'INVALID_JSON', 'INVALID_PAYLOAD', 'INVALID_SOURCE', 'INVALID_QUEUE', 'INVALID_JOB_ID'].includes(error.code);
    logger.error('gateway.serverless.failed', { request_id: requestId, error_code: error.code || 'WORKER_TICK_FAILED' });
    send(res, clientError ? 400 : 500, {
      ok: false,
      request_id: requestId,
      error: {
        code: clientError ? error.code : 'WORKER_TICK_FAILED',
        message: clientError ? error.message : 'The worker invocation failed safely and will be retried.',
      },
    });
  }
};
