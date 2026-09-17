const {
  externalApiError,
  recordApiUsage,
  requestId,
  requireApiKey,
} = require('../../api-keys');
const { applyEntitlementHeaders } = require('../../entitlements');
const {
  handleOptions,
  requireMethod,
  sendJson,
} = require('../../veritrust-api');

module.exports = async function handler(req, res) {
  if (handleOptions(req, res)) return;
  const request_id = requestId(req);
  let auth = null;

  try {
    requireMethod(req, 'GET');
    auth = await requireApiKey(req, 'usage:read');
    applyEntitlementHeaders(res, auth.entitlement);
    const usage = await recordApiUsage(auth, {
      endpoint: '/api/v1/usage',
      status: 'success',
      request_id,
      latency_ms: 0,
    });

    sendJson(res, 200, {
      ok: true,
      request_id,
      usage: usage || auth.usage,
      billing: auth.entitlement || null,
      api_key: {
        name: auth.public.name,
        masked_key: auth.public.masked_key,
        status: auth.public.status,
        last_used_at: auth.public.last_used_at,
      },
    });
  } catch (error) {
    externalApiError(res, error, 'Unable to load API usage.', request_id);
  }
};
