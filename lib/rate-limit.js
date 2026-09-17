const crypto = require('crypto');
const { HttpError, sendJson } = require('./veritrust-api');
const {
  isServiceRoleConfigured,
  supabaseFetch,
} = require('./supabase-server');

const LIMITS = {
  guestDaily: 3,
  freeAuthenticatedDaily: 25,
  unknownPlanDaily: 10,
};

function clientIp(req) {
  const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return forwarded
    || String(req.headers['x-real-ip'] || '').trim()
    || String(req.socket?.remoteAddress || '').trim()
    || 'unknown';
}

function hashIdentity(value) {
  return crypto.createHash('sha256').update(String(value || 'unknown')).digest('hex');
}

function planCodeFromContext(context) {
  const plan = context?.organization?.plans || context?.organization?.plan || null;
  return String(plan?.code || context?.organization?.plan_code || '').toLowerCase();
}

function limitForContext(context) {
  if (!context?.user?.id) return LIMITS.guestDaily;
  const plan = context?.organization?.plans || context?.organization?.plan || null;
  const planCode = planCodeFromContext(context);
  if (planCode === 'free') return LIMITS.freeAuthenticatedDaily;
  if (Number(plan?.daily_scan_limit) > 0) return Number(plan.daily_scan_limit);
  return LIMITS.unknownPlanDaily;
}

async function consumeRateLimit({
  req,
  endpoint,
  context = null,
  limit = null,
  identityType: requestedIdentityType = null,
  identityValue: requestedIdentityValue = null,
}) {
  if (!isServiceRoleConfigured()) {
    throw new HttpError(503, 'Request limits are temporarily unavailable.', { code: 'RATE_LIMIT_UNAVAILABLE' });
  }

  const isUser = Boolean(context?.user?.id);
  const identityType = requestedIdentityType || (isUser ? 'user' : 'ip');
  const identityValue = requestedIdentityValue || (isUser ? context.user.id : clientIp(req));
  const limitCount = Math.max(1, Number(limit || limitForContext(context)));

  let rows;
  try {
    rows = await supabaseFetch('/rest/v1/rpc/consume_api_rate_limit', {
      method: 'POST',
      service: true,
      body: {
        target_identity_type: identityType,
        target_identity_hash: hashIdentity(identityValue),
        target_endpoint: endpoint,
        target_limit_count: limitCount,
        target_metadata: {
          authenticated: isUser,
          plan_code: planCodeFromContext(context) || null,
        },
      },
    });
  } catch (error) {
    const text = `${error?.message || ''} ${JSON.stringify(error?.details || '')}`.toLowerCase();
    const missingRpc = Number(error?.status || 0) === 404
      || text.includes('could not find')
      || text.includes('does not exist')
      || text.includes('schema cache')
      || text.includes('pgrst202');
    if (!missingRpc) throw error;
    throw new HttpError(503, 'Request limits are temporarily unavailable.', { code: 'RATE_LIMIT_UNAVAILABLE' });
  }

  const result = Array.isArray(rows) ? rows[0] : rows;
  if (!result) {
    throw new HttpError(500, 'Rate limit check failed.', { code: 'RATE_LIMIT_UNAVAILABLE' });
  }

  return {
    allowed: Boolean(result.allowed),
    limit: Number(result.limit_count || limitCount),
    remaining: Math.max(0, Number(result.remaining || 0)),
    resetAt: result.reset_at || null,
    count: Number(result.request_count || 0),
  };
}

async function enforceRateLimit(options) {
  const result = await consumeRateLimit(options);
  if (result.allowed) return result;

  throw new HttpError(429, 'Daily request limit reached. Please try again tomorrow.', {
    code: 'RATE_LIMIT_EXCEEDED',
    meta: {
      limit: result.limit,
      remaining: 0,
      reset_at: result.resetAt,
    },
  });
}

function sendRateLimitError(res, error) {
  sendJson(res, 429, {
    ok: false,
    error: {
      code: error.code || 'RATE_LIMIT_EXCEEDED',
      message: error.message || 'Daily request limit reached. Please try again tomorrow.',
    },
    ...(error.extra?.meta ? { rate_limit: error.extra.meta } : {}),
  });
}

module.exports = {
  LIMITS,
  clientIp,
  consumeRateLimit,
  enforceRateLimit,
  sendRateLimitError,
};
