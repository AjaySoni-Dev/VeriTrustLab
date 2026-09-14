const { createCheckoutSession } = require('../../billing');
const { getProfileContext } = require('../../supabase-server');
const {
  handleApiError,
  handleOptions,
  parseJsonBody,
  requireMethod,
  sendJson,
} = require('../../veritrust-api');
const { validateJsonContentType } = require('../../validators');

module.exports = async function handler(req, res) {
  if (handleOptions(req, res)) return;

  try {
    requireMethod(req, 'POST');
    validateJsonContentType(req);
    const context = await getProfileContext(req);
    const body = await parseJsonBody(req, 4096);
    const checkout = await createCheckoutSession(req, context, {
      plan: body.plan,
      interval: body.interval || 'monthly',
    });
    sendJson(res, 200, { ok: true, checkout });
  } catch (error) {
    handleApiError(res, error, 'Unable to start checkout.');
  }
};
