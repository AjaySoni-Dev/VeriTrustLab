const { handleStripeWebhook } = require('../../billing');
const {
  handleApiError,
  requireMethod,
  sendJson,
} = require('../../veritrust-api');

module.exports = async function handler(req, res) {
  try {
    requireMethod(req, 'POST');
    const result = await handleStripeWebhook(req);
    sendJson(res, 200, { ok: true, ...result });
  } catch (error) {
    handleApiError(res, error, 'Billing webhook failed.');
  }
};

module.exports.config = {
  api: {
    bodyParser: false,
  },
};
