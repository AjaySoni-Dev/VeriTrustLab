const { createPortalSession } = require('../../billing');
const { getProfileContext } = require('../../supabase-server');
const {
  handleApiError,
  handleOptions,
  requireMethod,
  sendJson,
} = require('../../veritrust-api');

module.exports = async function handler(req, res) {
  if (handleOptions(req, res)) return;

  try {
    requireMethod(req, 'POST');
    const context = await getProfileContext(req);
    const portal = await createPortalSession(req, context);
    sendJson(res, 200, { ok: true, portal });
  } catch (error) {
    handleApiError(res, error, 'Unable to open billing portal.');
  }
};
