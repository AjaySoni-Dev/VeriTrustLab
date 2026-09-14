// Private route implementation; api/account.js is the Vercel entrypoint.
const {
  getProfileContext,
  recentScans,
} = require('../../supabase-server');
const {
  handleApiError,
  handleOptions,
  requireMethod,
  sendJson,
} = require('../../veritrust-api');

module.exports = async function handler(req, res) {
  if (handleOptions(req, res)) return;

  try {
    requireMethod(req, 'GET');
    const url = new URL(req.url || '/', 'http://localhost');
    const context = await getProfileContext(req, url.searchParams.get('org_id'));
    const scans = await recentScans(context, url.searchParams.get('limit') || 20);

    sendJson(res, 200, {
      ok: true,
      organization: context.organization,
      scans,
    });
  } catch (error) {
    handleApiError(res, error, 'Unable to load scans.');
  }
};
