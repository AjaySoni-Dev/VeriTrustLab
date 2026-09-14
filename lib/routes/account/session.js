// Private route implementation; api/account.js is the Vercel entrypoint.
const {
  getProfileContext,
  workspaceStats,
} = require('../../supabase-server');
const { billingSnapshot } = require('../../entitlements');
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
    const [stats, billing] = await Promise.all([
      workspaceStats(context),
      billingSnapshot(context),
    ]);

    sendJson(res, 200, {
      ok: true,
      user: {
        id: context.user.id,
        email: context.user.email,
      },
      profile: context.profile,
      organization: context.organization,
      role: context.role,
      stats,
      billing,
    });
  } catch (error) {
    handleApiError(res, error, 'Session check failed.');
  }
};
