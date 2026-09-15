// Private route implementation; api/account.js is the Vercel entrypoint.
const { dashboardSnapshot } = require('../../supabase-server');
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
    const dashboard = await dashboardSnapshot(req, {
      orgId: url.searchParams.get('org_id'),
      limit: url.searchParams.get('limit') || 100,
      offset: url.searchParams.get('offset') || 0,
    });
    if (dashboard?.organization?.id) {
      dashboard.billing = await billingSnapshot(dashboard.organization.id);
    }
    sendJson(res, 200, dashboard);
  } catch (error) {
    handleApiError(res, error, 'Unable to load the dashboard.');
  }
};
