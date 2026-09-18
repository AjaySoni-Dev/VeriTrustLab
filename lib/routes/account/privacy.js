// Private route implementation; api/account.js is the Vercel entrypoint.
const { getProfileContext } = require('../../supabase-server');
const {
  legalHolds,
  listDataRightsRequests,
  privacyPolicy,
  requestDataRightsAction,
} = require('../../platform');
const {
  HttpError,
  handleApiError,
  handleOptions,
  parseJsonBody,
  sendJson,
} = require('../../veritrust-api');
const { validateJsonContentType } = require('../../validators');

module.exports = async function handler(req, res) {
  if (handleOptions(req, res)) return;
  try {
    if (!['GET', 'POST'].includes(req.method)) throw new HttpError(405, 'Use GET or POST for this endpoint.');
    const url = new URL(req.url || '/', 'http://localhost');
    const context = await getProfileContext(req, url.searchParams.get('org_id'));

    if (req.method === 'GET') {
      const [policy, requests, holds] = await Promise.all([
        privacyPolicy(context),
        listDataRightsRequests(context),
        ['owner', 'admin'].includes(String(context.role || '').toLowerCase()) ? legalHolds(context) : Promise.resolve([]),
      ]);
      sendJson(res, 200, {
        ok: true,
        organization: { id: context.organization.id, name: context.organization.name },
        role: context.role,
        policy,
        requests,
        legal_holds: holds,
      });
      return;
    }

    validateJsonContentType(req);
    const body = await parseJsonBody(req, 16 * 1024);
    const action = String(body.action || '').toLowerCase();
    if (!['export', 'erasure'].includes(action)) {
      throw new HttpError(400, 'Choose export or erasure.', { code: 'INVALID_DATA_RIGHTS_ACTION' });
    }
    const result = await requestDataRightsAction(context, action, body.scope || {});
    sendJson(res, result.duplicate ? 200 : 202, { ok: true, request: result });
  } catch (error) {
    handleApiError(res, error, 'Unable to process the privacy request.');
  }
};
