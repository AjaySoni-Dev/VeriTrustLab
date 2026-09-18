// Private route implementation; api/account.js is the Vercel entrypoint.
const {
  getCase,
  getProfileContext,
  listCases,
  recordCaseDecision,
  updateCaseWorkflow,
} = require('../../supabase-server');
const {
  HttpError,
  handleApiError,
  handleOptions,
  parseJsonBody,
  sendJson,
} = require('../../veritrust-api');

module.exports = async function handler(req, res) {
  if (handleOptions(req, res)) return;

  try {
    if (!['GET', 'POST'].includes(req.method)) {
      throw new HttpError(405, 'Use GET or POST for this endpoint.');
    }
    const url = new URL(req.url || '/', 'http://localhost');
    const context = await getProfileContext(req, url.searchParams.get('org_id'));
    const caseId = url.searchParams.get('id');

    if (req.method === 'GET') {
      if (caseId) {
        sendJson(res, 200, {
          ok: true,
          organization: context.organization,
          role: context.role,
          user: { id: context.user.id, email: context.user.email },
          case: await getCase(context, caseId),
        });
        return;
      }
      const cases = await listCases(context, {
        status: url.searchParams.get('status'),
        priority: url.searchParams.get('priority'),
        assigned: url.searchParams.get('assigned'),
        limit: url.searchParams.get('limit'),
      });
      sendJson(res, 200, {
        ok: true,
        organization: context.organization,
        role: context.role,
        user: { id: context.user.id, email: context.user.email },
        cases,
      });
      return;
    }

    if (!caseId) throw new HttpError(400, 'Case ID is required.', { code: 'INVALID_INPUT' });
    const body = await parseJsonBody(req, 32 * 1024);
    const action = String(body.action || '').toLowerCase();
    if (action === 'decision') {
      const result = await recordCaseDecision(context, caseId, body);
      sendJson(res, 200, { ok: true, result, case: await getCase(context, caseId) });
      return;
    }
    if (action === 'workflow') {
      const result = await updateCaseWorkflow(context, caseId, body);
      sendJson(res, 200, { ok: true, result, case: await getCase(context, caseId) });
      return;
    }
    throw new HttpError(400, 'Unknown case action.', { code: 'INVALID_INPUT' });
  } catch (error) {
    handleApiError(res, error, 'Unable to update the case workflow.');
  }
};
