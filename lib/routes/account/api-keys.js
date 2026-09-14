// Private route implementation; api/account.js is the Vercel entrypoint.
const {
  createApiKey,
  listApiKeys,
  revokeApiKey,
} = require('../../api-keys');
const {
  getProfileContext,
} = require('../../supabase-server');
const {
  handleApiError,
  handleOptions,
  parseJsonBody,
  sendJson,
} = require('../../veritrust-api');
const { validateJsonContentType } = require('../../validators');

module.exports = async function handler(req, res) {
  if (handleOptions(req, res)) return;

  try {
    const context = await getProfileContext(req);

    if (req.method === 'GET') {
      const keys = await listApiKeys(context);
      sendJson(res, 200, { ok: true, api_keys: keys });
      return;
    }

    if (req.method === 'POST') {
      validateJsonContentType(req);
      const body = await parseJsonBody(req, 4096);
      const apiKey = await createApiKey(context, {
        name: body.name,
        scopes: body.scopes,
        mode: body.mode,
      });
      sendJson(res, 201, {
        ok: true,
        api_key: apiKey,
        warning: 'Copy this key now. It will not be shown again.',
      });
      return;
    }

    if (req.method === 'DELETE') {
      const url = new URL(req.url || '/', 'http://localhost');
      const body = req.headers['content-type']?.includes('application/json')
        ? await parseJsonBody(req, 2048)
        : {};
      const id = url.searchParams.get('id') || body.id;
      const revoked = await revokeApiKey(context, id);
      sendJson(res, 200, { ok: true, revoked });
      return;
    }

    sendJson(res, 405, {
      ok: false,
      error: {
        code: 'METHOD_NOT_ALLOWED',
        message: 'Use GET, POST, or DELETE for this endpoint.',
      },
    });
  } catch (error) {
    handleApiError(res, error, 'Unable to manage API keys.');
  }
};
