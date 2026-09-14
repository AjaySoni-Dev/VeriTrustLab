// Private route implementation; api/account.js is the Vercel entrypoint.
const { getProfileContext } = require('../../supabase-server');
const { platformJobStatus } = require('../../platform');
const { HttpError, handleApiError, handleOptions, sendJson } = require('../../veritrust-api');

module.exports = async function handler(req, res) {
  if (handleOptions(req, res)) return;
  try {
    if (req.method !== 'GET') throw new HttpError(405, 'Use GET for this endpoint.');
    const url = new URL(req.url || '/', 'http://localhost');
    const context = await getProfileContext(req, url.searchParams.get('org_id'));
    const jobId = url.searchParams.get('id');
    sendJson(res, 200, { ok: true, job: await platformJobStatus(context, jobId) });
  } catch (error) {
    handleApiError(res, error, 'Unable to read the background job.');
  }
};
