// Private route implementation; api/system.js is the Vercel entrypoint.
const { publishedModelCards } = require('../../platform');
const { HttpError, handleApiError, handleOptions, sendJson } = require('../../veritrust-api');
const { isModuleEnabled } = require('../../modules');

function cardModule(card) {
  const key = String(card?.model_key || card?.key || card?.task || '').toLowerCase();
  if (/pixel|prism|deepfake|image/u.test(key)) return 'deepfake';
  if (/mailguard|cortex|phish|message/u.test(key)) return 'phishing';
  if (/swift|sentinel|link|url/u.test(key)) return 'link';
  return null;
}

module.exports = async function handler(req, res) {
  if (handleOptions(req, res)) return;
  try {
    if (req.method !== 'GET') throw new HttpError(405, 'Use GET for this endpoint.');
    const url = new URL(req.url || '/', 'http://localhost');
    const modelKey = String(url.searchParams.get('model') || '').trim();
    const published = await publishedModelCards(modelKey || null);
    const cards = (Array.isArray(published) ? published : []).filter((card) => {
      const moduleName = cardModule(card);
      return !moduleName || isModuleEnabled(moduleName);
    });
    sendJson(res, 200, {
      ok: true,
      cards,
      governance_status: cards.length ? 'published' : 'validation_pending',
    });
  } catch (error) {
    handleApiError(res, error, 'Model governance information is unavailable.');
  }
};
