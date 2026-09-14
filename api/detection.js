const { handleOptions, sendJson } = require('../lib/veritrust-api');
const { requireModuleEnabled } = require('../lib/modules');

const routes = Object.freeze({
  deepfake: require('../lib/routes/detection/deepfake'),
  phishing: require('../lib/routes/detection/phishing'),
  'link-check': require('../lib/routes/detection/link-check'),
});

function routeName(req) {
  const url = new URL(req.url || '/', 'http://localhost');
  return url.searchParams.get('route') || '';
}

module.exports = async function handler(req, res) {
  const selected = routeName(req);
  const routeHandler = routes[selected];
  if (routeHandler) {
    try {
      requireModuleEnabled(selected === 'link-check' ? 'link' : selected);
    } catch {
      sendJson(res, 404, { ok: false, error: { code: 'NOT_FOUND', message: 'The requested resource was not found.' } });
      return;
    }
    return routeHandler(req, res);
  }
  if (handleOptions(req, res)) return;
  sendJson(res, 404, { ok: false, error: { code: 'NOT_FOUND', message: 'Unknown VeriTrust detection endpoint.' } });
};

module.exports.routeName = routeName;
