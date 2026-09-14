const { handleOptions, sendJson } = require('../lib/veritrust-api');

const routes = Object.freeze({
  session: require('../lib/routes/account/session'),
  scans: require('../lib/routes/account/scans'),
  cases: require('../lib/routes/account/cases'),
  dashboard: require('../lib/routes/account/dashboard'),
  'api-keys': require('../lib/routes/account/api-keys'),
  'auth-session': require('../lib/routes/account/auth-session'),
  profile: require('../lib/routes/account/profile'),
  privacy: require('../lib/routes/account/privacy'),
  jobs: require('../lib/routes/account/jobs'),
});

function routeName(req) {
  const url = new URL(req.url || '/', 'http://localhost');
  return url.searchParams.get('route') || '';
}

module.exports = async function handler(req, res) {
  const selected = routeName(req);
  const routeHandler = routes[selected];
  if (routeHandler) return routeHandler(req, res);
  if (handleOptions(req, res)) return;
  sendJson(res, 404, { ok: false, error: { code: 'NOT_FOUND', message: 'Unknown VeriTrust account endpoint.' } });
};

module.exports.routeName = routeName;

module.exports.config = {
  api: {
    bodyParser: false,
  },
};
