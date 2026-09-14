const {
  handleOptions,
  sendJson,
} = require('../lib/veritrust-api');

const routes = {
  checkout: require('../lib/routes/billing/checkout'),
  portal: require('../lib/routes/billing/portal'),
  subscription: require('../lib/routes/billing/subscription'),
  webhook: require('../lib/routes/billing/webhook'),
};

function routeName(req) {
  const url = new URL(req.url || '/', 'http://localhost');
  const fromQuery = url.searchParams.get('route');
  if (fromQuery) return fromQuery;
  const parts = url.pathname.split('/').filter(Boolean);
  return parts[2] || '';
}

module.exports = async function handler(req, res) {
  const route = routeName(req);
  const routeHandler = routes[route];

  if (!routeHandler) {
    if (handleOptions(req, res)) return;
    sendJson(res, 404, {
      ok: false,
      error: {
        code: 'NOT_FOUND',
        message: 'Unknown VeriTrust billing endpoint.',
      },
    });
    return;
  }

  return routeHandler(req, res);
};

module.exports.config = {
  api: {
    bodyParser: false,
  },
};
