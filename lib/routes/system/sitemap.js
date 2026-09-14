const { MODULE_CONFIG } = require('../../modules');

const BASE_URL = 'https://www.veritrustlab.in';
const LAST_MODIFIED = '2026-08-22';
const PUBLIC_ROUTES = Object.freeze([
  ['/', '1.0'],
  ['/detection', '0.9'],
  ...(MODULE_CONFIG.deepfake ? [['/deepfake', '0.8']] : []),
  ...(MODULE_CONFIG.phishing ? [['/phishing', '0.8']] : []),
  ...(MODULE_CONFIG.link ? [['/link-check', '0.8']] : []),
  ...(MODULE_CONFIG.gateway ? [['/gateway', '0.8']] : []),
  ['/developers', '0.7'],
  ['/docs', '0.7'],
  ...(MODULE_CONFIG.gateway ? [['/gateway-powershell', '0.6']] : []),
  ['/model-performance', '0.6'],
  ['/security', '0.5'],
  ['/privacy', '0.5'],
  ['/terms', '0.4'],
  ['/disclaimer', '0.4'],
]);

module.exports = async function handler(req, res) {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.statusCode = 405;
    res.setHeader('Allow', 'GET, HEAD');
    res.end();
    return;
  }
  const rows = PUBLIC_ROUTES.map(([route, priority]) => (
    `  <url><loc>${BASE_URL}${route}</loc><lastmod>${LAST_MODIFIED}</lastmod><priority>${priority}</priority></url>`
  )).join('\n');
  const body = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${rows}\n</urlset>\n`;
  res.statusCode = 200;
  res.setHeader('Content-Type', 'application/xml; charset=utf-8');
  res.setHeader('Cache-Control', 'public, max-age=0, must-revalidate');
  res.end(req.method === 'HEAD' ? '' : body);
};
