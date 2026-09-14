import moduleConfig from './config/modules.json';

const MODULES = moduleConfig;

const MODULE_PAGE: Record<string, keyof typeof MODULES> = {
  deepfake: 'deepfake',
  phishing: 'phishing',
  'link-check': 'link',
  gateway: 'gateway',
  'gateway-powershell': 'gateway',
};

export const config = {
  matcher: [
    '/deepfake',
    '/deepfake.html',
    '/phishing',
    '/phishing.html',
    '/link-check',
    '/link-check.html',
    '/gateway',
    '/gateway.html',
    '/gateway-powershell',
    '/gateway-powershell.html',
  ],
};

export default function moduleGuardMiddleware(request) {
  const page = new URL(request.url).pathname.split('/').filter(Boolean).pop()?.replace(/\.html$/iu, '') || '';
  const moduleName = MODULE_PAGE[page];
  if (!moduleName || MODULES[moduleName]) return;

  return new Response('Not Found', {
    status: 404,
    headers: {
      'Cache-Control': 'no-store',
      'Content-Type': 'text/plain; charset=utf-8',
      'X-Robots-Tag': 'noindex, nofollow, nosnippet',
    },
  });
}
