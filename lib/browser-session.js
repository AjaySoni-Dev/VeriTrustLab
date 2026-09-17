const { serverConfig } = require('./config');

const ACCESS_COOKIE = 'veritrust_access';
const REFRESH_COOKIE = 'veritrust_refresh';
const DEFAULT_ACCESS_MAX_AGE = 60 * 60;
const REFRESH_MAX_AGE = 30 * 24 * 60 * 60;

function parseCookies(req) {
  return String(req?.headers?.cookie || '').split(';').reduce((cookies, part) => {
    const separator = part.indexOf('=');
    if (separator < 1) return cookies;
    const name = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    try {
      cookies[name] = decodeURIComponent(value);
    } catch {
      cookies[name] = '';
    }
    return cookies;
  }, {});
}

function cookieSecurity() {
  return process.env.NODE_ENV === 'production' || Boolean(process.env.VERCEL) ? '; Secure' : '';
}

function boundedAccessMaxAge(session) {
  const expiresIn = Number(session?.expires_in);
  if (Number.isFinite(expiresIn) && expiresIn > 0) {
    return Math.max(60, Math.min(7 * 24 * 60 * 60, Math.floor(expiresIn)));
  }
  const expiresAt = Number(session?.expires_at);
  if (Number.isFinite(expiresAt) && expiresAt > 0) {
    const remaining = Math.floor(expiresAt - (Date.now() / 1000));
    if (remaining > 0) return Math.max(60, Math.min(7 * 24 * 60 * 60, remaining));
  }
  return DEFAULT_ACCESS_MAX_AGE;
}

function sessionCookie(name, value, maxAge) {
  return `${name}=${encodeURIComponent(String(value || ''))}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${cookieSecurity()}`;
}

function expiredCookie(name) {
  return `${name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT${cookieSecurity()}`;
}

function setSessionCookies(res, session) {
  if (!session?.access_token || !session?.refresh_token) throw new Error('Authentication provider did not return a complete session.');
  res.setHeader('Set-Cookie', [
    sessionCookie(ACCESS_COOKIE, session.access_token, boundedAccessMaxAge(session)),
    sessionCookie(REFRESH_COOKIE, session.refresh_token, REFRESH_MAX_AGE),
  ]);
}

function clearSessionCookies(res) {
  res.setHeader('Set-Cookie', [
    expiredCookie(ACCESS_COOKIE),
    expiredCookie(REFRESH_COOKIE),
  ]);
}

function accessCookie(req) {
  return parseCookies(req)[ACCESS_COOKIE] || null;
}

function refreshCookie(req) {
  return parseCookies(req)[REFRESH_COOKIE] || null;
}

function trustedSiteOrigin(req) {
  const production = process.env.NODE_ENV === 'production' || Boolean(process.env.VERCEL);
  const raw = production
    ? serverConfig.siteUrl
    : `${String(req.headers['x-forwarded-proto'] || 'http').split(',')[0].trim()}://${String(req.headers['x-forwarded-host'] || req.headers.host || 'localhost:3000').split(',')[0].trim()}`;
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw Object.assign(new Error('Trusted site origin is invalid.'), { status: 500, code: 'SERVER_CONFIG_ERROR' });
  }
  const local = ['localhost', '127.0.0.1', '::1'].includes(parsed.hostname);
  if (parsed.protocol !== 'https:' && !(local && parsed.protocol === 'http:')) {
    throw Object.assign(new Error('Trusted site origin must use HTTPS.'), { status: 500, code: 'SERVER_CONFIG_ERROR' });
  }
  return parsed.origin;
}

module.exports = {
  ACCESS_COOKIE,
  DEFAULT_ACCESS_MAX_AGE,
  REFRESH_COOKIE,
  REFRESH_MAX_AGE,
  accessCookie,
  boundedAccessMaxAge,
  clearSessionCookies,
  parseCookies,
  refreshCookie,
  setSessionCookies,
  trustedSiteOrigin,
};
