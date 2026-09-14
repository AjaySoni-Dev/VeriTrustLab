const {
  accessCookie,
  clearSessionCookies,
  refreshCookie,
  setSessionCookies,
  trustedSiteOrigin,
} = require('../../browser-session');
const {
  getUserFromRequest,
  supabaseFetch,
} = require('../../supabase-server');
const {
  HttpError,
  handleApiError,
  handleOptions,
  parseJsonBody,
  requireMethod,
  sendJson,
} = require('../../veritrust-api');
const { validateJsonContentType } = require('../../validators');
const { enforceRateLimit } = require('../../rate-limit');

function actionName(req) {
  return new URL(req.url || '/', 'http://localhost').searchParams.get('action') || 'session';
}

function validateCredentials(body, signup = false) {
  const email = String(body.email || '').trim().toLowerCase();
  const password = String(body.password || '');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/u.test(email) || email.length > 254) {
    throw new HttpError(400, 'Enter a valid email address.', { code: 'INVALID_EMAIL' });
  }
  if (!password || password.length > 128 || (signup && password.length < 12)) {
    throw new HttpError(400, signup ? 'Use a password containing 12 to 128 characters.' : 'Email or password is invalid.', { code: 'INVALID_CREDENTIALS' });
  }
  return { email, password };
}

function isAccessTokenRejection(error) {
  return [401, 403].includes(Number(error?.status || 0));
}

function isInvalidRefreshCredential(error) {
  return [400, 401, 403].includes(Number(error?.status || 0));
}

async function refreshBrowserSession(req, res) {
  const token = refreshCookie(req);
  if (!token) return null;
  try {
    const session = await supabaseFetch('/auth/v1/token?grant_type=refresh_token', {
      method: 'POST',
      body: { refresh_token: token },
    });
    setSessionCookies(res, session);
    return session;
  } catch (error) {
    if (isInvalidRefreshCredential(error)) {
      clearSessionCookies(res);
      return null;
    }
    throw error;
  }
}

async function verifiedBrowserSession(req, res) {
  try {
    const auth = await getUserFromRequest(req);
    return { authenticated: true, user: auth.user };
  } catch (error) {
    if (!isAccessTokenRejection(error)) throw error;
  }
  const refreshed = await refreshBrowserSession(req, res);
  if (!refreshed?.access_token) return null;
  const user = await supabaseFetch('/auth/v1/user', { accessToken: refreshed.access_token });
  return { authenticated: true, user };
}

module.exports = async function handler(req, res) {
  if (handleOptions(req, res)) return;
  const action = actionName(req);
  try {
    if (action === 'session') {
      requireMethod(req, 'GET');
      const session = await verifiedBrowserSession(req, res);
      if (!session) throw new HttpError(401, 'Sign in to continue.', { code: 'UNAUTHORIZED' });
      sendJson(res, 200, { ok: true, ...session });
      return;
    }

    if (action === 'signin' || action === 'signup') {
      requireMethod(req, 'POST');
      validateJsonContentType(req);
      const body = await parseJsonBody(req, 16384);
      const credentials = validateCredentials(body, action === 'signup');
      await enforceRateLimit({
        req,
        endpoint: `auth:${action}:network`,
        limit: 300,
      });
      await enforceRateLimit({
        req,
        endpoint: `auth:${action}:account`,
        limit: action === 'signin' ? 30 : 5,
        identityType: 'ip',
        identityValue: credentials.email,
      });
      const session = action === 'signin'
        ? await supabaseFetch('/auth/v1/token?grant_type=password', { method: 'POST', body: credentials })
        : await supabaseFetch(`/auth/v1/signup?redirect_to=${encodeURIComponent(`${trustedSiteOrigin(req)}/auth`)}`, {
          method: 'POST',
          body: {
            ...credentials,
            data: {
              full_name: String(body.fullName || '').trim().slice(0, 120),
              workspace_name: String(body.workspaceName || '').trim().slice(0, 120),
            },
          },
        });
      if (session?.access_token && session?.refresh_token) setSessionCookies(res, session);
      sendJson(res, action === 'signin' ? 200 : 201, {
        ok: true,
        authenticated: Boolean(session?.access_token),
        user: session?.user || null,
      });
      return;
    }

    if (action === 'callback') {
      requireMethod(req, 'POST');
      validateJsonContentType(req);
      const body = await parseJsonBody(req, 32768);
      const accessToken = String(body.access_token || '');
      const refreshToken = String(body.refresh_token || '');
      if (!accessToken || !refreshToken || accessToken.length > 16384 || refreshToken.length > 16384) {
        throw new HttpError(400, 'Authentication callback is incomplete.', { code: 'INVALID_AUTH_CALLBACK' });
      }
      const user = await supabaseFetch('/auth/v1/user', { accessToken });
      setSessionCookies(res, { access_token: accessToken, refresh_token: refreshToken });
      sendJson(res, 200, { ok: true, authenticated: true, user });
      return;
    }

    if (action === 'password') {
      requireMethod(req, 'POST');
      validateJsonContentType(req);
      const body = await parseJsonBody(req, 2048);
      const password = String(body.password || '');
      if (password.length < 12 || password.length > 128) throw new HttpError(400, 'Use a password containing 12 to 128 characters.', { code: 'INVALID_PASSWORD' });
      const token = accessCookie(req);
      if (!token) throw new HttpError(401, 'Your recovery session has expired.', { code: 'UNAUTHORIZED' });
      await supabaseFetch('/auth/v1/user', { method: 'PUT', accessToken: token, body: { password } });
      sendJson(res, 200, { ok: true });
      return;
    }

    if (action === 'logout') {
      requireMethod(req, 'POST');
      const token = accessCookie(req);
      if (token) await supabaseFetch('/auth/v1/logout', { method: 'POST', accessToken: token }).catch(() => null);
      clearSessionCookies(res);
      sendJson(res, 200, { ok: true });
      return;
    }

    throw new HttpError(404, 'Unknown browser session action.', { code: 'NOT_FOUND' });
  } catch (error) {
    handleApiError(res, error, 'Authentication request failed.');
  }
};

module.exports.isAccessTokenRejection = isAccessTokenRejection;
module.exports.isInvalidRefreshCredential = isInvalidRefreshCredential;
