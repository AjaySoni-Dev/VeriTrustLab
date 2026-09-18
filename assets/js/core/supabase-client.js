(function initVeriTrustSupabase(global) {
  const runtimeConfig = global.VeriTrust_CONFIG || global['VERI' + 'TRUST_CONFIG'] || {};
  const supabaseConfig = runtimeConfig.supabase || {};
  const apiConfig = runtimeConfig.api || {};
  const authEndpoint = apiConfig.authSession || '/api/auth-session';
  const profileEndpoint = apiConfig.profile || '/api/profile';
  let currentSession = null;
  let sessionRequest = null;

  function normalizeUrl(url) {
    return String(url || '').replace(/\/$/, '');
  }

  function normalizeCredential(value) {
    const cleaned = String(value || '').trim();
    const lines = cleaned.split(/\r?\n/u).map((line) => line.trim()).filter(Boolean);
    return lines.length > 1 && new Set(lines).size === 1 ? lines[0] : cleaned;
  }

  const baseUrl = normalizeUrl(supabaseConfig.url);
  const anonKey = normalizeCredential(supabaseConfig.anonKey);

  function isConfigured() {
    return Boolean(baseUrl && anonKey && !/[\u0000-\u001f\u007f]/u.test(anonKey));
  }

  function getStoredSession() {
    return currentSession;
  }

  async function readJsonResponse(response, fallbackMessage) {
    let data = null;
    try {
      data = await response.json();
    } catch {
      data = null;
    }
    if (!response.ok || data?.ok === false) {
      const error = new Error(data?.error?.message || data?.message || fallbackMessage || `Request failed with status ${response.status}.`);
      error.status = response.status;
      error.code = data?.error?.code || '';
      throw error;
    }
    return data;
  }

  async function browserAuth(action, options = {}) {
    const response = await fetch(`${authEndpoint}?action=${encodeURIComponent(action)}`, {
      method: options.method || 'GET',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: {
        Accept: 'application/json',
        ...(options.body ? { 'Content-Type': 'application/json' } : {}),
      },
      body: options.body ? JSON.stringify(options.body) : undefined,
    });
    return readJsonResponse(response, 'Authentication request failed.');
  }

  async function supabaseFetch(path, options = {}) {
    if (!isConfigured()) {
      throw new Error('Account service is unavailable.');
    }

    const legacyJwtKey = anonKey.split('.').length === 3 ? anonKey : null;
    const headers = {
      apikey: anonKey,
      ...(legacyJwtKey ? { Authorization: `Bearer ${legacyJwtKey}` } : {}),
      ...(options.body ? { 'Content-Type': 'application/json' } : {}),
      ...(options.headers || {}),
    };

    const response = await fetch(`${baseUrl}${path}`, {
      method: options.method || 'GET',
      headers,
      body: options.body ? JSON.stringify(options.body) : undefined,
    });

    const text = await response.text();
    let data = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = text;
    }

    if (!response.ok) {
      const message = data?.msg || data?.message || data?.error_description || data?.error || `Account request failed with status ${response.status}.`;
      throw new Error(message);
    }

    return data;
  }

  async function signUp({ email, password, fullName, workspaceName }) {
    if (String(password || '').length < 12) throw new Error('Use at least 12 characters for your password.');
    if (String(password).length > 128) throw new Error('Password must not exceed 128 characters.');
    const data = await browserAuth('signup', {
      method: 'POST',
      body: { email, password, fullName, workspaceName },
    });
    currentSession = data.authenticated ? { authenticated: true, user: data.user || null } : null;
    return data;
  }

  async function signIn({ email, password }) {
    const data = await browserAuth('signin', {
      method: 'POST',
      body: { email, password },
    });
    currentSession = { authenticated: true, user: data.user || null };
    return currentSession;
  }

  async function getSession(options = {}) {
    if (currentSession && !options.refresh) return currentSession;
    if (sessionRequest) return sessionRequest;
    const verifySession = async () => {
      try {
        return await browserAuth('session');
      } catch (error) {
        const status = Number(error?.status || 0);
        const transient = !status || status === 408 || status === 425 || status === 429 || status >= 500;
        if (!transient) throw error;
        await new Promise((resolve) => global.setTimeout(resolve, 250));
        return browserAuth('session');
      }
    };
    sessionRequest = verifySession()
      .then((data) => {
        currentSession = { authenticated: true, user: data.user || null };
        return currentSession;
      })
      .catch((error) => {
        if (error.status === 401) {
          currentSession = null;
          return null;
        }
        throw error;
      })
      .finally(() => {
        sessionRequest = null;
      });
    return sessionRequest;
  }

  async function signOut() {
    try {
      await browserAuth('logout', { method: 'POST' });
    } finally {
      currentSession = null;
    }
  }

  async function resetPassword(email) {
    const redirectTo = new URL('/auth', global.location.origin).href;
    return supabaseFetch('/auth/v1/recover', {
      method: 'POST',
      body: {
        email,
        redirect_to: redirectTo,
      },
    });
  }

  async function consumeAuthCallback() {
    const hash = new URLSearchParams(global.location.hash.replace(/^#/, ''));
    const query = new URLSearchParams(global.location.search);
    const error = hash.get('error_description') || query.get('error_description') || hash.get('error') || query.get('error');
    if (error) throw new Error(error);

    const accessToken = hash.get('access_token');
    const refreshToken = hash.get('refresh_token');
    if (!accessToken) return null;
    const type = hash.get('type') || query.get('type') || 'confirmation';

    const cleanUrl = new URL(global.location.href);
    ['access_token', 'refresh_token', 'expires_in', 'expires_at', 'token_type', 'type', 'error', 'error_description'].forEach((key) => cleanUrl.searchParams.delete(key));
    cleanUrl.hash = '';
    global.history.replaceState({}, document.title, `${cleanUrl.pathname}${cleanUrl.search}`);

    const data = await browserAuth('callback', {
      method: 'POST',
      body: {
        access_token: accessToken,
        refresh_token: refreshToken,
      },
    });
    currentSession = { authenticated: true, user: data.user || null };
    return { session: currentSession, type };
  }

  async function updatePassword(password) {
    if (String(password || '').length < 12) throw new Error('Use at least 12 characters for your new password.');
    if (String(password).length > 128) throw new Error('Password must not exceed 128 characters.');
    return browserAuth('password', { method: 'POST', body: { password } });
  }

  async function callAppApi(url, options = {}) {
    const requestOptions = {
      ...options,
      credentials: 'same-origin',
      headers: { ...(options.headers || {}) },
    };
    let response = await fetch(url, requestOptions);
    if (response.status === 401 && !String(url).startsWith(authEndpoint)) {
      const refreshed = await getSession({ refresh: true });
      if (refreshed) response = await fetch(url, requestOptions);
    }
    return readJsonResponse(response);
  }

  async function getSessionContext() {
    return callAppApi(apiConfig.session || '/api/session', { cache: 'no-store' });
  }

  async function getDashboard(options = {}) {
    const params = new URLSearchParams({
      limit: String(Math.max(1, Math.min(100, Number(options.limit) || 100))),
      offset: String(Math.max(0, Math.min(10000, Number(options.offset) || 0))),
    });
    if (options.orgId) params.set('org_id', options.orgId);
    return callAppApi(`${apiConfig.dashboard || '/api/dashboard'}?${params}`, { cache: 'no-store' });
  }

  async function getRecentScans(orgId, limit = 20) {
    const params = new URLSearchParams({
      org_id: orgId,
      limit: String(limit),
    });
    return callAppApi(`${apiConfig.scans || '/api/scans'}?${params}`, { cache: 'no-store' });
  }

  async function getCases(options = {}) {
    const params = new URLSearchParams({
      limit: String(Math.max(1, Math.min(100, Number(options.limit) || 50))),
    });
    if (options.orgId) params.set('org_id', options.orgId);
    if (options.status) params.set('status', options.status);
    if (options.priority) params.set('priority', options.priority);
    if (options.assigned) params.set('assigned', options.assigned);
    return callAppApi(`${apiConfig.cases || '/api/cases'}?${params}`, { cache: 'no-store' });
  }

  async function getCase(caseId) {
    return callAppApi(`${apiConfig.cases || '/api/cases'}?id=${encodeURIComponent(caseId)}`, { cache: 'no-store' });
  }

  async function updateCase(caseId, body) {
    return callAppApi(`${apiConfig.cases || '/api/cases'}?id=${encodeURIComponent(caseId)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {}),
    });
  }

  async function updateProfile(profilePatch) {
    const data = await callAppApi(`${profileEndpoint}?action=update`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(profilePatch || {}),
    });
    return data.profile;
  }

  async function getAvatarBlobUrl(path) {
    if (!path) return null;
    const response = await fetch(`${profileEndpoint}?action=avatar`, {
      credentials: 'same-origin',
      cache: 'no-store',
    });
    if (!response.ok) return null;
    return URL.createObjectURL(await response.blob());
  }

  async function uploadAvatar(file) {
    if (!file || !['image/jpeg', 'image/png', 'image/webp'].includes(file.type)) {
      throw new Error('Use a JPEG, PNG, or WebP avatar.');
    }
    if (file.size > 1024 * 1024) throw new Error('Keep the avatar under 1 MB.');
    const body = new FormData();
    body.append('avatar', file);
    const data = await callAppApi(`${profileEndpoint}?action=avatar`, {
      method: 'POST',
      body,
    });
    return data.path;
  }


  global.VeriTrustSupabase = {
    isConfigured,
    getStoredSession,
    getSession,
    getSessionContext,
    getDashboard,
    getRecentScans,
    getCases,
    getCase,
    updateCase,
    getAvatarBlobUrl,
    updateProfile,
    uploadAvatar,
    signIn,
    signOut,
    signUp,
    resetPassword,
    consumeAuthCallback,
    updatePassword,
    callAppApi,
  };
})(window);
