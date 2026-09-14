(function initializeVeriTrustConfig(global) {
  'use strict';

  const MODULE_KEYS = Object.freeze(['phishing', 'deepfake', 'link', 'gateway']);
  const MODULE_DEFAULTS = Object.freeze({ phishing: true, deepfake: false, link: true, gateway: true });
  const MODULE_ROUTES = Object.freeze({
    deepfake: ['/deepfake'],
    phishing: ['/phishing'],
    link: ['/link-check'],
    gateway: ['/gateway', '/gateway-powershell'],
  });
  const MODULE_HASHES = Object.freeze({
    deepfake: 'deepfake',
    'image-checks': 'deepfake',
    phishing: 'phishing',
    'message-checks': 'phishing',
    link: 'link',
    'link-checks': 'link',
    gateway: 'gateway',
  });
  const MODULE_TERMS = Object.freeze({
    deepfake: /\b(?:deep[ -]?fake|synthetic[ -]?media|image deepfake|image review)\b/iu,
    phishing: /\b(?:phishing|phish|message review|message check)\b/iu,
    link: /\b(?:link intelligence|link and api review|link check|link scan|url analysis|url-string analysis|url classifier)\b/iu,
    gateway: /\b(?:unified (?:security )?gateway|gateway scan|multimodal gateway|gateway review|gateway)\b/iu,
  });

  document.documentElement.classList.add('vt-module-filtering');
  const guardStyle = document.createElement('style');
  guardStyle.dataset.moduleGuard = 'true';
  guardStyle.textContent = 'html.vt-module-filtering body{visibility:hidden!important}';
  document.head.appendChild(guardStyle);

  function requestJson(url) {
    try {
      const request = new XMLHttpRequest();
      request.open('GET', url, false);
      request.setRequestHeader('Accept', 'application/json');
      request.send(null);
      if (request.status >= 200 && request.status < 300) return JSON.parse(request.responseText || '{}');
    } catch {
      return {};
    }
    return {};
  }

  function normalizedModules(value) {
    const source = value && typeof value === 'object' && !Array.isArray(value) ? value : {};
    return Object.freeze(Object.fromEntries(MODULE_KEYS.map((key) => [
      key,
      typeof source[key] === 'boolean' ? source[key] : MODULE_DEFAULTS[key],
    ])));
  }

  const serverRuntimeConfig = requestJson('/api/client-config').config || {};
  const fileModuleConfig = Object.keys(serverRuntimeConfig.modules || {}).length
    ? {}
    : requestJson('/config/modules.json');
  const injectedConfig = global.VeriTrust_PUBLIC_CONFIG || {};
  const modules = normalizedModules(
    Object.keys(serverRuntimeConfig.modules || {}).length ? serverRuntimeConfig.modules : fileModuleConfig,
  );

  function normalizePath(value) {
    try {
      const url = new URL(value, global.location.href);
      return url.pathname.replace(/\.html$/iu, '').replace(/\/+$/u, '') || '/';
    } catch {
      return '';
    }
  }

  function moduleForPath(value) {
    const path = normalizePath(value);
    return MODULE_KEYS.find((key) => MODULE_ROUTES[key].includes(path)) || null;
  }

  function moduleForReference(value) {
    try {
      const url = new URL(value, global.location.href);
      const fromHash = MODULE_HASHES[url.hash.replace(/^#/u, '').toLowerCase()];
      return fromHash || moduleForPath(url.pathname);
    } catch {
      return null;
    }
  }

  function isEnabled(moduleName) {
    return modules[String(moduleName || '').trim().toLowerCase()] === true;
  }

  function enabledModuleKeys() {
    return MODULE_KEYS.filter(isEnabled);
  }

  function isScanVisible(scan) {
    const rawType = String(scan?.scan_type || scan?.type || '').trim().toLowerCase();
    const inputs = Array.isArray(scan?.scan_inputs) ? scan.scan_inputs : [scan?.scan_inputs].filter(Boolean);
    const logicalLink = scan?.metadata?.logical_scan_type === 'link'
      || scan?.metadata?.original_scan_type === 'link'
      || inputs.some((input) => input?.input_kind === 'url'
        || input?.metadata?.logical_scan_type === 'link'
        || input?.metadata?.original_scan_type === 'link');
    const moduleName = logicalLink ? 'link' : (rawType === 'deepfake_image' ? 'deepfake' : rawType);
    return !MODULE_KEYS.includes(moduleName) || isEnabled(moduleName);
  }

  function moduleList(element) {
    return String(element?.dataset?.module || element?.dataset?.modules || '')
      .split(/[\s,]+/u)
      .map((value) => value.trim().toLowerCase())
      .filter(Boolean);
  }

  function removeElement(element) {
    if (!(element instanceof Element) || element.dataset.moduleRemoved === 'true') return;
    element.dataset.moduleRemoved = 'true';
    element.remove();
  }

  function removeDisabledReferences(scope = document) {
    const root = scope instanceof Element || scope instanceof Document ? scope : document;
    const disabled = MODULE_KEYS.filter((key) => !isEnabled(key));
    if (!disabled.length) return;

    root.querySelectorAll('[data-module], [data-modules]').forEach((element) => {
      const required = moduleList(element);
      const mode = String(element.dataset.moduleMode || 'all').toLowerCase();
      const visible = mode === 'any' ? required.some(isEnabled) : required.every(isEnabled);
      if (!visible) removeElement(element);
    });

    root.querySelectorAll('a[href], area[href], form[action]').forEach((element) => {
      const moduleName = moduleForReference(element.getAttribute('href') || element.getAttribute('action'));
      if (!moduleName || isEnabled(moduleName)) return;
      const parentItem = element.closest('li');
      if (parentItem && parentItem.querySelectorAll('a,button').length === 1) removeElement(parentItem);
      else removeElement(element);
    });

    const disabledTerms = disabled.map((key) => MODULE_TERMS[key]);
    const mentionsDisabledModule = (value) => disabledTerms.some((pattern) => pattern.test(String(value || '')));
    if (mentionsDisabledModule(document.title)) document.title = 'VeriTrust | Email Threat & Forensic Intelligence';
    root.querySelectorAll('meta[content]').forEach((element) => {
      if (mentionsDisabledModule(element.getAttribute('content'))) {
        element.setAttribute('content', 'VeriTrust email threat detection and forensic intelligence platform.');
      }
    });
    root.querySelectorAll('script[type="application/ld+json"]').forEach((element) => {
      if (mentionsDisabledModule(element.textContent)) removeElement(element);
    });
    root.querySelectorAll('[aria-label], [title]').forEach((element) => {
      if (mentionsDisabledModule(element.getAttribute('aria-label'))) element.removeAttribute('aria-label');
      if (mentionsDisabledModule(element.getAttribute('title'))) element.removeAttribute('title');
    });
    root.querySelectorAll('section, article, [class*="card"], [class*="feature"], [class*="stat"]').forEach((element) => {
      const identity = `${element.id || ''} ${element.getAttribute('aria-label') || ''}`;
      const heading = element.querySelector(':scope > h1, :scope > h2, :scope > h3, :scope > h4, :scope > header h1, :scope > header h2, :scope > div > h2, :scope > div > h3, :scope > div > h4');
      const identityModule = MODULE_HASHES[String(element.id || '').toLowerCase()];
      if ((identityModule && !isEnabled(identityModule)) || mentionsDisabledModule(identity) || mentionsDisabledModule(heading?.textContent)) removeElement(element);
    });

    root.querySelectorAll('li, tr, dt, dd, option, button, p, small, figcaption, h1, h2, h3, h4, h5, h6').forEach((element) => {
      if (!element.isConnected || !mentionsDisabledModule(element.textContent)) return;
      removeElement(element);
    });

    const detectionGrid = document.querySelector('.choice-grid');
    if (detectionGrid && !detectionGrid.querySelector('.choice-card') && !detectionGrid.querySelector('[data-modules-empty]')) {
      const empty = document.createElement('p');
      empty.dataset.modulesEmpty = 'true';
      empty.setAttribute('role', 'status');
      empty.textContent = 'No review workflows are currently available.';
      detectionGrid.appendChild(empty);
    }
  }

  let filterScheduled = false;
  function scheduleModuleFilter() {
    if (filterScheduled) return;
    filterScheduled = true;
    global.requestAnimationFrame(() => {
      filterScheduled = false;
      removeDisabledReferences(document);
    });
  }

  const pageModule = moduleForPath(global.location.pathname);
  if (pageModule && !isEnabled(pageModule)) global.location.replace('/detection');

  const apiDefaults = {
    health: '/api/health',
    session: '/api/session',
    dashboard: '/api/dashboard',
    scans: '/api/scans',
    cases: '/api/cases',
    apiKeys: '/api/api-keys',
    authSession: '/api/auth-session',
    profile: '/api/profile',
    privacy: '/api/privacy',
    jobs: '/api/jobs',
    modelCards: '/api/model-cards',
    ...(isEnabled('deepfake') ? { deepfake: '/api/deepfake' } : {}),
    ...(isEnabled('link') ? { linkCheck: '/api/link-check' } : {}),
    ...(isEnabled('phishing') ? { phishing: '/api/phishing' } : {}),
  };
  const runtimeConfigValue = {
    ...(isEnabled('deepfake') ? {
      cropApiUrl: 'https://ajaysoni-dev-deepfakefusion.hf.space/api/crop-image',
      cropOutputBaseUrl: 'https://ajaysoni-dev-deepfakefusion.hf.space',
      maxImageBytes: 4 * 1024 * 1024,
    } : {}),
    ...serverRuntimeConfig,
    ...injectedConfig,
    modules,
    supabase: {
      url: '',
      anonKey: '',
      ...(serverRuntimeConfig.supabase || {}),
      ...(injectedConfig.supabase || {}),
    },
    api: {
      ...apiDefaults,
      ...(serverRuntimeConfig.api || {}),
      ...(injectedConfig.api || {}),
      ...(!isEnabled('deepfake') ? { deepfake: undefined } : {}),
      ...(!isEnabled('link') ? { linkCheck: undefined } : {}),
      ...(!isEnabled('phishing') ? { phishing: undefined } : {}),
    },
  };

  global.VeriTrust_CONFIG = runtimeConfigValue;
  global['VERI' + 'TRUST_CONFIG'] = runtimeConfigValue;
  global.VeriTrustModules = Object.freeze({
    config: modules,
    enabled: enabledModuleKeys,
    filter: removeDisabledReferences,
    filterRecords: (records) => (Array.isArray(records) ? records.filter(isScanVisible) : []),
    isEnabled,
    isScanVisible,
    moduleForPath,
  });

  const observer = new MutationObserver(scheduleModuleFilter);
  document.addEventListener('DOMContentLoaded', () => {
    removeDisabledReferences(document);
    observer.observe(document.body, { childList: true, subtree: true });
    document.documentElement.classList.remove('vt-module-filtering');
    guardStyle.remove();
  }, { once: true });
})(window);
