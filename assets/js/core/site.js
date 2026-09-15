function veritrustPageId(pathname = window.location.pathname) {
  const path = String(pathname || '/').replace(/\/+$/, '') || '/';
  return path.split('/').filter(Boolean).pop()?.replace(/\.html$/i, '').toLowerCase() || 'index';
}

const VeriTrustPageAccess = (() => {
  const pathname = window.location.pathname;
  const page = veritrustPageId(pathname);
  const isLanding = page === 'index';
  const isAuth = page === 'auth';
  const publicPages = new Set([
    'index',
    'auth',
    'developers',
    'docs',
    'gateway-powershell',
    'verify-evidence',
    'model-performance',
    'privacy',
    'terms',
    'security',
    'disclaimer',
  ]);
  const isPublic = publicPages.has(page);

  const safeRedirect = (value, fallback = '/dashboard') => {
    if (!value) return fallback;
    try {
      const target = new URL(value, window.location.href);
      if (target.origin !== window.location.origin) return fallback;
      const targetPage = target.pathname.split('/').filter(Boolean).pop()?.toLowerCase() || '';
      if (['', 'index', 'index.html', 'auth', 'auth.html'].includes(targetPage)) return fallback;
      return `${target.pathname}${target.search}${target.hash}`;
    } catch {
      return fallback;
    }
  };

  const currentDestination = () => `${pathname}${window.location.search}${window.location.hash}`;
  const shouldBlockForAuth = isAuth || !isPublic;
  const shouldVerifyBeforePaint = shouldBlockForAuth;
  if (shouldVerifyBeforePaint) {
    document.documentElement.classList.add('vt-auth-checking');
    document.documentElement.setAttribute('aria-busy', 'true');
  }

  const resolve = async () => {
    const client = window.VeriTrustSupabase;
    let session = null;
    let callback = null;
    let callbackError = null;
    let sessionError = null;
    // Browser sessions are verified by our same-origin API and do not depend on
    // the public Supabase configuration request succeeding in the browser.
    if (client?.getSession) {
      try {
        callback = await client.consumeAuthCallback?.() || null;
      } catch (error) {
        callbackError = error;
      }
      try {
        session = await client.getSession();
      } catch (error) {
        sessionError = error;
        session = null;
      }
    }

    const isRecovery = isAuth && callback?.type === 'recovery';
    if (session && isAuth && !isRecovery) {
      const params = new URLSearchParams(window.location.search);
      window.location.replace(safeRedirect(params.get('redirect')));
      return { allowed: false, session };
    }

    if (!isPublic && !session) {
      if (sessionError) {
        if (shouldVerifyBeforePaint) {
          document.documentElement.classList.remove('vt-auth-checking');
          document.documentElement.removeAttribute('aria-busy');
        }
        return { allowed: true, callback, callbackError, isAuth, isLanding, session: null, sessionError };
      }
      const redirect = encodeURIComponent(currentDestination());
      window.location.replace(`/auth?redirect=${redirect}`);
      return { allowed: false, session: null };
    }

    if (shouldVerifyBeforePaint) {
      document.documentElement.classList.remove('vt-auth-checking');
      document.documentElement.removeAttribute('aria-busy');
    }
    return { allowed: true, callback, callbackError, isAuth, isLanding, session, sessionError };
  };

  window.VeriTrustAuthFlow = { safeRedirect };
  return resolve();
})();

window.VeriTrustPageAccess = VeriTrustPageAccess;

const VeriTrustLoadingShimmer = (() => {
  const candidates = [
    '[role="status"]',
    '.is-loading',
    '.gateway-history-item',
    'h1[id$="-title"]',
    '.vt-loading-shimmer',
  ].join(',');
  const spinnerOnly = [
    'button',
    '.btn',
    '.result-loading',
    '.loading-state',
    '.gateway-result',
    '.gateway-history-item',
  ].join(',');
  const loadingCopy = /^(?:loading|checking|preparing|processing|saving|submitting|creating|refreshing|uploading|analyzing|enrolling|verifying|please wait)\b/i;
  let scheduled = false;

  const isLoading = (node) => {
    if (!(node instanceof HTMLElement) || node.hidden) return false;
    if (node.matches(spinnerOnly) || node.closest('.result-dialog, .gateway-result')) return false;
    if (node.classList.contains('is-loading')) return true;
    if (node.getAttribute('aria-busy') === 'true') return true;

    const copy = String(node.textContent || '').trim();
    if (!loadingCopy.test(copy)) return false;
    return node.matches('[role="status"], h1[id$="-title"]');
  };

  const sync = (scope = document) => {
    const nodes = scope instanceof HTMLElement && scope.matches(candidates)
      ? [scope, ...scope.querySelectorAll(candidates)]
      : [...scope.querySelectorAll(candidates)];
    nodes.forEach((node) => node.classList.toggle('vt-loading-shimmer', isLoading(node)));
  };

  const schedule = () => {
    if (scheduled) return;
    scheduled = true;
    window.requestAnimationFrame(() => {
      scheduled = false;
      sync();
    });
  };

  const observer = new MutationObserver(schedule);
  observer.observe(document.documentElement, {
    attributes: true,
    attributeFilter: ['aria-busy', 'class', 'disabled', 'hidden'],
    characterData: true,
    childList: true,
    subtree: true,
  });
  document.addEventListener('DOMContentLoaded', schedule, { once: true });

  return { sync };
})();

window.VeriTrustLoadingShimmer = VeriTrustLoadingShimmer;

const VeriTrustSiteChrome = (() => {
  const currentPage = () => veritrustPageId(window.location.pathname);

  const directChild = (tagName) => [...document.body.children]
    .find((node) => node.tagName === tagName.toUpperCase()) || null;

  const createHeader = (page) => {
    const header = document.createElement('header');
    header.className = 'tool-header-shell vt-page-header vt-site-header';
    header.dataset.siteHeader = 'true';
    header.innerHTML = `
      <div class="tool-header-inner">
        <a href="/" class="tool-header-brand" aria-label="VeriTrust Lab home">
          <img src="/assets/images/logo.png" alt="" class="tool-header-mark">
          <img src="/assets/images/brand.png" alt="VeriTrust Lab" class="tool-header-word">
        </a>
        <nav class="tool-header-links" aria-label="Primary navigation">
          <a href="/">Home</a>
          <a href="/phishing">Investigate</a>
          <a href="/gateway-powershell#live-smtp">Live SMTP</a>
          <a href="/verify-evidence">Verify Evidence</a>
        </nav>
        <div class="tool-header-actions">
          <a href="/auth" class="tool-header-login" hidden aria-hidden="true">Log in</a>
          <a href="/dashboard" class="tool-header-dashboard">Dashboard</a>
          <button class="tool-menu-toggle" aria-label="Open page menu" aria-expanded="false" type="button">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
              <path d="M4 6h16M4 12h16M4 18h16" stroke-linecap="round"/>
            </svg>
          </button>
        </div>
      </div>
    `;
    if (['dashboard', 'scans', 'cases', 'case', 'api-access', 'billing', 'account'].includes(page)) {
      header.querySelector('.tool-header-dashboard')?.classList.add('active');
      header.querySelector('.tool-header-dashboard')?.setAttribute('aria-current', 'page');
    }
    return header;
  };

  const createFooter = () => {
    const footer = document.createElement('footer');
    footer.className = 'vt-site-footer';
    footer.dataset.siteFooter = 'true';
    footer.innerHTML = `
      <div class="vt-site-footer-bottom">
        <span>&copy; 2026 VeriTrust Lab.</span>
        <span>Infrastructure location is approximate and does not identify a person.</span>
      </div>
    `;
    return footer;
  };

  const render = () => {
    const page = currentPage();
    document.body.dataset.page = page;
    document.body.classList.add('vt-unified-chrome');
    document.querySelector('.auth-back-button')?.remove();
    document.querySelectorAll('main .doc-content > footer.doc-section').forEach((footer) => footer.remove());

    const header = createHeader(page);
    const existingHeader = directChild('header');
    if (existingHeader) existingHeader.replaceWith(header);
    else document.body.prepend(header);

    const nestedAuthFooter = document.querySelector('.auth-footer');
    if (nestedAuthFooter) nestedAuthFooter.remove();
    const footer = createFooter();
    const existingFooter = directChild('footer');
    if (existingFooter) existingFooter.replaceWith(footer);
    else document.body.appendChild(footer);
    window.VeriTrustModules?.filter(document);
  };

  return { currentPage, render };
})();

document.addEventListener('DOMContentLoaded', async () => {
  VeriTrustSiteChrome.render();
  const access = await VeriTrustPageAccess;
  if (!access.allowed) return;

  const bindMenu = (toggleSelector, linksSelector) => {
    const menuToggle = document.querySelector(toggleSelector);
    const navLinks = document.querySelector(linksSelector);
    if (!menuToggle || !navLinks) return;
    if (menuToggle.dataset.menuManaged === 'inline') return;

    menuToggle.addEventListener('click', () => {
      const isOpen = navLinks.classList.toggle('is-open');
      menuToggle.setAttribute('aria-expanded', String(isOpen));
      menuToggle.closest('header')?.classList.toggle('menu-open', isOpen);
    });

    navLinks.querySelectorAll('a').forEach((link) => {
      link.addEventListener('click', () => {
        navLinks.classList.remove('is-open');
        menuToggle.setAttribute('aria-expanded', 'false');
        menuToggle.closest('header')?.classList.remove('menu-open');
      });
    });
  };

  const normalizePrimaryNavigation = () => {
    const nav = document.querySelector('.tool-header-links');
    if (!nav) return;

    const currentPage = veritrustPageId(window.location.pathname);
    const activeSection = {
      index: 'index',
      phishing: 'phishing',
      'phishing-result': 'phishing',
      'gateway-powershell': 'gateway-powershell',
      'verify-evidence': 'verify-evidence'
    }[currentPage];
    const primaryItems = [
      ['/', 'Home', 'index'],
      ['/phishing', 'Investigate', 'phishing'],
      ['/gateway-powershell#live-smtp', 'Live SMTP', 'gateway-powershell'],
      ['/verify-evidence', 'Verify Evidence', 'verify-evidence']
    ];
    nav.querySelectorAll(':scope > a').forEach((link) => link.remove());
    const fragment = document.createDocumentFragment();
    primaryItems.forEach(([href, label, section]) => {
      const link = document.createElement('a');
      link.href = href;
      link.textContent = label;
      if (section === activeSection) {
        link.classList.add('active');
        link.setAttribute('aria-current', 'page');
      }
      fragment.appendChild(link);
    });
    nav.prepend(fragment);

    const actions = nav.closest('.tool-header-inner')?.querySelector('.tool-header-actions');
    if (actions && !actions.querySelector('.tool-menu-toggle')) {
      const toggle = document.createElement('button');
      toggle.className = 'tool-menu-toggle';
      toggle.type = 'button';
      toggle.setAttribute('aria-label', 'Open page menu');
      toggle.setAttribute('aria-expanded', 'false');
      toggle.innerHTML = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M4 6h16M4 12h16M4 18h16" stroke-linecap="round"/></svg>';
      actions.appendChild(toggle);
    }
  };

  normalizePrimaryNavigation();
  window.VeriTrustModules?.filter(document);

  bindMenu('.menu-toggle', '.nav-links');
  bindMenu('.tool-menu-toggle', '.tool-header-links');

  const activeWorkspaceLink = document.querySelector('.workspace-nav a.active');
  const workspaceNav = activeWorkspaceLink?.closest('.workspace-nav');
  if (activeWorkspaceLink && workspaceNav) {
    requestAnimationFrame(() => {
      workspaceNav.scrollLeft = activeWorkspaceLink.offsetLeft
        - ((workspaceNav.clientWidth - activeWorkspaceLink.offsetWidth) / 2);
    });
  }

  const updateAuthNavigation = async () => {
    const authLinks = document.querySelectorAll('.tool-header-login, .login-link, .nav-actions a[href="/auth"]');
    const dashboardLinks = document.querySelectorAll('.tool-header-dashboard, a[href="/dashboard"]');
    const toolHeaderLinks = document.querySelector('.tool-header-links, #primary-navigation');
    const isAuthPage = VeriTrustSiteChrome.currentPage() === 'auth';

    const closeToolMenu = () => {
      const menuToggle = document.querySelector('.tool-menu-toggle, .menu-toggle');
      toolHeaderLinks?.classList.remove('is-open');
      menuToggle?.setAttribute('aria-expanded', 'false');
      menuToggle?.closest('header')?.classList.remove('menu-open');
    };

    const showAuthLink = (link) => {
      if (isAuthPage && link.classList.contains('tool-header-login')) {
        link.hidden = true;
        link.setAttribute('aria-hidden', 'true');
        return;
      }

      link.hidden = false;
      link.removeAttribute('aria-hidden');
      link.removeAttribute('aria-label');
      link.href = '/auth';
      link.classList.remove('is-logout');
      link.textContent = link.classList.contains('login-link')
        ? 'Login / Sign Up'
        : link.classList.contains('tool-header-login')
          ? 'Log in'
          : 'Login';
    };

    const hideAuthLink = (link) => {
      link.hidden = true;
      link.setAttribute('aria-hidden', 'true');
      link.removeAttribute('href');
      link.classList.remove('is-logout');
    };

    const bindLogout = (link) => {
      link.hidden = false;
      link.removeAttribute('aria-hidden');
      link.setAttribute('aria-label', 'Log out of VeriTrust Lab');
      link.href = '#sign-out';
      link.textContent = 'Log out';
      link.classList.add('is-logout');
      if (!link.dataset.logoutBound) {
        link.dataset.logoutBound = 'true';
        link.addEventListener('click', async (event) => {
          event.preventDefault();
          await window.VeriTrustSupabase.signOut();
          window.location.href = '/auth';
        });
      }
    };
    const ensureMobileMenuActions = (authState = 'signed-out') => {
      if (!toolHeaderLinks) return null;

      const sessionActive = authState === 'authenticated';

      let wrap = toolHeaderLinks.querySelector('.tool-header-mobile-actions');
      if (!wrap) {
        wrap = document.createElement('div');
        wrap.className = 'tool-header-mobile-actions';
        toolHeaderLinks.appendChild(wrap);
      }

      let dashboardAction = wrap.querySelector('[data-mobile-dashboard-action]');
      const hasDashboardNavLink = Boolean(toolHeaderLinks.querySelector(':scope > a[href="/dashboard"]'));
      if (hasDashboardNavLink && dashboardAction) {
        dashboardAction.remove();
      } else if (!hasDashboardNavLink && !dashboardAction) {
        dashboardAction = document.createElement('a');
        dashboardAction.href = '/dashboard';
        dashboardAction.textContent = 'Dashboard';
        dashboardAction.dataset.mobileDashboardAction = 'true';
        dashboardAction.addEventListener('click', closeToolMenu);
        wrap.appendChild(dashboardAction);
      }

      let authAction = wrap.querySelector('[data-mobile-auth-action]');
      if (authState === 'unavailable' || (!sessionActive && isAuthPage)) {
        authAction?.remove();
        return wrap;
      }

      if (!authAction) {
        authAction = document.createElement('a');
        authAction.dataset.mobileAuthAction = 'true';
        wrap.appendChild(authAction);
      }

      if (sessionActive && window.VeriTrustSupabase?.signOut) {
        bindLogout(authAction);
      } else {
        authAction.hidden = false;
        authAction.removeAttribute('aria-hidden');
        authAction.href = '/auth';
        authAction.textContent = 'Login / Sign Up';
        authAction.classList.remove('is-logout');
      }

      return wrap;
    };

    const session = access.session;

    if (session) {
      document.body.classList.add('vt-authenticated');
      document.body.classList.remove('vt-signed-out');

      authLinks.forEach(bindLogout);

      dashboardLinks.forEach((link) => {
        if (link.classList.contains('tool-header-dashboard')) {
          link.textContent = 'Dashboard';
        }
      });
      ensureMobileMenuActions('authenticated');
    } else if (access.sessionError) {
      document.body.classList.remove('vt-authenticated', 'vt-signed-out');
      document.body.classList.add('vt-session-unavailable');
      authLinks.forEach(hideAuthLink);
      ensureMobileMenuActions('unavailable');
    } else {
      document.body.classList.remove('vt-authenticated', 'vt-session-unavailable');
      document.body.classList.add('vt-signed-out');
      authLinks.forEach(showAuthLink);
      ensureMobileMenuActions('signed-out');
    }
  };

  await updateAuthNavigation();

  document.querySelectorAll('[data-auth-tab]').forEach((button) => {
    button.addEventListener('click', () => {
      const target = button.dataset.authTab;
      document.querySelectorAll('[data-auth-tab]').forEach((item) => item.classList.remove('active'));
      document.querySelectorAll('.auth-form').forEach((form) => form.classList.remove('active'));
      button.classList.add('active');
      const form = document.getElementById(target);
      if (form) form.classList.add('active');
    });
  });
});
