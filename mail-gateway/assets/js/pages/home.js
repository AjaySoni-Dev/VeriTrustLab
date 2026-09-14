document.documentElement.classList.add('js');

const homeHeader = document.getElementById('header');
const homeMenuToggle = document.querySelector('.menu-toggle');
const homeNavLinks = document.querySelector('.nav-links');
const reduceHomeMotion = window.matchMedia('(prefers-reduced-motion: reduce)');

const updateHomeScrollState = () => {
  homeHeader?.classList.toggle('is-scrolled', window.scrollY > 10);
};

updateHomeScrollState();
window.addEventListener('scroll', updateHomeScrollState, { passive: true });

const homeRevealElements = document.querySelectorAll('.reveal');
if (reduceHomeMotion.matches || !('IntersectionObserver' in window)) {
  homeRevealElements.forEach((element) => element.classList.add('active'));
} else {
  const revealOnScroll = new IntersectionObserver((entries, observer) => {
    entries.forEach((entry) => {
      if (!entry.isIntersecting) return;
      entry.target.classList.add('active');
      observer.unobserve(entry.target);
    });
  }, { threshold: 0.1, rootMargin: '0px 0px -30px 0px' });
  homeRevealElements.forEach((element) => revealOnScroll.observe(element));
}

const closeHomeMenu = () => {
  homeNavLinks?.classList.remove('is-open');
  homeMenuToggle?.setAttribute('aria-expanded', 'false');
  homeMenuToggle?.setAttribute('aria-label', 'Open navigation menu');
  document.body.classList.remove('menu-open');
};

homeMenuToggle?.addEventListener('click', () => {
  const isOpen = homeNavLinks?.classList.toggle('is-open') ?? false;
  homeMenuToggle.setAttribute('aria-expanded', String(isOpen));
  homeMenuToggle.setAttribute('aria-label', isOpen ? 'Close navigation menu' : 'Open navigation menu');
  document.body.classList.toggle('menu-open', isOpen);
});

homeNavLinks?.querySelectorAll('a').forEach((link) => link.addEventListener('click', closeHomeMenu));
document.addEventListener('keydown', (event) => {
  if (event.key !== 'Escape') return;
  closeHomeMenu();
  homeMenuToggle?.focus();
});
window.addEventListener('resize', () => {
  if (window.innerWidth > 1024) closeHomeMenu();
});

const COOKIE_CONSENT_KEY = 'vt-cookie-consent-v1';
const cookieConsentPanel = document.getElementById('cookie-consent');

const readCookieConsent = () => {
  try {
    const storedChoice = window.localStorage.getItem(COOKIE_CONSENT_KEY);
    if (storedChoice === 'all' || storedChoice === 'essential') return storedChoice;
  } catch (_) {
    // Consent can still be read from the cookie when storage is unavailable.
  }

  const consentCookie = document.cookie
    .split('; ')
    .find((entry) => entry.startsWith(`${COOKIE_CONSENT_KEY}=`));
  const cookieChoice = consentCookie?.split('=')[1];
  return cookieChoice === 'all' || cookieChoice === 'essential' ? cookieChoice : '';
};

const saveCookieConsent = (choice) => {
  document.documentElement.dataset.cookieConsent = choice;

  try {
    window.localStorage.setItem(COOKIE_CONSENT_KEY, choice);
  } catch (_) {
    // The first-party preference cookie remains the fallback.
  }

  const secureAttribute = window.location.protocol === 'https:' ? '; Secure' : '';
  document.cookie = `${COOKIE_CONSENT_KEY}=${choice}; Max-Age=31536000; Path=/; SameSite=Lax${secureAttribute}`;
  window.dispatchEvent(new CustomEvent('veritrust:cookie-consent', { detail: { choice } }));
};

const existingCookieConsent = readCookieConsent();
if (existingCookieConsent) {
  document.documentElement.dataset.cookieConsent = existingCookieConsent;
} else if (cookieConsentPanel) {
  cookieConsentPanel.hidden = false;
  window.requestAnimationFrame(() => cookieConsentPanel.classList.add('is-visible'));

  cookieConsentPanel.querySelectorAll('[data-cookie-choice]').forEach((button) => {
    button.addEventListener('click', () => {
      const choice = button.dataset.cookieChoice;
      if (choice !== 'all' && choice !== 'essential') return;

      saveCookieConsent(choice);
      cookieConsentPanel.classList.remove('is-visible');
      window.setTimeout(() => {
        cookieConsentPanel.hidden = true;
      }, reduceHomeMotion.matches ? 0 : 320);
    });
  });
}
