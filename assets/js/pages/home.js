/* Progressive enhancement: all content and destinations work without this file. */
(() => {
  'use strict';
  document.addEventListener('DOMContentLoaded', () => {
    const motion = window.matchMedia('(prefers-reduced-motion: reduce)');
    const button = document.querySelector('.home-motion-toggle');
    let userPaused = false;
    const syncMotion = () => {
      const paused = userPaused || motion.matches;
      document.body.classList.toggle('home-fx-paused', paused);
      if (!button) return;
      button.hidden = motion.matches;
      button.setAttribute('aria-pressed', String(paused));
      button.textContent = paused ? 'Resume visual effects' : 'Pause visual effects';
    };
    button?.addEventListener('click', () => { userPaused = !userPaused; syncMotion(); });
    motion.addEventListener('change', syncMotion);
    syncMotion();

    // site.js renders the shared header before this listener. Bind synchronously
    // so navigation never depends on the asynchronous session request.
    const header = document.querySelector('.vt-site-header');
    const toggle = header?.querySelector('.tool-menu-toggle');
    const nav = header?.querySelector('.tool-header-links');
    if (!toggle || !nav) return;
    toggle.dataset.menuManaged = 'inline';
    nav.id = 'home-primary-navigation';
    toggle.setAttribute('aria-controls', nav.id);
    const setOpen = (open, returnFocus = false) => {
      nav.classList.toggle('is-open', open);
      header.classList.toggle('menu-open', open);
      toggle.setAttribute('aria-expanded', String(open));
      toggle.setAttribute('aria-label', open ? 'Close page menu' : 'Open page menu');
      if (returnFocus) toggle.focus();
    };
    toggle.addEventListener('click', () => setOpen(toggle.getAttribute('aria-expanded') !== 'true'));
    nav.addEventListener('click', (event) => { if (event.target.closest('a')) setOpen(false); });
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape' && toggle.getAttribute('aria-expanded') === 'true') setOpen(false, true);
    });
    document.addEventListener('click', (event) => { if (!header.contains(event.target)) setOpen(false); });
    header.addEventListener('focusout', (event) => {
      if (event.relatedTarget && !header.contains(event.relatedTarget)) setOpen(false);
    });
    window.matchMedia('(min-width: 1051px)').addEventListener('change', () => setOpen(false));
  });
})();
