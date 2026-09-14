(function exposeScanLauncher(root, factory) {
  const api = factory(root);
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.VeriTrustScanLauncher = api;
})(typeof window !== 'undefined' ? window : null, (root) => {
  function shouldUseGui({ width, userAgentMobile = false } = {}) {
    return Boolean(userAgentMobile) || Number(width) < 768;
  }

  function browserIsMobile() {
    return shouldUseGui({
      width: root?.innerWidth || 0,
      userAgentMobile: root?.navigator?.userAgentData?.mobile === true
        || /Android|iPhone|iPad|iPod|Mobile|IEMobile|Opera Mini/i.test(root?.navigator?.userAgent || ''),
    });
  }

  function bind() {
    if (!root?.document) return;
    const launcher = root.document.querySelector('[data-scan-launcher]');
    const dialog = root.document.getElementById('scan-mode-dialog');
    if (!launcher || !dialog) return;

    launcher.addEventListener('click', (event) => {
      if (browserIsMobile()) return;
      if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      event.preventDefault();
      if (typeof dialog.showModal === 'function') dialog.showModal();
      else dialog.setAttribute('open', '');
    });

    dialog.addEventListener('click', (event) => {
      if (event.target !== dialog) return;
      if (typeof dialog.close === 'function') dialog.close();
      else dialog.removeAttribute('open');
    });

    root.addEventListener('resize', () => {
      if (browserIsMobile() && dialog.open) {
        if (typeof dialog.close === 'function') dialog.close();
        else dialog.removeAttribute('open');
        root.location.assign(launcher.href);
      }
    });
  }

  if (root?.document) {
    if (root.document.readyState === 'loading') root.document.addEventListener('DOMContentLoaded', bind);
    else bind();
  }

  return Object.freeze({ shouldUseGui });
});
