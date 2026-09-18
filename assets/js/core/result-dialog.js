(() => {
  const bodyClass = 'result-dialog-is-open';

  const dialogFor = (targetId) => document.getElementById(targetId)?.closest('.result-dialog');

  const syncBody = () => {
    document.body.classList.toggle(bodyClass, Boolean(document.querySelector('.result-dialog[open]')));
  };

  const clearShimmer = (dialog) => {
    dialog.classList.remove('vt-loading-shimmer');
    dialog.querySelectorAll('.vt-loading-shimmer').forEach((node) => {
      node.classList.remove('vt-loading-shimmer');
    });
  };

  const openFor = (targetId) => {
    const dialog = dialogFor(targetId);
    if (!dialog) return;
    clearShimmer(dialog);
    if (!dialog.open) {
      if (typeof dialog.showModal === 'function') dialog.showModal();
      else dialog.setAttribute('open', '');
    }
    syncBody();
    dialog.querySelector('[data-result-dialog-close]')?.focus({ preventScroll: true });
  };

  const closeFor = (targetId) => {
    const dialog = dialogFor(targetId);
    if (!dialog?.open) return;
    if (typeof dialog.close === 'function') dialog.close();
    else dialog.removeAttribute('open');
    syncBody();
  };

  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.result-dialog').forEach((dialog) => {
      dialog.querySelector('[data-result-dialog-close]')?.addEventListener('click', () => {
        if (typeof dialog.close === 'function') dialog.close();
        else dialog.removeAttribute('open');
        syncBody();
      });

      dialog.addEventListener('cancel', () => requestAnimationFrame(syncBody));
      dialog.addEventListener('close', syncBody);
      dialog.addEventListener('click', (event) => {
        if (event.target !== dialog) return;
        const box = dialog.getBoundingClientRect();
        const inside = event.clientX >= box.left && event.clientX <= box.right
          && event.clientY >= box.top && event.clientY <= box.bottom;
        if (!inside) dialog.close();
      });
    });
  });

  window.VeriTrustResultDialog = { closeFor, openFor };
})();
