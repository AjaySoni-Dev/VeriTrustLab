(function modelPerformance(global) {
  const summary = document.querySelector('[data-model-governance]');
  const root = document.querySelector('[data-model-cards]');
  if (!summary || !root) return;
  const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));

  async function load() {
    const endpoint = global.VeriTrust_CONFIG?.api?.modelCards || '/api/model-cards';
    const response = await fetch(endpoint, { headers: { Accept: 'application/json' }, cache: 'no-store' });
    const payload = await response.json().catch(() => null);
    if (!response.ok || payload?.ok === false) throw new Error(payload?.error?.message || 'Model governance information is unavailable.');
    const cards = Array.isArray(payload.cards) ? payload.cards : [];
    summary.setAttribute('aria-busy', 'false');
    if (!cards.length) {
      summary.innerHTML = '<strong>Independent validation pending</strong><p>Five active model paths are registered, but none has an approved, published model card. VeriTrust therefore displays no benchmark claim.</p>';
      root.innerHTML = '<div class="model-card-empty"><strong>No published model cards</strong><p>Evaluation data, calibration, thresholds, limitations, and approval evidence must be recorded before publication.</p></div>';
      return;
    }
    summary.innerHTML = `<strong>${cards.length} published model card${cards.length === 1 ? '' : 's'}</strong><p>Only approved registry content is shown below.</p>`;
    root.innerHTML = cards.map((card) => `
      <article class="model-card-public">
        <div><span>${escapeHtml(card.model_key)}</span><strong>${escapeHtml(card.display_name)}</strong></div>
        <p><b>Version:</b> ${escapeHtml(card.model_version)} &middot; Card ${escapeHtml(card.card_version)}</p>
        <p><b>Intended use:</b> ${escapeHtml(card.intended_use)}</p>
        <p><b>Limitations:</b> ${escapeHtml(card.limitations)}</p>
        <details><summary>Evaluation and safeguards</summary><pre>${escapeHtml(JSON.stringify({ evaluation: card.evaluation_summary, calibration: card.calibration, thresholds: card.thresholds, unknown_policy: card.unknown_policy, human_review: card.human_review_policy }, null, 2))}</pre></details>
        <small>Published ${escapeHtml(card.published_at ? new Date(card.published_at).toLocaleDateString() : 'date unavailable')} &middot; SHA-256 ${escapeHtml(card.checksum)}</small>
      </article>
    `).join('');
  }

  load().catch((error) => {
    summary.setAttribute('aria-busy', 'false');
    summary.innerHTML = `<strong>Registry unavailable</strong><p>${escapeHtml(error.message)}</p>`;
    root.innerHTML = '<div class="model-card-empty"><strong>No unverified claims are shown</strong><p>Try again later.</p></div>';
  });
})(window);
