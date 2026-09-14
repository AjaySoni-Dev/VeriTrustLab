(function accountGovernance(global) {
  const api = () => global.VeriTrustSupabase;
  const config = () => global.VeriTrust_CONFIG?.api || {};
  const panel = document.querySelector('[data-privacy-panel]');
  if (!panel) return;

  const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[character]));
  const message = (value, tone = '') => {
    const node = document.querySelector('[data-privacy-message]');
    if (!node) return;
    node.textContent = value;
    node.dataset.tone = tone;
  };
  const title = (value) => String(value || 'unknown').replaceAll('_', ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());
  const formatDate = (value) => value && !Number.isNaN(Date.parse(value)) ? new Date(value).toLocaleString() : 'Not available';

  function setSignedOutState(detail = 'Sign in to view and create data-rights requests.') {
    panel.setAttribute('aria-busy', 'false');
    const status = document.querySelector('[data-privacy-status]');
    if (status) { status.textContent = 'Sign in required'; status.className = 'status-pill warn'; }
    document.querySelector('[data-request-export]')?.setAttribute('disabled', '');
    document.querySelector('[data-request-erasure]')?.setAttribute('disabled', '');
    message(detail);
  }

  function renderRequests(requests) {
    const root = document.querySelector('[data-privacy-requests]');
    if (!root) return;
    if (!requests.length) {
      root.innerHTML = '<div class="model-card-empty"><strong>No active requests</strong><p>Your verified export and erasure requests will appear here.</p></div>';
      return;
    }
    root.innerHTML = requests.map((request) => `
      <article class="privacy-request-card">
        <div><strong>${escapeHtml(title(request.request_type))}</strong><span>${escapeHtml(request.display_id)}</span></div>
        <span class="status-pill ${request.status === 'completed' ? 'safe' : request.status === 'failed' ? 'danger' : 'warn'}">${escapeHtml(title(request.status))}</span>
        <p>Requested ${escapeHtml(formatDate(request.created_at))}. Due ${escapeHtml(formatDate(request.due_at))}.</p>
        ${request.download_url ? `<a class="btn btn-secondary" href="${escapeHtml(request.download_url)}" rel="nofollow">Download export</a>` : ''}
        ${request.failure_code ? `<p class="governance-error">${escapeHtml(title(request.failure_code))}</p>` : ''}
      </article>
    `).join('');
  }

  function renderPolicy(policy) {
    const root = document.querySelector('[data-privacy-policy]');
    if (!root) return;
    root.innerHTML = `
      <div><span>Service event payload</span><strong>${escapeHtml(policy.billing_event_payload_days)} days</strong></div>
      <div><span>Operational telemetry</span><strong>${escapeHtml(policy.operational_event_days)} days</strong></div>
      <div><span>Raw artifact policy</span><strong>${escapeHtml(policy.raw_artifact_retention_hours)} hours</strong></div>
      <div><span>Automated deletion</span><strong>${policy.retention_enforcement_enabled ? 'Approved and enabled' : 'Disabled pending approval'}</strong></div>
    `;
  }

  async function load() {
    if (!api()?.isConfigured?.()) {
      setSignedOutState('Account services are not configured in this environment.');
      return;
    }
    const session = await api()?.getSession();
    if (!session) {
      setSignedOutState();
      return;
    }
    const payload = await api().callAppApi(config().privacy || '/api/privacy', { cache: 'no-store' });
    renderPolicy(payload.policy);
    renderRequests(payload.requests || []);
    const status = document.querySelector('[data-privacy-status]');
    if (status) { status.textContent = 'Protected'; status.className = 'status-pill safe'; }
    message(payload.legal_holds?.length ? `${payload.legal_holds.length} active legal hold(s) apply to this workspace.` : 'No active workspace legal holds were returned for your role.');
    panel.setAttribute('aria-busy', 'false');
  }

  async function request(action, button) {
    if (action === 'erasure' && !global.confirm('Start an erasure review? VeriTrust will verify legal holds and organization-owned records before any deletion.')) return;
    button.disabled = true;
    const original = button.textContent;
    button.textContent = action === 'export' ? 'Requesting export…' : 'Starting review…';
    try {
      const payload = await api().callAppApi(config().privacy || '/api/privacy', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action, scope: { requested_from: 'account_ui' } }),
      });
      await load();
      message(payload.request?.duplicate ? 'An equivalent request is already active.' : 'Request accepted. Status will update as the worker progresses.', 'success');
    } catch (error) {
      message(error.message || 'Unable to create the request.', 'error');
    } finally {
      button.disabled = false;
      button.textContent = original;
    }
  }

  document.querySelector('[data-request-export]')?.addEventListener('click', (event) => request('export', event.currentTarget));
  document.querySelector('[data-request-erasure]')?.addEventListener('click', (event) => request('erasure', event.currentTarget));
  load().catch((error) => {
    setSignedOutState(error.message || 'Privacy controls are temporarily unavailable.');
    message(error.message || 'Privacy controls are temporarily unavailable.', 'error');
  });
})(window);
