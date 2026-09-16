document.addEventListener('DOMContentLoaded', async () => {
  const table = document.querySelector('[data-recent-scans]');
  const filters = document.querySelector('[data-scan-filters]');
  const statusText = document.querySelector('[data-dashboard-status-text]');
  const SCAN_BATCH_SIZE = 5;
  const EMAIL_INPUT_MODES = new Set(['plain_text', 'raw_eml', 'trusted_receiver_event']);
  const EMAIL_V2_SOURCES = new Set(['phishing-v2', 'trusted-receiver-v2']);
  let activeFilter = 'recent';
  let visibleLimit = SCAN_BATCH_SIZE;
  let emailScans = [];

  const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[char]));

  const scanResult = (scan) => Array.isArray(scan?.scan_results) ? (scan.scan_results[0] || {}) : (scan?.scan_results || {});

  const isEmailForensicScan = (scan = {}) => {
    const metadata = scan.metadata || {};
    const source = String(scan.source || metadata.gateway?.source || '').toLowerCase();
    return String(scan.scan_type || '').toLowerCase() === 'phishing'
      || metadata.evidence_schema === 'phishing-evidence-7'
      || EMAIL_INPUT_MODES.has(String(metadata.input_mode || '').toLowerCase())
      || EMAIL_V2_SOURCES.has(source);
  };

  const emailForensicStage = (scan = {}) => ({
    plain_text: 'Pasted Text',
    raw_eml: 'Original EML',
    trusted_receiver_event: 'Trusted Receiver',
  }[String(scan.metadata?.input_mode || '').toLowerCase()] || 'Email Evidence');

  const titleCase = (value) => {
    const text = String(value || 'unknown').trim();
    return text ? text.charAt(0).toUpperCase() + text.slice(1).toLowerCase() : 'Unknown';
  };

  const formatPercent = (value) => `${Math.round(Math.max(0, Math.min(1, Number(value) || 0)) * 100)}%`;
  const formatDate = (value) => {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? 'Unknown' : date.toLocaleDateString();
  };
  const riskLevel = (scan) => String(scan.risk_level || scanResult(scan).risk_level || 'unknown').toLowerCase();
  const isHighRisk = (scan) => ['high', 'critical'].includes(riskLevel(scan));
  const isTrustedReceiver = (scan) => String(scan.metadata?.input_mode || '').toLowerCase() === 'trusted_receiver_event';

  const filterOptions = [
    ['recent', 'Recent'],
    ['high', 'High Risk'],
    ['trusted', 'Trusted SMTP'],
  ];

  const matchingScans = () => emailScans.filter((scan) => {
    if (activeFilter === 'high') return isHighRisk(scan);
    if (activeFilter === 'trusted') return isTrustedReceiver(scan);
    return true;
  });

  const renderFilters = () => {
    if (!filters) return;
    filters.innerHTML = filterOptions.map(([value, label]) => `<button class="${activeFilter === value ? 'active' : ''}" type="button" data-scan-filter="${value}">${label}</button>`).join('');
    filters.querySelectorAll('[data-scan-filter]').forEach((button) => {
      button.addEventListener('click', () => {
        activeFilter = button.dataset.scanFilter || 'recent';
        visibleLimit = SCAN_BATCH_SIZE;
        renderScans();
      });
    });
  };

  const renderScans = () => {
    if (!table) return;
    table.removeAttribute('aria-busy');
    renderFilters();
    const matches = matchingScans();
    const visible = matches.slice(0, visibleLimit);

    if (!emailScans.length) {
      table.innerHTML = '<div class="empty-state-table"><strong>No email investigations yet.</strong><p>Start with pasted text, upload an original EML, or use the trusted SMTP receiver.</p></div>';
      return;
    }
    if (!matches.length) {
      table.innerHTML = '<div class="empty-state-table"><strong>No investigations match this filter.</strong><p>Choose another evidence view or run a new investigation.</p></div>';
      return;
    }

    table.innerHTML = `
      <div class="scan-table" role="table" aria-label="Recent email investigations">
        <div class="scan-row scan-head" role="row"><span>Evidence</span><span>Verdict</span><span>Risk</span><span>Confidence</span><span>Actions</span></div>
        ${visible.map((scan, index) => {
    const result = scanResult(scan);
    const label = result.label || scan.final_label || scan.status || 'Unknown';
    const risk = titleCase(result.risk_level || scan.risk_level || 'unknown');
    const confidence = Number(result.confidence || scan.confidence || 0);
    const indicators = Array.isArray(result.indicators) ? result.indicators.slice(0, 5) : [];
    return `
          <div class="scan-row scan-row-rich" role="row">
            <span data-label="Evidence" class="scan-type-with-stage"><strong>Email Investigation</strong><small>${escapeHtml(emailForensicStage(scan))}</small></span>
            <span data-label="Verdict" class="scan-verdict ${isHighRisk(scan) ? 'scan-verdict-danger' : ''}">${escapeHtml(titleCase(label))}</span>
            <span data-label="Risk"><strong class="risk-badge risk-badge-${escapeHtml(String(risk).toLowerCase())}">${escapeHtml(risk)}</strong></span>
            <span data-label="Confidence">${escapeHtml(formatPercent(confidence))} · ${escapeHtml(formatDate(scan.created_at))}</span>
            <span class="scan-actions" data-label="Actions"><button type="button" data-scan-action="open-email" data-scan-index="${index}">Open Investigation</button><button type="button" data-scan-action="email-json" data-scan-index="${index}">Evidence JSON</button></span>
          </div>
          <details class="scan-detail-row"><summary>View evidence summary</summary><p>${escapeHtml(result.explanation || 'Saved email-forensic result.')}</p>${indicators.length ? `<div class="scan-detail-signals">${indicators.map((item) => `<span>${escapeHtml(typeof item === 'string' ? item : (item?.title || item?.description || item?.label || item?.code || 'Signal'))}</span>`).join('')}</div>` : ''}<p class="scan-detail-id">Evidence stage: ${escapeHtml(emailForensicStage(scan))} · Scan ID: ${escapeHtml(scan.id)}</p></details>`;
  }).join('')}
      </div>
      ${matches.length > SCAN_BATCH_SIZE ? `<div class="scan-pagination"><p>Showing ${visible.length} of ${matches.length} investigations</p>${visible.length < matches.length ? '<button class="btn btn-secondary" type="button" data-load-more-scans>Load more</button>' : ''}</div>` : ''}`;

    table.querySelectorAll('[data-scan-action]').forEach((button) => {
      button.addEventListener('click', () => {
        const scan = visible[Number(button.dataset.scanIndex || 0)];
        if (!scan) return;
        if (button.dataset.scanAction === 'open-email') globalThis.location.href = `/phishing-result?scan_id=${encodeURIComponent(scan.id)}`;
        if (button.dataset.scanAction === 'email-json') globalThis.location.href = `/api/v2/phishing/export/${encodeURIComponent(scan.id)}/json`;
      });
    });
    table.querySelector('[data-load-more-scans]')?.addEventListener('click', () => {
      visibleLimit += SCAN_BATCH_SIZE;
      renderScans();
    });
  };

  try {
    if (!window.VeriTrustSupabase?.isConfigured()) throw new Error('Supabase is not configured for this deployment.');
    const session = await window.VeriTrustSupabase.getSession();
    if (!session) {
      globalThis.location.href = `/auth?next=${encodeURIComponent('/dashboard')}`;
      return;
    }
    const context = await window.VeriTrustSupabase.getDashboard({ limit: 100 });
    const records = window.VeriTrustModules?.filterRecords(context.scans || []) || context.scans || [];
    emailScans = records.filter(isEmailForensicScan);
    renderScans();
    document.body.classList.remove('dashboard-is-loading');
  } catch (error) {
    document.body.classList.remove('dashboard-is-loading');
    if (statusText) statusText.textContent = error.message || 'Unable to load saved investigations.';
    if (table) {
      table.removeAttribute('aria-busy');
      table.innerHTML = '<div class="empty-state-table"><strong>Unable to load investigations.</strong><p>Check the authenticated deployment configuration and try again.</p></div>';
    }
  }
});
