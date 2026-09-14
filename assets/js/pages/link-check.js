const qs = (selector, root = document) => root.querySelector(selector);
const qsa = (selector, root = document) => [...root.querySelectorAll(selector)];

const DEFAULT_CONFIG = {
  api: {
    linkCheck: '/api/link-check',
  },
};
const runtimeConfig = window.VeriTrust_CONFIG || window['VERI' + 'TRUST_CONFIG'] || {};
const config = {
  ...DEFAULT_CONFIG,
  ...runtimeConfig,
  api: {
    ...DEFAULT_CONFIG.api,
    ...(runtimeConfig.api || {}),
  },
};

let scanContextPromise = null;
let lastResult = null;
const analysisProgress = window.VeriTrustAnalysisProgress.create();

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (char) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  }[char]));
}

function setLog(message) {
  const node = qs('#activityLog');
  if (node) node.textContent = message;
}

function setLoading(button, loading, label) {
  if (!button) return;
  if (!button.dataset.defaultLabel) button.dataset.defaultLabel = button.textContent;
  button.disabled = loading;
  button.textContent = label || button.dataset.defaultLabel;
  button.classList.toggle('is-loading', loading);
  if (loading) button.setAttribute('aria-busy', 'true');
  else button.removeAttribute('aria-busy');
  button.classList.remove('vt-loading-shimmer');
}

function formatPercent(value) {
  return window.VeriTrustAnalysisResult.percent(value);
}

function riskBadgeClass(level) {
  const normalized = String(level || 'low').toLowerCase();
  if (!['low', 'medium', 'high', 'critical'].includes(normalized)) return 'risk-badge risk-badge-unknown';
  return `risk-badge risk-badge-${['low', 'medium', 'high', 'critical'].includes(normalized) ? normalized : 'medium'}`;
}

function riskClass(result) {
  const level = String(result.risk_level || '').toLowerCase();
  if (level === 'critical') return 'risk-critical';
  if (level === 'high') return 'risk-high';
  if (level === 'medium') return 'risk-medium';
  return level === 'low' ? 'risk-low' : '';
}

async function parseJsonResponse(response) {
  let data = null;
  try {
    data = await response.json();
  } catch {
    throw new Error(response.ok ? 'The server returned an unexpected response.' : `The server could not complete this check. Status ${response.status}.`);
  }
  if (!response.ok || data.ok === false) {
    const error = new Error(data?.error?.message || 'Request failed.');
    error.code = data?.error?.code || '';
    error.status = response.status;
    throw error;
  }
  return data;
}

async function requestJson(url, options) {
  return window.VeriTrustAnalysisResult.withDeadline(async (signal) => {
    let response;
    try { response = await fetch(url, { ...options, signal }); }
    catch (error) {
      if (signal.aborted) throw error;
      throw new Error('Unable to reach link analysis. Please check your connection and try again.');
    }
    return parseJsonResponse(response);
  });
}

async function getScanContext() {
  if (!window.VeriTrustSupabase?.isConfigured()) {
    throw new Error('Sign in to run and save this review.');
  }
  if (!scanContextPromise) scanContextPromise = window.VeriTrustSupabase.getSessionContext();
  try {
    return await scanContextPromise;
  } catch {
    scanContextPromise = null;
    throw new Error('Sign in to run and save this review.');
  }
}

async function authHeaders() {
  const session = await window.VeriTrustSupabase?.getSession();
  if (!session) throw new Error('Sign in before running a saved VeriTrust scan.');
  return {};
}

function normalizedReport(data) {
  const result = data.result || {};
  return {
    title: data.report?.title || 'VeriTrust Link Intelligence Report',
    scan_id: data.scan_id || data.scan?.id || null,
    scan_type: data.scan_type || 'link',
    created_at: data.created_at || new Date().toISOString(),
    model: {
      key: data.model?.key || '',
      name: data.model?.name || 'VeriTrust Swift',
      fallback_used: Boolean(data.model?.fallback_used || data.model?.fallback_from),
      fallback_from: data.model?.fallback_from || null,
      fallback_from_name: data.model?.fallback_from_name || null,
      fallback_reason: data.model?.fallback_reason || null,
      inference_mode: data.model?.inference_mode || null,
      provider_status: data.model?.provider_status || null,
    },
    result,
    scores: data.scores || [],
    report: data.report || {
      title: 'VeriTrust Link Intelligence Report',
      disclaimer: 'AI-assisted result. Not legal, forensic, cybersecurity, or final proof.',
      exportable: true,
    },
  };
}

function downloadJsonReport(data) {
  const report = normalizedReport(data);
  const id = report.scan_id ? String(report.scan_id).slice(0, 8) : Date.now();
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `veritrust-link-report-${id}.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

async function printReport(data) {
  const report = normalizedReport(data);
  if (window.VeriTrustReporting?.printReport) {
    await window.VeriTrustReporting.printReport(report);
    return;
  }
  window.print();
}

function summaryText(data) {
  const report = normalizedReport(data);
  const result = report.result || {};
  const extracted = result.extracted || {};
  return [
    report.title,
    `URL: ${extracted.normalized_url || extracted.input_url || 'N/A'}`,
    `Verdict: ${result.label || 'Unknown'}`,
    `Risk: ${result.risk_level || 'Low'}`,
    `Confidence: ${formatPercent(result.confidence)}`,
    result.confidence_band ? `Confidence band: ${result.confidence_band}` : '',
    `Model: ${report.model.name}`,
    report.model.fallback_used ? `Fallback used from: ${report.model.fallback_from || 'selected model'}` : '',
    result.summary || '',
    result.disclaimer || '',
  ].filter(Boolean).join('\n');
}

async function copySummary(data) {
  const text = summaryText(data);
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.setAttribute('readonly', '');
  textarea.style.position = 'fixed';
  textarea.style.left = '-9999px';
  document.body.appendChild(textarea);
  textarea.select();
  document.execCommand('copy');
  textarea.remove();
}

function renderLoadingResult() {
  window.VeriTrustResultDialog?.closeFor('linkResult');
  const target = qs('#linkResult');
  if (!target) return;
  target.classList.remove('result-empty', 'result-ready', 'vt-loading-shimmer');
  target.classList.add('result-loading');
  target.innerHTML = `
    <div class="loading-state">
      <span class="spinner" aria-hidden="true"></span>
      <strong>Analyzing link</strong>
      <p>Please wait while VeriTrust reviews the URL and risk patterns.</p>
    </div>
  `;
}

function renderSignalList(items) {
  if (!Array.isArray(items) || !items.length) {
    return '<p class="result-muted">No strong URL risk indicators were found.</p>';
  }
  return `
    <div class="signal-list">
      ${items.map((item) => `
        <div class="signal-item">
          <div>
            <strong>${escapeHtml(item.title || item.type || 'Signal')}</strong>
            <p>${escapeHtml(item.description || '')}</p>
          </div>
          <span class="${riskBadgeClass(item.severity || 'Medium')}">${escapeHtml(item.severity || 'Medium')}</span>
        </div>
      `).join('')}
    </div>
  `;
}

function renderExtracted(extracted = {}) {
  const details = [
    ['Extracted URL', extracted.normalized_url || extracted.input_url],
    ['Hostname', extracted.hostname],
    ['Domain', extracted.domain],
    ['Scheme', extracted.scheme],
    ['Path', extracted.path],
    ['URLs found', Array.isArray(extracted.urls_found) ? extracted.urls_found.join(', ') : ''],
  ];
  if (Object.prototype.hasOwnProperty.call(extracted, 'query_present')) {
    details.splice(5, 0, ['Query present', extracted.query_present ? 'Yes' : 'No']);
  }
  const visibleDetails = details.filter(([, value]) => value !== undefined && value !== null && value !== '');

  if (!visibleDetails.length) return '';

  return `
    <details class="result-details">
      <summary>Extracted details <span>${visibleDetails.length}</span></summary>
      <div class="entity-grid">
        ${visibleDetails.map(([label, value]) => `
          <div class="entity-group">
            <span>${escapeHtml(label)}</span>
            <strong>${escapeHtml(value)}</strong>
          </div>
        `).join('')}
      </div>
    </details>
  `;
}

function renderResult(data) {
  lastResult = data;
  const target = qs('#linkResult');
  if (!target) return;
  const result = data.result || {};
  const model = data.model || {};
  const labelLower = String(result.label || '').toLowerCase();
  const isBad = ['suspicious', 'phishing', 'malicious', 'unknown'].includes(labelLower);
  const confidence = formatPercent(result.confidence);
  const score = formatPercent(result.link_score);
  const fallback = Boolean(model.fallback_used || model.fallback_from);
  const modelMeta = result.model_meta || {};
  const fallbackReason = model.fallback_reason || modelMeta.fallback_reason || 'Hosted inference was unavailable; fallback scoring was used.';

  target.classList.remove('result-empty', 'result-loading', 'vt-loading-shimmer');
  target.classList.add('result-ready');
  target.innerHTML = `
    <div class="result-summary">
      <div>
        <span class="result-kicker">Verdict</span>
        <span class="final-label ${isBad ? 'bad' : labelLower === 'safe' ? 'good' : ''}">${escapeHtml(result.label || 'Unknown')}</span>
      </div>
      <span class="status-pill">${escapeHtml(model.name || modelMeta.name || 'VeriTrust Swift')}</span>
    </div>
    ${score !== 'Not available' ? `<div class="score-meter" aria-hidden="true"><span class="${riskClass(result)}" style="width:${Number.parseInt(score, 10) || 0}%"></span></div>` : ''}
    <div class="result-metrics">
      <div class="metric"><span>Confidence</span><strong>${confidence}</strong></div>
      <div class="metric"><span>Link score</span><strong>${score}</strong></div>
      <div class="metric"><span>Risk</span><strong class="${riskBadgeClass(result.risk_level || 'Unknown')}">${escapeHtml(result.risk_level || 'Unknown')}</strong></div>
    </div>
    <p class="result-note">${escapeHtml(result.summary || 'Link analysis complete.')}</p>
    ${fallback ? `<p class="fallback-notice">Fallback used: ${escapeHtml(model.fallback_from_name || model.fallback_from || modelMeta.fallback_from || 'selected model')} to ${escapeHtml(model.name || 'VeriTrust Swift')}. ${escapeHtml(fallbackReason)}</p>` : ''}
    ${data.warning?.message ? `<p class="fallback-notice">${escapeHtml(data.warning.message)}</p>` : ''}
    <details class="result-details">
      <summary>Indicators <span>${Array.isArray(result.indicators) ? result.indicators.length : 0}</span></summary>
      ${renderSignalList(result.indicators || [])}
    </details>
    ${renderExtracted(result.extracted || {})}
    <details class="result-details result-technical">
      <summary>Technical details</summary>
      <div class="result-meta">
        <span>Model: ${escapeHtml(model.name || 'VeriTrust Swift')}</span>
        <span>Confidence band: ${escapeHtml(result.confidence_band || 'N/A')}</span>
        ${data.scan_id || data.scan?.id ? `<span>Scan ID: ${escapeHtml(data.scan_id || data.scan.id)}</span>` : ''}
      </div>
      <p class="result-disclaimer">${escapeHtml(result.disclaimer || data.report?.disclaimer || 'AI-assisted result. Manual review is recommended.')}</p>
    </details>
    <div class="report-actions">
      <button class="btn btn-secondary" type="button" data-report-action="download" aria-label="Download JSON report">JSON</button>
      <button class="btn btn-secondary" type="button" data-report-action="print" aria-label="Save PDF report">Save PDF</button>
      <button class="btn btn-secondary" type="button" data-report-action="copy" aria-label="Copy result summary">Copy</button>
    </div>
  `;

  qs('[data-report-action="download"]', target)?.addEventListener('click', () => downloadJsonReport(data));
  qs('[data-report-action="print"]', target)?.addEventListener('click', () => printReport(data));
  qs('[data-report-action="copy"]', target)?.addEventListener('click', async () => {
    try {
      await copySummary(data);
      setLog('Result summary copied.');
    } catch {
      setLog('Unable to copy summary.');
    }
  });
  const shell = document.getElementById('linkResultShell');
  if (shell) { shell.hidden = false; shell.focus({ preventScroll: true }); }
  else window.VeriTrustResultDialog?.openFor('linkResult');
}

function renderError(message, details = {}) {
  lastResult = null;
  const target = qs('#linkResult');
  if (!target) return;
  const detailParts = [
    details.code ? `Code: ${details.code}` : '',
    details.status ? `Status: ${details.status}` : '',
  ].filter(Boolean);
  target.classList.remove('result-empty', 'result-loading', 'vt-loading-shimmer');
  target.classList.add('result-ready');
  target.innerHTML = `
    <div class="result-summary">
      <div>
        <span class="result-kicker">Status</span>
        <span class="final-label bad">Unable to analyze</span>
      </div>
      <span class="status-pill">VeriTrust Swift</span>
    </div>
    <p class="result-note">${escapeHtml(message || 'Link analysis failed.')}</p>
    ${detailParts.length ? `<p class="result-muted">${escapeHtml(detailParts.join(' · '))}</p>` : ''}
    <div class="result-section">
      <h3>Next step</h3>
      <p class="result-muted">Check that you are signed in, the URL starts with http:// or https://, and the deployment has the latest API route.</p>
    </div>
    <p class="result-disclaimer">No report was generated because this request did not complete.</p>
  `;
  const shell = document.getElementById('linkResultShell');
  if (shell) { shell.hidden = false; shell.focus({ preventScroll: true }); }
  else window.VeriTrustResultDialog?.openFor('linkResult');
}

async function analyzeLink() {
  const url = qs('#linkUrl')?.value.trim() || '';
  const contextText = qs('#linkContext')?.value.trim() || '';
  if (!url && !contextText) throw new Error('Please provide a valid URL or text containing a URL.');

  const context = await getScanContext();
  const headers = {
    'Content-Type': 'application/json',
    ...(await authHeaders()),
  };
  const data = await analysisProgress.request(config.api.linkCheck || '/api/link-check', {
    method: 'POST',
    headers,
    body: JSON.stringify({
      url,
      context: contextText,
      text: url || contextText,
      model: qs('#linkModel')?.value || 'swift',
      org_id: context?.organization?.id || null,
    }),
  });

  if (!data.result || typeof data.result !== 'object') throw new Error('The server response did not contain a link analysis report.');
  renderResult(data);
  if (data.warning?.message) setLog(data.warning.message);
  return data;
}

function bindCustomModelSelects() {
  const controls = qsa('[data-model-select]');
  const closeAll = (except = null) => {
    controls.forEach((control) => {
      if (control === except) return;
      control.classList.remove('open');
      qs('.model-select-trigger', control)?.setAttribute('aria-expanded', 'false');
    });
  };

  controls.forEach((control) => {
    const select = document.getElementById(control.dataset.modelSelect || '');
    const trigger = qs('.model-select-trigger', control);
    const options = qsa('.model-option', control);
    const label = qs('[data-model-label]', control);
    const desc = qs('[data-model-desc]', control);
    const badge = qs('[data-model-badge]', control);
    if (!select || !trigger || !options.length) return;

    const isDisabledOption = (option) => option?.dataset.disabled === 'true' || option?.getAttribute('aria-disabled') === 'true';
    const setValue = (value) => {
      const selected = options.find((option) => option.dataset.value === value && !isDisabledOption(option))
        || options.find((option) => !isDisabledOption(option))
        || options[0];
      select.value = selected.dataset.value || '';
      options.forEach((option) => {
        const active = option === selected;
        option.classList.toggle('active', active);
        option.setAttribute('aria-selected', String(active));
      });
      if (label) label.textContent = selected.dataset.label || '';
      if (desc) desc.textContent = selected.dataset.desc || '';
      if (badge) badge.textContent = selected.dataset.badge || '';
      closeAll();
    };

    trigger.addEventListener('click', (event) => {
      event.stopPropagation();
      const isOpen = control.classList.contains('open');
      closeAll(control);
      control.classList.toggle('open', !isOpen);
      trigger.setAttribute('aria-expanded', String(!isOpen));
    });

    options.forEach((option) => {
      option.addEventListener('click', (event) => {
        event.stopPropagation();
        if (isDisabledOption(option)) {
          setLog(`${option.dataset.label || 'This model'} is not available in this version.`);
          closeAll();
          return;
        }
        setValue(option.dataset.value || '');
      });
    });

    setValue(select.value || 'swift');
  });

  document.addEventListener('click', (event) => {
    if (!event.target.closest('[data-model-select]')) closeAll();
  });
}

document.addEventListener('DOMContentLoaded', async () => {
  const access = await window.VeriTrustPageAccess;
  if (!access?.allowed) return;

  bindCustomModelSelects();
  let busy = false;

  qs('#linkCheckForm')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (busy) return;
    busy = true;
    const button = qs('#linkSubmit');
    const controls = qsa('#linkCheckForm input, #linkCheckForm textarea');
    controls.forEach((control) => { control.disabled = true; });
    try {
      const shell = document.getElementById('linkResultShell');
      if (shell) shell.hidden = true;
      analysisProgress.begin();
      setLog('Analyzing link...');
      setLoading(button, true, 'Analyzing...');
      const data = await analyzeLink();
      analysisProgress.finish();
      if (!data?.warning?.message) {
        setLog('Link analysis complete.');
      }
    } catch (error) {
      analysisProgress.finish(error);
      lastResult = null;
      setLog('');
    } finally {
      busy = false;
      controls.forEach((control) => { control.disabled = false; });
      setLoading(button, false);
    }
  });

  window.VeriTrustLinkCheck = {
    getLastResult: () => lastResult,
  };
});
