(function caseWorkspace(global) {
  'use strict';

  const WRITE_ROLES = new Set(['owner', 'admin', 'analyst']);
  const state = { case: null, role: 'viewer', user: null, busy: false };

  const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[char]));

  const titleCase = (value) => String(value || 'unknown')
    .replaceAll('_', ' ')
    .replace(/\b\w/gu, (letter) => letter.toUpperCase());

  const formatDate = (value) => {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? 'Unknown time' : date.toLocaleString();
  };

  const formatPercent = (value) => {
    const number = Number(value);
    return Number.isFinite(number) ? `${Math.round(Math.max(0, Math.min(1, number)) * 100)}%` : 'Unknown';
  };

  const truncate = (value, length = 150) => {
    const text = String(value || '').trim();
    return text.length > length ? `${text.slice(0, length - 1)}…` : text;
  };

  const setStatus = (message, error = false) => {
    const node = document.querySelector('[data-case-status]');
    if (!node) return;
    node.textContent = message;
    node.classList.toggle('case-error', error);
  };

  const statusPill = (value) => `<span class="case-status-pill" data-status="${escapeHtml(value)}">${escapeHtml(titleCase(value))}</span>`;
  const priorityPill = (value) => `<span class="case-priority-pill" data-priority="${escapeHtml(value)}">${escapeHtml(titleCase(value))}</span>`;
  const riskPill = (value) => `<span class="case-chip">Risk: ${escapeHtml(titleCase(value))}</span>`;

  function renderCaseList(cases) {
    const target = document.querySelector('[data-case-list]');
    if (!target) return;
    const rows = Array.isArray(cases) ? cases : [];
    const counts = {
      open: rows.filter((item) => item.status === 'open').length,
      review: rows.filter((item) => item.status === 'in_review').length,
      decided: rows.filter((item) => item.status === 'decided').length,
      high: rows.filter((item) => ['high', 'critical'].includes(item.risk_level)).length,
    };
    for (const [selector, value] of [
      ['[data-case-count-open]', counts.open],
      ['[data-case-count-review]', counts.review],
      ['[data-case-count-decided]', counts.decided],
      ['[data-case-count-high]', counts.high],
    ]) {
      const node = document.querySelector(selector);
      if (node) node.textContent = String(value);
    }

    if (!rows.length) {
      target.innerHTML = '<div class="empty-state-table"><strong>No cases match this queue.</strong><p>Change the filters or run a new scan. Every completed detection becomes a review case automatically.</p></div>';
      return;
    }
    target.innerHTML = `<div class="case-queue">${rows.map((item) => {
      const decision = item.current_decision || {};
      const assignment = item.assigned_to
        ? (item.assigned_to === state.user?.id ? 'Assigned to you' : 'Assigned')
        : 'Unassigned';
      return `<a class="case-queue-item" href="case.html?id=${encodeURIComponent(item.id)}">
        <div class="case-queue-title">
          <div class="case-chip-row">${statusPill(item.status)} ${priorityPill(item.priority)}</div>
          <strong>${escapeHtml(item.title)}</strong>
          <p>${escapeHtml(truncate(item.summary || decision.rationale || 'Awaiting evidence and review.'))}</p>
          <span class="case-meta">${escapeHtml(item.display_id)} · ${escapeHtml(item.evidence_count)} evidence item${item.evidence_count === 1 ? '' : 's'} · ${escapeHtml(assignment)}</span>
        </div>
        <div><span class="case-meta">Current outcome</span><strong>${escapeHtml(titleCase(decision.outcome || 'pending'))}</strong></div>
        <div><span class="case-meta">Updated</span><strong>${escapeHtml(formatDate(item.updated_at))}</strong></div>
        <div>${riskPill(item.risk_level)}</div>
      </a>`;
    }).join('')}</div>`;
  }

  async function loadCaseList(filters = {}) {
    setStatus('Loading the case queue.');
    const payload = await global.VeriTrustSupabase.getCases({ limit: 100, ...filters });
    state.role = String(payload.role || 'viewer').toLowerCase();
    state.user = payload.user || null;
    renderCaseList(payload.cases || []);
    setStatus(`${payload.cases?.length || 0} investigation case${payload.cases?.length === 1 ? '' : 's'} in this view.`);
  }

  function evidenceIndicators(item) {
    const indicators = Array.isArray(item.indicators) ? item.indicators : [];
    if (!indicators.length) return '';
    return `<div class="case-chip-row">${indicators.slice(0, 8).map((indicator) => {
      const label = typeof indicator === 'string'
        ? indicator
        : indicator?.title || indicator?.description || indicator?.label || indicator?.code || 'Signal';
      return `<span class="case-chip">${escapeHtml(truncate(label, 80))}</span>`;
    }).join('')}</div>`;
  }

  function renderEvidence(caseRow) {
    const target = document.querySelector('[data-case-evidence]');
    if (!target) return;
    if (!caseRow.evidence?.length) {
      target.innerHTML = '<div class="empty-state-table"><strong>No normalized evidence yet.</strong><p>The source analysis may still be processing or may have failed.</p></div>';
      return;
    }
    const disabled = !WRITE_ROLES.has(state.role) || caseRow.status === 'closed' ? ' disabled' : '';
    target.innerHTML = `<div class="case-evidence-list">${caseRow.evidence.map((item) => {
      const provenance = item.provenance || {};
      const model = provenance.model_key || provenance.model_version || item.evidence_type;
      return `<article class="case-evidence-card">
        <label><input type="checkbox" value="${escapeHtml(item.id)}" data-case-evidence-check${disabled}>
          <span><strong>${escapeHtml(item.title)}</strong><p>${escapeHtml(item.summary || 'Normalized detection evidence.')}</p>
            <div class="case-chip-row"><span class="case-chip">${escapeHtml(titleCase(item.verdict))}</span>${riskPill(item.risk_level)}<span class="case-chip">Confidence: ${escapeHtml(formatPercent(item.confidence))}</span></div>
            ${evidenceIndicators(item)}
            <span class="case-evidence-provenance">Source: ${escapeHtml(item.source_type)} / ${escapeHtml(item.source_id)} · Model: ${escapeHtml(model || 'unknown')} · Captured ${escapeHtml(formatDate(item.created_at))}</span>
          </span>
        </label>
      </article>`;
    }).join('')}</div>`;
    target.querySelectorAll('[data-case-evidence-check]').forEach((input) => input.addEventListener('change', updateEvidenceSelection));
  }

  function renderDecisions(caseRow) {
    const target = document.querySelector('[data-case-decisions]');
    if (!target) return;
    if (!caseRow.decisions?.length) {
      target.innerHTML = '<div class="empty-state-table"><strong>No decision yet.</strong><p>Machine assessments and analyst conclusions will appear here.</p></div>';
      return;
    }
    target.innerHTML = caseRow.decisions.slice().reverse().map((item) => `<article class="case-decision-card" data-kind="${escapeHtml(item.decision_kind)}">
      <div class="case-chip-row"><span class="case-chip">${escapeHtml(titleCase(item.decision_kind))}</span><span class="case-chip">${escapeHtml(titleCase(item.outcome))}</span>${riskPill(item.risk_level)}</div>
      <strong>Decision ${escapeHtml(item.sequence)}</strong>
      <p>${escapeHtml(item.rationale)}</p>
      <span class="case-meta">${escapeHtml(formatDate(item.created_at))} · ${escapeHtml(item.evidence_ids?.length || 0)} cited evidence item${item.evidence_ids?.length === 1 ? '' : 's'}</span>
    </article>`).join('');
  }

  function renderEvents(caseRow) {
    const target = document.querySelector('[data-case-events]');
    if (!target) return;
    const events = Array.isArray(caseRow.events) ? caseRow.events : [];
    target.innerHTML = events.length ? events.slice().reverse().map((item) => `<div class="case-audit-item"><time datetime="${escapeHtml(item.created_at)}">${escapeHtml(formatDate(item.created_at))}</time><span>${escapeHtml(titleCase(item.event_type))}</span></div>`).join('') : '<p class="case-meta">No audit events are available.</p>';
  }

  function renderWorkflow(caseRow) {
    const target = document.querySelector('[data-case-workflow]');
    if (!target) return;
    const canWrite = WRITE_ROLES.has(state.role);
    const analystDecision = caseRow.decisions?.some((item) => ['analyst', 'analyst_override'].includes(item.decision_kind));
    document.querySelector('[data-analyst-panel]')?.toggleAttribute('hidden', !canWrite || caseRow.status === 'closed');
    const access = document.querySelector('[data-case-access]');
    if (access) access.textContent = canWrite ? `You have ${titleCase(state.role)} review access.` : 'Viewer access is read-only.';

    target.innerHTML = `<div class="case-workflow-controls">
      <div class="case-chip-row">${statusPill(caseRow.status)} ${priorityPill(caseRow.priority)} ${riskPill(caseRow.risk_level)}</div>
      <p class="case-meta">${caseRow.assigned_to ? (caseRow.assigned_to === state.user?.id ? 'Assigned to you.' : `Assigned to ${caseRow.assigned_to}.`) : 'This case is unassigned.'}</p>
      ${canWrite ? `<label>Priority<select data-case-priority>
        ${['low', 'normal', 'high', 'urgent'].map((value) => `<option value="${value}"${value === caseRow.priority ? ' selected' : ''}>${titleCase(value)}</option>`).join('')}
      </select></label><div class="case-workflow-actions">
        ${caseRow.assigned_to === state.user?.id
    ? '<button class="btn btn-secondary" type="button" data-case-action="release">Release</button>'
    : '<button class="btn btn-secondary" type="button" data-case-action="take">Take case</button>'}
        ${caseRow.status === 'closed'
    ? '<button class="btn btn-secondary" type="button" data-case-action="reopen">Reopen</button>'
    : analystDecision
      ? '<button class="btn btn-secondary" type="button" data-case-action="close">Close case</button>'
      : '<button class="btn btn-secondary" type="button" data-case-action="review">Mark in review</button>'}
      </div>` : ''}
    </div>`;

    if (!canWrite) return;
    target.querySelector('[data-case-priority]')?.addEventListener('change', (event) => runWorkflow({ priority: event.target.value }, event.target));
    target.querySelectorAll('[data-case-action]').forEach((button) => button.addEventListener('click', () => {
      const action = button.dataset.caseAction;
      if (action === 'take') runWorkflow({ assigned_to: state.user.id, status: caseRow.status === 'open' ? 'in_review' : caseRow.status }, button);
      if (action === 'release') runWorkflow({ assigned_to: null, status: caseRow.status === 'in_review' ? 'open' : caseRow.status }, button);
      if (action === 'review') runWorkflow({ status: 'in_review' }, button);
      if (action === 'close') runWorkflow({ status: 'closed' }, button);
      if (action === 'reopen') runWorkflow({ status: 'open' }, button);
    }));
  }

  function updateEvidenceSelection() {
    const count = document.querySelectorAll('[data-case-evidence-check]:checked').length;
    const node = document.querySelector('[data-evidence-selection]');
    if (node) node.textContent = `${count} evidence item${count === 1 ? '' : 's'} selected.`;
  }

  function renderDetail(caseRow) {
    state.case = caseRow;
    const display = document.querySelector('[data-case-display]');
    const title = document.querySelector('[data-case-title]');
    const badges = document.querySelector('[data-case-badges]');
    if (display) display.textContent = `Workspace / ${caseRow.display_id}`;
    if (title) title.textContent = caseRow.title;
    if (badges) badges.innerHTML = `${statusPill(caseRow.status)} ${priorityPill(caseRow.priority)} ${riskPill(caseRow.risk_level)}`;
    setStatus(caseRow.summary || 'Review the normalized evidence and decision history.');
    renderEvidence(caseRow);
    renderDecisions(caseRow);
    renderEvents(caseRow);
    renderWorkflow(caseRow);
    updateEvidenceSelection();
  }

  async function runWorkflow(patch, control) {
    if (state.busy || !state.case) return;
    state.busy = true;
    if (control) control.disabled = true;
    setStatus('Updating the case workflow.');
    try {
      const payload = await global.VeriTrustSupabase.updateCase(state.case.id, { action: 'workflow', ...patch });
      renderDetail(payload.case);
      setStatus('Case workflow updated.');
    } catch (error) {
      setStatus(error.message || 'Unable to update the case.', true);
    } finally {
      state.busy = false;
      if (control) control.disabled = false;
    }
  }

  function bindDecisionForm() {
    const form = document.querySelector('[data-case-decision-form]');
    if (!form) return;
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (state.busy || !state.case) return;
      const submit = form.querySelector('button[type="submit"]');
      const data = new FormData(form);
      const evidenceIds = [...document.querySelectorAll('[data-case-evidence-check]:checked')].map((input) => input.value);
      state.busy = true;
      submit.disabled = true;
      submit.textContent = 'Recording decision…';
      setStatus('Recording the analyst decision.');
      try {
        const payload = await global.VeriTrustSupabase.updateCase(state.case.id, {
          action: 'decision',
          outcome: data.get('outcome'),
          risk_level: data.get('risk_level'),
          rationale: data.get('rationale'),
          evidence_ids: evidenceIds,
        });
        form.reset();
        renderDetail(payload.case);
        setStatus('Analyst decision recorded. The previous decisions remain in the audit history.');
      } catch (error) {
        setStatus(error.message || 'Unable to record the analyst decision.', true);
      } finally {
        state.busy = false;
        submit.disabled = false;
        submit.textContent = 'Record analyst decision';
      }
    });
  }

  async function loadCaseDetail() {
    const caseId = new URLSearchParams(global.location.search).get('id');
    if (!caseId) throw new Error('A case ID is required. Return to the case queue and select a case.');
    const payload = await global.VeriTrustSupabase.getCase(caseId);
    state.role = String(payload.role || 'viewer').toLowerCase();
    state.user = payload.user || null;
    renderDetail(payload.case);
  }

  async function init() {
    if (!global.VeriTrustSupabase?.isConfigured()) throw new Error('Account service is unavailable.');
    const session = await global.VeriTrustSupabase.getSession();
    if (!session) {
      setStatus('Sign in to open the investigation workspace.', true);
      const target = document.querySelector('[data-case-list], [data-case-evidence]');
      if (target) target.innerHTML = '<div class="empty-state-table"><strong>Sign in required</strong><p><a class="btn btn-primary" href="auth.html">Sign in</a></p></div>';
      return;
    }
    if (document.querySelector('[data-cases-list]')) {
      const form = document.querySelector('[data-case-filters]');
      form?.addEventListener('submit', async (event) => {
        event.preventDefault();
        const data = new FormData(form);
        try {
          await loadCaseList({ status: data.get('status'), priority: data.get('priority'), assigned: data.get('assigned') });
        } catch (error) {
          setStatus(error.message || 'Unable to load cases.', true);
        }
      });
      await loadCaseList();
    }
    if (document.querySelector('[data-case-detail]')) {
      bindDecisionForm();
      await loadCaseDetail();
    }
  }

  global.VeriTrustCases = { escapeHtml, titleCase, truncate };
  document.addEventListener('DOMContentLoaded', () => {
    init().catch((error) => setStatus(error.message || 'Unable to load the case workspace.', true)).finally(() => {
      document.body.classList.remove('dashboard-is-loading');
      document.querySelector('.dashboard-shell')?.removeAttribute('aria-busy');
    });
  });
})(window);
