(function analysisProgressModule(global) {
  'use strict';

  function checkedPayload(payload, status = 200) {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload) || payload.ok !== true || status >= 400) {
      const error = new Error(payload?.error?.message || 'The analysis request could not be completed.');
      error.code = payload?.error?.code || 'ANALYSIS_REQUEST_FAILED';
      error.status = status;
      throw error;
    }
    return payload;
  }

  async function readResponse(response, onEvent = () => {}) {
    if (!response.headers.get('content-type')?.includes('application/x-ndjson')) {
      let payload;
      try { payload = await response.json(); } catch { throw new Error('The server returned an unreadable response. No result is available.'); }
      return checkedPayload(payload, response.status);
    }
    if (!response.body) throw new Error('Live updates are unavailable in this browser.');
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    let bytes = 0;
    let final = null;
    let sequence = 0;
    function consume(line) {
      if (!line.trim()) return;
      let event;
      try { event = JSON.parse(line); } catch { throw new Error('A server update was unreadable. Check scan history before retrying.'); }
      if (!Number.isInteger(event.sequence) || event.sequence <= sequence) throw new Error('The server update sequence was invalid.');
      sequence = event.sequence;
      if (event.type === 'result') { final = event; return; }
      if (event.type !== 'progress' || !['running', 'completed', 'failed', 'skipped'].includes(event.state) || typeof event.stage !== 'string' || typeof event.message !== 'string') throw new Error('The server returned an unsupported progress update.');
      onEvent(event);
    }
    try {
      while (!final) {
        const { value, done } = await reader.read();
        if (done) { buffer += decoder.decode(); if (buffer.trim()) consume(buffer); break; }
        bytes += value.byteLength;
        if (bytes > 4 * 1024 * 1024) throw new Error('The server response exceeded the report size limit.');
        buffer += decoder.decode(value, { stream: true });
        let boundary;
        while (!final && (boundary = buffer.indexOf('\n')) !== -1) {
          consume(buffer.slice(0, boundary));
          buffer = buffer.slice(boundary + 1);
        }
      }
      if (!final) throw new Error('The connection ended before a final report arrived. Check scan history before retrying.');
      return checkedPayload(final.payload, final.status);
    } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
  }

  function create() {
    const panel = global.document?.getElementById('analysisProgress');
    const heading = global.document?.getElementById('analysisProgressTitle');
    const current = global.document?.getElementById('analysisProgressMessage');
    const currentStage = global.document?.getElementById('analysisProgressStage');
    const completedBadge = global.document?.getElementById('analysisProgressCompleted');
    const historySummary = global.document?.getElementById('analysisProgressHistorySummary');
    const list = global.document?.getElementById('analysisProgressEvents');
    const history = new Map();
    let active = false;
    let completedCount = 0;

    const stageLabel = (value) => String(value || 'Processing')
      .replace(/[_-]+/gu, ' ')
      .replace(/\b\w/gu, (letter) => letter.toUpperCase());

    function syncCompletedBadge() {
      if (completedBadge) {
        completedBadge.textContent = `+${completedCount} completed`;
        completedBadge.hidden = completedCount === 0;
      }
      if (historySummary) historySummary.textContent = completedCount
        ? `Activity history · ${completedCount} completed`
        : 'Activity history';
    }

    function renderHistory() {
      if (!list) return;
      const rows = [...history.values()].slice(-8);
      list.replaceChildren(...rows.map((event) => {
        const row = global.document.createElement('li');
        row.dataset.state = event.state;
        const label = global.document.createElement('span');
        const text = global.document.createElement('p');
        label.textContent = `${stageLabel(event.stage)} · ${{ running: 'In progress', completed: 'Done', failed: 'Unavailable', skipped: 'Not applicable', interrupted: 'No final update' }[event.state] || 'Updated'}`;
        text.textContent = event.message;
        row.append(label, text);
        return row;
      }));
    }

    function begin(message = 'Checking input and workspace access.') {
      active = true;
      completedCount = 0;
      history.clear();
      list?.replaceChildren();
      syncCompletedBadge();
      if (panel) { panel.hidden = false; panel.dataset.state = 'running'; }
      const idle = global.document?.getElementById('analysisIdle');
      if (idle) idle.hidden = true;
      const details = panel?.querySelector('details');
      if (details) details.open = false;
      if (heading) heading.textContent = 'Analysis in progress';
      if (currentStage) currentStage.textContent = 'Preparing';
      if (current) current.textContent = message;
      panel?.scrollIntoView?.({ block: 'nearest', behavior: 'auto' });
    }

    function update(event) {
      if (!active) return;
      const previous = history.get(event.stage);
      if (event.state === 'completed' && previous?.state !== 'completed') completedCount += 1;
      history.set(event.stage, { ...event });
      syncCompletedBadge();
      renderHistory();

      // Keep the live surface compact: only the current step is shown. Completed
      // work collapses into the +N badge and remains available in Activity history.
      if (event.state === 'running') {
        if (currentStage) currentStage.textContent = stageLabel(event.stage);
        if (current) current.textContent = event.message;
      } else if (event.state === 'failed') {
        if (currentStage) currentStage.textContent = `${stageLabel(event.stage)} unavailable`;
        if (current) current.textContent = event.message;
      } else if (event.state === 'skipped' && ![...history.values()].some((item) => item.state === 'running')) {
        if (currentStage) currentStage.textContent = 'Continuing';
        if (current) current.textContent = event.message;
      }
    }

    function finish(error = null, { pending = false, title, message } = {}) {
      active = false;
      if (panel) panel.dataset.state = error ? 'failed' : 'completed';
      if (heading) heading.textContent = error ? 'Analysis interrupted' : pending ? 'Scan still processing' : 'Report received';
      if (currentStage) currentStage.textContent = error ? 'Action required' : pending ? 'Processing' : 'Complete';
      if (current) current.textContent = error ? `${error.message}${error.code ? ` Reference: ${error.code}.` : ''}` : pending ? 'The server confirmed that this scan is already running. Open its saved status to follow it.' : 'The investigation is complete. Review the concise result or open the complete PDF report.';
      if (!error && title && heading) heading.textContent = title;
      if (!error && message && current) current.textContent = message;

      for (const [stage, event] of history) {
        if (event.state === 'running') history.set(stage, { ...event, state: 'interrupted' });
      }
      renderHistory();
      syncCompletedBadge();
      const details = panel?.querySelector('details');
      if (details) details.open = Boolean(error);
    }

    async function request(url, options = {}) {
      if (currentStage) currentStage.textContent = 'Submitting';
      if (current) current.textContent = 'Sending the request. Waiting for the server to confirm processing.';
      return global.VeriTrustAnalysisResult.withDeadline(async (signal) => {
        let response;
        try {
          response = await global.fetch(url, { ...options, signal, credentials: 'same-origin', headers: { ...options.headers, Accept: 'application/x-ndjson' } });
        } catch (error) {
          if (signal.aborted) throw error;
          throw new Error('The connection failed. Check scan history before submitting again.');
        }
        if (!response.headers.get('content-type')?.includes('application/x-ndjson') && current) {
          if (currentStage) currentStage.textContent = 'Reading response';
          current.textContent = 'Reading the server response. This deployment did not provide live processing updates.';
        }
        return readResponse(response, update);
      });
    }
    return { begin, update, finish, request };
  }

  const api = { create, readResponse };
  if (typeof module === 'object' && module.exports) module.exports = api;
  else global.VeriTrustAnalysisProgress = api;
}(typeof window === 'object' ? window : globalThis));
