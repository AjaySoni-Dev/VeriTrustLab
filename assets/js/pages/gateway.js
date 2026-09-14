(function initGateway(global) {
  const api = global.VeriTrustSupabase;
  const results = global.VeriTrustAnalysisResult;
  const form = document.getElementById('gateway-form');
  if (!form || !api) return;
  const elements = Object.fromEntries(['auth','error','text','urls','file','file-label','context','submit','cancel','status','status-copy','empty','output','recommendation','risk','verdict','reasons','evidence','audit','refresh','result-loading','history-list','history-pagination','history-count','history-more'].map((name) => [name, document.getElementById(`gateway-${name}`)]));
  const resultPanel = document.querySelector('.gateway-result');
  let activeScanId = null;
  let polling = null;
  let viewGeneration = 0;
  let submitting = false;
  let historyRows = [];
  let visibleHistoryCount = 5;
  let historySelectionPending = false;
  const HISTORY_PAGE_SIZE = 5;
  const requestedScanId = new URLSearchParams(global.location.search).get('scan_id');
  const mediaModuleEnabled = global.VeriTrustModules?.isEnabled?.('deepfake') === true;
  const mediaUpload = typeof elements.file?.closest === 'function' ? elements.file.closest('.gateway-upload') : null;
  if (mediaUpload) mediaUpload.hidden = !mediaModuleEnabled;

  function setError(message) {
    elements.error.textContent = message || '';
    elements.error.hidden = !message;
    if (message) { elements.error.tabIndex = -1; elements.error.focus(); }
  }
  function setBusy(busy, message) {
    form.querySelectorAll('input,textarea,select,button').forEach((item) => {
      if (item !== elements.cancel) item.disabled = busy;
    });
    elements.submit.textContent = busy ? 'Processing…' : 'Analyze through gateway';
    elements.submit.classList.toggle('is-loading', busy);
    elements.submit.classList.remove('vt-loading-shimmer');
    if (busy) elements.submit.setAttribute('aria-busy', 'true');
    else elements.submit.removeAttribute('aria-busy');
    resultPanel?.classList.toggle('is-loading', busy);
    resultPanel?.classList.remove('vt-loading-shimmer');
    if (message) elements['status-copy'].textContent = message;
  }
  async function request(url, options = {}) {
    return results.withDeadline((signal) => api.callAppApi(url, { ...options, signal }));
  }

  function resetPolling() {
    clearTimeout(polling);
    viewGeneration += 1;
    return viewGeneration;
  }

  async function uploadMedia(file) {
    const registered = await request('/api/v1/gateway/uploads', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ kind: file.type.startsWith('image/') ? 'image' : file.type.startsWith('audio/') ? 'audio' : 'video', mime_type: file.type, size_bytes: file.size }) });
    const config = global.VeriTrust_CONFIG || {};
    if (!registered.signed_upload || !registered.signed_upload.url) throw new Error('A signed private upload URL was not returned.');
    const signedUrl = /^https?:/i.test(registered.signed_upload.url || '') ? registered.signed_upload.url : `${String(config.supabase?.url || '').replace(/\/$/,'')}/storage/v1${registered.signed_upload.url}`;
    const uploadResponse = await results.withDeadline((signal) => fetch(signedUrl, { method: 'PUT', headers: { 'Content-Type': file.type, 'x-upsert': 'false' }, body: file, signal }), 180000);
    if (!uploadResponse.ok) throw new Error('The private media upload failed.');
    await request(`/api/v1/gateway/uploads/${registered.upload_id}/complete`, { method: 'POST' });
    return { upload_id: registered.upload_id, kind: file.type.startsWith('image/') ? 'image' : file.type.startsWith('audio/') ? 'audio' : 'video' };
  }

  function render(data) {
    activeScanId = data.scan_id || activeScanId;
    const decision = data.decision || {};
    resultPanel?.classList.remove('vt-loading-shimmer');
    resultPanel?.querySelectorAll('.vt-loading-shimmer').forEach((node) => {
      node.classList.remove('vt-loading-shimmer');
    });
    elements.empty.hidden = true; elements.output.hidden = false;
    elements.status.textContent = (data.status || 'unknown').replaceAll('_', ' ');
    elements['status-copy'].textContent = results.statusCopy(data.status);
    elements.recommendation.textContent = (decision.recommendation || 'Pending').replaceAll('_', ' ');
    elements.risk.textContent = results.percent(decision.risk);
    elements.verdict.textContent = decision.verdict || 'Unknown';
    elements.reasons.replaceChildren(...(decision.reason_codes || []).map((code) => { const span=document.createElement('span'); span.textContent=code.replaceAll('_',' '); return span; }));
    renderEvidence(data);
    elements.audit.replaceChildren(...[['Scan',data.display_id||data.scan_id],['Request',data.submission_request_id||data.request_id],['Policy',data.policy_version_id],['Correlation',data.correlation_version]].map(([label,value])=>{const line=document.createElement('div');line.textContent=`${label}: ${value||'—'}`;return line;}));
    elements.cancel.hidden = !['accepted','queued','processing','partially_completed','cancel_requested'].includes(data.status);
  }

  function renderEvidence(data) {
    const artifacts = new Map((data.artifacts || []).map((item) => [item.id, item]));
    elements.evidence.replaceChildren(...(data.evidence || []).map((item) => {
      const article = document.createElement('article');
      const heading = document.createElement('div');
      heading.className = 'gateway-evidence-head';
      const title = document.createElement('strong');
      title.textContent = String(item.model || 'Analysis').replaceAll('_', ' ');
      const status = document.createElement('span');
      status.textContent = String(item.status || 'unknown').replaceAll('_', ' ');
      status.dataset.status = item.status || 'unknown';
      heading.append(title, status);
      const summary = document.createElement('p');
      summary.textContent = item.status === 'completed'
        ? `Risk score: ${results.percent(item.score)}. Verdict: ${item.verdict || 'unknown'}.`
        : 'This check did not produce a final score.';
      article.append(heading, summary);
      const reasons = document.createElement('ul');
      for (const reason of item.reason_codes || []) {
        const line = document.createElement('li');
        line.textContent = String(reason).replaceAll('_', ' ').toLowerCase();
        reasons.append(line);
      }
      if (reasons.childElementCount) article.append(reasons);
      const details = document.createElement('details');
      const label = document.createElement('summary');
      label.textContent = 'Evidence provenance';
      const provenance = document.createElement('p');
      const artifact = artifacts.get(item.artifact_id);
      provenance.textContent = `Artifact: ${artifact?.type || 'unknown'} · ${item.artifact_id || 'unavailable'}. Model version: ${item.model_version || 'unavailable'}. Confidence: ${results.percent(item.confidence_value)}.`;
      details.append(label, provenance);
      article.append(details);
      return article;
    }));
    if (!elements.evidence.childElementCount) elements.evidence.textContent = 'No specialist evidence is available yet.';
  }

  async function poll(scanId, generation = viewGeneration) {
    clearTimeout(polling);
    try {
      const data = await request(`/api/v1/gateway/scans/${scanId}`, { cache: 'no-store' });
      if (generation !== viewGeneration) return;
      render(data);
      if (!results.terminal(data.status)) polling = setTimeout(() => poll(scanId, generation), 2500);
      else { setBusy(false); refreshHistory(); }
    } catch (error) {
      if (generation !== viewGeneration) return;
      setError(error.message);
      elements['status-copy'].textContent = 'Status updates paused. Reopen the scan from history to resume. The server may still be processing it.';
      setBusy(false);
    }
  }

  async function openHistoryScan(scan, item) {
    if (historySelectionPending || submitting) return;
    historySelectionPending = true;
    setError('');
    const generation = resetPolling();
    elements['history-list'].querySelectorAll('.gateway-history-item').forEach((historyItem) => {
      historyItem.classList.toggle('is-selected', historyItem === item);
      historyItem.removeAttribute('aria-current');
    });
    item.disabled = true;
    item.setAttribute('aria-current', 'true');
    elements['result-loading'].hidden = false;
    resultPanel?.classList.add('is-history-loading');
    resultPanel?.classList.remove('vt-loading-shimmer');
    resultPanel?.setAttribute('aria-busy', 'true');
    elements['status-copy'].textContent = `Loading ${scan.display_id || 'selected scan'}…`;

    try {
      const data = await request(`/api/v1/gateway/scans/${scan.id}`, { cache: 'no-store' });
      if (generation !== viewGeneration) return;
      render(data);
      setBusy(!results.terminal(data.status));
      if (!results.terminal(data.status)) polling = setTimeout(() => poll(scan.id, generation), 2500);
    } catch (error) {
      setError(error.message);
      elements['status-copy'].textContent = 'The selected scan could not be loaded.';
      setBusy(false);
    } finally {
      historySelectionPending = false;
      item.disabled = false;
      elements['result-loading'].hidden = true;
      resultPanel?.classList.remove('is-history-loading', 'vt-loading-shimmer');
      resultPanel?.removeAttribute('aria-busy');
    }
  }

  function renderHistory() {
    const visibleRows = historyRows.slice(0, visibleHistoryCount);
    elements['history-list'].replaceChildren(...visibleRows.map((scan) => {
      const item = document.createElement('button');
      item.type = 'button';
      item.className = 'gateway-history-item';
      item.setAttribute('aria-label', `Open scan ${scan.display_id || scan.id}, ${scan.status || 'unknown status'}`);

      const id = document.createElement('strong');
      id.textContent = scan.display_id || scan.id;
      const state = document.createElement('em');
      state.textContent = scan.status || 'unknown';
      const time = document.createElement('span');
      time.textContent = new Date(scan.created_at).toLocaleString();

      item.append(id, state, time);
      item.addEventListener('click', () => openHistoryScan(scan, item));
      return item;
    }));

    if (!historyRows.length) {
      elements['history-list'].textContent = 'No gateway scans yet.';
      elements['history-pagination'].hidden = true;
      return;
    }

    elements['history-count'].textContent = `Showing ${visibleRows.length} of ${historyRows.length} scans`;
    elements['history-more'].hidden = visibleRows.length >= historyRows.length;
    elements['history-pagination'].hidden = false;
  }

  async function refreshHistory() {
    elements.refresh.disabled = true;
    elements.refresh.classList.add('is-loading');
    elements.refresh.classList.remove('vt-loading-shimmer');
    elements.refresh.setAttribute('aria-busy', 'true');
    try {
      const data = await request('/api/v1/gateway/scans?limit=50', { cache: 'no-store' });
      historyRows = Array.isArray(data.scans) ? data.scans : [];
      visibleHistoryCount = HISTORY_PAGE_SIZE;
      renderHistory();
    } catch (error) {
      elements['history-list'].textContent = error.message;
      elements['history-pagination'].hidden = true;
    } finally {
      elements.refresh.disabled = false;
      elements.refresh.classList.remove('is-loading');
      elements.refresh.removeAttribute('aria-busy');
    }
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (submitting || historySelectionPending) return;
    submitting = true;
    resetPolling();
    setError(''); setBusy(true,'Validating and routing applicable models…');
    try {
      const session=await api.getSession(); if(!session)throw new Error('Sign in before submitting a gateway scan.');
      const files=mediaModuleEnabled && elements.file ? [...elements.file.files] : [];
      const urls=elements.urls.value.split(/\r?\n/).map((value)=>value.trim()).filter(Boolean);
      results.validateGatewayInput({ text: elements.text.value, urls, files });
      const media=[];
      for(const file of files)media.push(await uploadMedia(file));
      const context=elements.context.value;
      const data=await request('/api/v1/gateway/scans',{method:'POST',headers:{'Content-Type':'application/json','Idempotency-Key':crypto.randomUUID()},body:JSON.stringify({source:{kind:'web'},content:{text:elements.text.value,urls,media},processing_mode:media.length?'hybrid':'synchronous',metadata:{context_categories:context?[context]:[]}})});
      render(data); await refreshHistory(); if(!['completed','failed','cancelled'].includes(data.status))poll(data.scan_id);else setBusy(false);
    } catch(error){setError(error.message);setBusy(false);}
    finally { submitting = false; }
  });
  if (mediaModuleEnabled && elements.file) elements.file.addEventListener('change',()=>{const files=[...elements.file.files];elements['file-label'].textContent=files.length?`${files.length} file${files.length===1?'':'s'} selected`:'Choose supporting media files';});
  elements.cancel.addEventListener('click', async () => {
    if (!activeScanId || submitting || elements.cancel.disabled) return;
    const scanId = activeScanId;
    const generation = resetPolling();
    elements.cancel.disabled = true;
    try {
      await request(`/api/v1/gateway/scans/${scanId}/cancel`, { method: 'POST' });
      if (generation === viewGeneration) poll(scanId, generation);
    } catch (error) { if (generation === viewGeneration) { setError(error.message); poll(scanId, generation); } }
    finally { elements.cancel.disabled = false; }
  });
  elements.refresh.addEventListener('click',refreshHistory);
  elements['history-more'].addEventListener('click', () => {
    visibleHistoryCount = Math.min(historyRows.length, visibleHistoryCount + HISTORY_PAGE_SIZE);
    renderHistory();
  });
  api.getSession().then(async (session)=>{
    elements.auth.hidden=Boolean(session);
    form.querySelectorAll('input,textarea,select,button').forEach((item)=>item.disabled=!session);
    if (!session) return;
    await refreshHistory();
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(requestedScanId || '')) {
      setBusy(true, 'Loading requested scan...');
      poll(requestedScanId);
    }
  }).catch((error) => { setError(error.message || 'Unable to load your session. Reload and sign in again.'); });
})(window);
