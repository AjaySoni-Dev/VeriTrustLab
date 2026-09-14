(function emailInvestigationPage(global) {
  'use strict';

  const MAX_EML_BYTES = 10 * 1024 * 1024;
  const CONFIGURATION_FAILURE_CODES = new Set(['GATEWAY_POLICY_INVALID', 'GATEWAY_POLICY_UNAVAILABLE', 'SERVER_CONFIG_ERROR']);
  const STATE_LABELS = Object.freeze({
    LIKELY_PHISHING: 'Likely phishing',
    LIKELY_BENIGN: 'No strong phishing signs found',
    UNCERTAIN: 'Needs a closer look',
    UNSUPPORTED: 'Could not fully check this email',
    FAILED: 'Check could not be completed',
  });
  const HELP = Object.freeze({
    authentication: 'Sender verification checks whether the email was authorized by the domain it claims to come from. Original email data is required for most of these checks.',
    spf: 'SPF checks whether the sending mail server was allowed to send for the claimed domain. A saved .eml file alone cannot reliably recreate this historical check.',
    dkim: 'DKIM checks the email\'s cryptographic signature to see whether signed parts of the message changed after the sender sent it.',
    dmarc: 'DMARC checks whether the visible sender domain aligns with successful SPF or DKIM results and follows the domain owner\'s policy.',
    arc: 'ARC records how earlier trusted mail systems evaluated the message while it was forwarded. It adds context but does not prove that content is safe.',
    authResults: 'Authentication-Results is a header written by a mail server. VeriTrust treats a copied value as untrusted unless it comes directly from a configured receiver.',
    identity: 'Sender consistency compares the visible From address with reply, return-path, signing, and linked domains to reveal unexpected mismatches.',
    infrastructure: 'The delivery route is built from eligible public mail-server hops. It describes network infrastructure, not the sender\'s physical location.',
    model: 'The AI content check estimates phishing likelihood from the available subject and message wording. It is one piece of evidence, not a safety guarantee.',
    risk: 'The risk score is the Gateway\'s combined estimate from available evidence. Missing checks can reduce certainty, so always read the limitations.',
    coverage: 'Coverage shows which checks had enough information to run. "Limited" or "not available" is an evidence gap, not a safe result.',
    technicalCode: 'A technical code is the exact machine-readable name of a finding. It is kept in the report so another analyst or system can reproduce the decision.',
  });
  const PROTOCOL_HELP = Object.freeze({ SPF: HELP.spf, DKIM: HELP.dkim, DMARC: HELP.dmarc, ARC: HELP.arc, AUTHENTICATION_RESULTS: HELP.authResults });
  const DECISION_LABELS = Object.freeze({
    allow: 'No immediate action', warn: 'Show a warning', manual_review: 'Review manually', quarantine: 'Move to quarantine', block: 'Block the message', hold: 'Hold for review',
  });
  const OBSERVATION_LABELS = Object.freeze({
    CREDENTIAL_REQUEST: 'Asks for passwords or security codes',
    PAYMENT_REQUEST: 'Asks for money or payment',
    URGENCY_OR_COERCION: 'Uses urgency or pressure',
    OUT_OF_BAND_CONTACT: 'Asks to move to another contact method',
    ATTACHMENT_LURE: 'Pushes the reader to open an attachment',
    QR_OR_LINK_LURE: 'Pushes the reader to follow a link or QR code',
    IMPERSONATION_CLAIM: 'Claims to represent a trusted person or team',
    VISIBLE_URL_DIFFERS_FROM_HREF: 'Visible link and actual destination do not match',
    OBFUSCATED_LINK_TEXT: 'Link text appears intentionally disguised',
    HTML_HIDDEN_CONTENT: 'Email contains hidden content',
    HTML_META_REFRESH: 'Email attempts an automatic redirect',
    AI_INPUT_INSTRUCTION_OVERRIDE: 'Message contains instructions aimed at an AI system',
    AI_INPUT_OBFUSCATION: 'Message contains hidden or unusual control characters',
    UNICODE_DIRECTIONAL_CONTROL: 'Text direction controls may disguise what is shown',
    IDENTITY_ADDRESS_MALFORMED: 'A sender address is malformed',
    IDENTITY_DOMAIN_MIXED_SCRIPTS: 'A sender domain mixes writing systems',
    IDENTITY_DOMAIN_CONFUSABLE: 'A sender domain may imitate another domain',
    URL_EXTRACTION_LIMIT_REACHED: 'Too many links to check completely',
    DOMAIN_REGISTERED_WITHIN_30_DAYS: 'A related domain was registered within the last 30 days',
    DOMAIN_REGISTERED_WITHIN_90_DAYS: 'A related domain was registered within the last 90 days',
    INFRASTRUCTURE_IP_HIGH_ABUSE_REPUTATION: 'A delivery IP has high recent abuse reputation',
    INFRASTRUCTURE_IP_ELEVATED_ABUSE_REPUTATION: 'A delivery IP has elevated recent abuse reputation',
  });
  const LIMITATION_LABELS = Object.freeze({
    SPF_UNAVAILABLE_WITHOUT_TRUSTED_RECEIVER_FACTS: 'SPF could not be recreated from the saved email alone.',
    AUTHENTICATION_TIMEOUT: 'A sender-verification check took too long to finish.',
    AUTHENTICATION_EVALUATION_FAILED: 'A sender-verification check could not be completed.',
    AUTHOR_IDENTITY_UNAVAILABLE: 'The original sender address was not available.',
    AMBIGUOUS_MULTIPLE_FROM: 'The email lists more than one From address.',
    AUTHOR_DOMAIN_MALFORMED_OR_UNAVAILABLE: 'The sender domain was missing or malformed.',
    AMBIGUOUS_MULTIPLE_REPLY_TO: 'The email lists more than one reply address.',
    AMBIGUOUS_MULTIPLE_RETURN_PATH: 'The email lists more than one return address.',
    AMBIGUOUS_MULTIPLE_SENDER: 'The email lists more than one sender address.',
    IP_REPUTATION_NOT_CONFIGURED: 'IP reputation is not configured in this deployment.',
    RDAP_LOOKUP_DISABLED: 'Domain-registration intelligence is disabled in this deployment.',
    CAMPAIGN_MEMORY_SCHEMA_NOT_APPLIED: 'Campaign Memory needs the forensic-intelligence database migration.',
    EVIDENCE_PASSPORT_SCHEMA_NOT_APPLIED: 'Evidence Passport persistence needs the forensic-intelligence database migration.',
  });
  const state = { mode: 'text', file: null, busy: false, lastScanId: null, parentScanId: null };
  const analysisProgress = global.VeriTrustAnalysisProgress.create();
  const one = (selector, root = document) => root.querySelector(selector);
  const all = (selector, root = document) => [...root.querySelectorAll(selector)];
  const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[character]));
  const titleCase = (value) => String(value || '').toLowerCase().replace(/_/g, ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());

  function helpLabel(label, help) {
    return `<span class="email-help-term" data-email-term="${escapeHtml(label)}" data-email-help="${escapeHtml(help)}">${escapeHtml(label)}</span>`;
  }

  function friendlyCode(value) {
    return OBSERVATION_LABELS[value] || 'A suspicious pattern was found';
  }

  function friendlyLimitation(value) {
    return LIMITATION_LABELS[value] || 'One technical check had insufficient evidence to finish.';
  }

  function friendlyStatus(value) {
    const labels = { PASS: 'Passed', FAIL: 'Failed', SOFTFAIL: 'Soft fail', NEUTRAL: 'Neutral', NONE: 'No result', TEMPERROR: 'Temporary error', PERMERROR: 'Permanent error', UNKNOWN: 'Unknown', UNAVAILABLE: 'Not available', completed: 'Completed', failed: 'Failed', pending: 'Pending', accepted: 'Accepted', processing: 'Processing' };
    return labels[value] || titleCase(value || 'Unknown');
  }

  function endpoint(name, fallback) {
    const runtime = global.VeriTrust_CONFIG || global['VERI' + 'TRUST_CONFIG'] || {};
    return runtime.api?.[name] || fallback;
  }


  function queryParameter(name) {
    const target = String(name || '');
    const search = String(global.location?.search || '').replace(/^\?/, '');
    for (const pair of search.split('&')) {
      if (!pair) continue;
      const [rawKey, ...rawValue] = pair.split('=');
      let key = rawKey;
      let value = rawValue.join('=');
      try { key = decodeURIComponent(rawKey.replace(/\+/g, ' ')); value = decodeURIComponent(value.replace(/\+/g, ' ')); } catch { /* ignore malformed query pairs */ }
      if (key === target) return value;
    }
    return null;
  }

  function setStatus(message) {
    const target = one('#activityLog');
    if (target) target.textContent = message;
  }

  function setError(message) {
    const target = one('#emailInputError');
    if (!target) return;
    target.textContent = message || '';
    target.hidden = !message;
    if (message) target.focus();
  }

  function failureGuidance(error) {
    if (CONFIGURATION_FAILURE_CODES.has(error?.code)) {
      return {
        summary: 'The investigation service needs an administrator configuration correction. Your message is not the cause.',
        detail: 'Your message was accepted, but the investigation service needs an administrator configuration correction. Retry after the deployment is updated.',
      };
    }
    return {
      summary: error?.message || 'The investigation could not be completed.',
      detail: 'Check the input and retry. If the failure continues, give support the error code below.',
    };
  }

  function setBusy(busy) {
    state.busy = busy;
    all('[data-email-mode], #emailSubject, #phishingText, #emailEmlFile').forEach((input) => { input.disabled = busy; });
    const button = one('#phishingSubmit');
    if (!button) return;
    button.disabled = busy;
    button.textContent = busy ? 'Checking email...' : state.mode === 'eml' ? 'Check original email' : 'Check email text';
    button.toggleAttribute('aria-busy', busy);
  }

  function setMode(mode, focusPanel = false) {
    if (state.busy) return;
    state.mode = mode;
    const tabs = all('[data-email-mode]');
    tabs.forEach((tab) => {
      const selected = tab.dataset.emailMode === mode;
      tab.classList.toggle('is-active', selected);
      tab.setAttribute('aria-selected', String(selected));
      tab.tabIndex = selected ? 0 : -1;
    });
    all('[data-email-panel]').forEach((panel) => { panel.hidden = panel.dataset.emailPanel !== mode; });
    const rawEvidence = mode === 'eml';
    const auth = one('[data-preview-auth]');
    const identity = one('[data-preview-identity]');
    const infra = one('[data-preview-infra]');
    const attachments = one('[data-preview-attachments]');
    if (auth) auth.textContent = rawEvidence ? 'Available (SPF limited)' : 'Needs original email';
    if (identity) identity.textContent = rawEvidence ? 'Available' : 'Limited with pasted text';
    if (infra) infra.textContent = rawEvidence ? 'Available when recorded' : 'Needs original email';
    if (attachments) attachments.textContent = rawEvidence ? 'Available' : 'Needs original email';
    setError('');
    setBusy(false);
    if (focusPanel) {
      const focusTarget = mode === 'text' ? one('#emailSubject') : one('.email-dropzone');
      focusTarget?.focus();
    }
  }

  function validateFile(file) {
    if (!file) throw new Error('Choose a raw .eml file to investigate.');
    if (!file.size) throw new Error('The selected file is empty.');
    if (file.size > MAX_EML_BYTES) throw new Error('The selected email exceeds the 10 MiB limit.');
    const extensionOk = /\.eml$/iu.test(file.name || '');
    const typeOk = !file.type || ['message/rfc822', 'application/octet-stream', 'text/plain'].includes(file.type);
    if (!extensionOk || !typeOk) throw new Error('Choose an original .eml file with a supported email content type.');
    return file;
  }

  function chooseFile(file) {
    if (state.busy) return;
    state.file = validateFile(file);
    const label = one('#emailFileLabel');
    if (label) label.textContent = `${state.file.name} · ${state.file.size < 1024 ? `${state.file.size} bytes` : `${(state.file.size / 1024).toLocaleString(undefined, { maximumFractionDigits: 1 })} KiB`}`;
  }

  async function parseResponse(response) {
    let payload;
    try { payload = await response.json(); } catch { payload = null; }
    if (!response.ok || !payload?.ok) {
      const error = payload?.error || {};
      const message = error.message || payload?.message || `The investigation could not be completed (status ${response.status}).`;
      const failure = new Error(message);
      failure.code = error.code || 'EMAIL_REQUEST_FAILED';
      failure.meta = error.meta || null;
      throw failure;
    }
    return payload;
  }

  async function requestInvestigation(signal) {
    if (!global.VeriTrustSupabase?.isConfigured()) throw new Error('Account access is temporarily unavailable.');
    const context = await global.VeriTrustSupabase.getSessionContext();
    if (!context?.organization?.id) throw new Error('Sign in and select a workspace before starting an investigation.');
    const idempotencyKey = global.crypto?.randomUUID?.() || `email-web-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    if (state.mode === 'eml') {
      const file = validateFile(state.file || one('#emailEmlFile')?.files?.[0]);
      return analysisProgress.request(endpoint('emailAnalyzeEml', '/api/v1/gateway/email/analyze-eml'), {
        signal,
        method: 'POST',
        headers: { 'Content-Type': 'message/rfc822', 'Idempotency-Key': idempotencyKey, 'X-Retention-Policy': 'ephemeral_24h', ...(state.parentScanId ? { 'X-VeriTrust-Parent-Scan-Id': state.parentScanId } : {}) },
        body: file,
      });
    }
    const subject = one('#emailSubject')?.value.trim() || '';
    const body = one('#phishingText')?.value.trim() || '';
    if (!subject && !body) throw new Error('Provide an email subject or message body.');
    if (body.length > 12000) throw new Error('Keep the message body at or below 12,000 characters.');
    return analysisProgress.request(endpoint('emailAnalyzeText', '/api/v1/gateway/email/analyze-text'), {
      signal,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Idempotency-Key': idempotencyKey },
      body: JSON.stringify({ subject, body, channel: 'email', retention_policy: 'metadata_only', org_id: context.organization.id, ...(state.parentScanId ? { parent_scan_id: state.parentScanId } : {}) }),
    });
  }


  async function loadSavedInvestigation(scanId) {
    const id = String(scanId || '').trim();
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(id)) return;
    setStatus('Loading the saved forensic investigation...');
    try {
      const response = await global.fetch(`/api/v2/phishing/evidence/${encodeURIComponent(id)}`, {
        method: 'GET', credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json' },
      });
      const payload = await parseResponse(response);
      if (!payload.evidence || !payload.gateway_decision) throw new Error('The saved scan does not contain a complete email decision.');
      renderResult(payload);
      setStatus('Saved forensic investigation loaded.');
    } catch (error) {
      renderFailure(error);
      setStatus('The saved forensic investigation could not be loaded.');
    }
  }

  function decisionRiskValue(decision, evidence) {
    const direct = [decision?.risk, decision?.risk_score];
    const history = Array.isArray(evidence?.gateway_decisions) ? [...evidence.gateway_decisions] : [];
    history.sort((a, b) => Number(b?.sequence || 0) - Number(a?.sequence || 0));
    history.forEach((item) => direct.push(item?.risk_score, item?.risk));
    for (const candidate of direct) {
      const value = Number(candidate);
      if (Number.isFinite(value) && value >= 0 && value <= 1) return value;
    }
    return null;
  }

  function evidenceStageName(mode) {
    return ({ plain_text: 'Pasted text', raw_eml: 'Original .eml', trusted_receiver_event: 'Trusted receiver' })[mode] || 'Pasted text';
  }

  function essentialSignals({ deterministic, authentication, relationships, children, threatIntelligence }) {
    const signals = [];
    deterministic.slice(0, 3).forEach((item) => signals.push({ label: friendlyCode(item.code), tone: 'attention' }));
    authentication.filter((item) => ['FAIL', 'SOFTFAIL', 'PERMERROR', 'TEMPERROR'].includes(String(item.result || '').toUpperCase())).slice(0, 2)
      .forEach((item) => signals.push({ label: `${String(item.protocol || 'Sender check').replaceAll('_', ' ')}: ${friendlyStatus(item.result)}`, tone: 'danger' }));
    relationships.slice(0, 2).forEach((item) => {
      if (item.reason_code) signals.push({ label: OBSERVATION_LABELS[item.reason_code] || titleCase(item.reason_code), tone: 'attention' });
    });
    const riskyChildren = children.filter((item) => item.state && !['completed', 'METADATA_ONLY'].includes(item.state)).slice(0, 2);
    riskyChildren.forEach((item) => signals.push({ label: item.type === 'url' ? `Link check: ${friendlyStatus(item.state)}` : `Attachment: ${friendlyStatus(item.state)}`, tone: 'attention' }));
    const intelligenceObservations = Array.isArray(threatIntelligence?.observations) ? threatIntelligence.observations : [];
    intelligenceObservations.slice(0, 2).forEach((item) => signals.push({ label: OBSERVATION_LABELS[item.code] || titleCase(item.code || 'Threat intelligence signal'), tone: 'attention' }));
    return signals.filter((item, index, array) => array.findIndex((candidate) => candidate.label === item.label) === index).slice(0, 5);
  }

  function renderCompactUspSummary({ evidence, infrastructure, infrastructureSummary, campaignMemory, passport, scanId }) {
    const completeness = evidence.evidence_completeness || {};
    const currentStage = evidenceStageName(evidence.input_mode);
    const next = Array.isArray(completeness.next_actions) ? completeness.next_actions[0] : null;
    const trusted = infrastructure.filter((hop) => hop.trust_level === 'trusted_receiver');
    const observed = infrastructure.filter((hop) => hop.trust_level !== 'trusted_receiver');
    const earliest = infrastructureSummary.earliest_reliable_public_node;
    const relatedCount = Number(campaignMemory.related_scan_count || campaignMemory.related_scans?.length || 0);
    const campaignState = campaignMemory.state === 'CORRELATED' ? `${relatedCount} prior investigation${relatedCount === 1 ? '' : 's'} linked` : campaignMemory.state === 'UNAVAILABLE' ? 'Correlation unavailable' : 'No strong prior campaign match';
    const geoState = trusted.length
      ? `${trusted.length} directly trusted SMTP observation${trusted.length === 1 ? '' : 's'}`
      : observed.length
        ? `${observed.length} observed relay claim${observed.length === 1 ? '' : 's'} · origin unverified`
        : 'No public relay location available';
    const passportState = passport?.passport_id ? `${passport.signature_algorithm || 'Ed25519'} signed · integrity package ready` : 'Signed package unavailable';
    const nextAction = next?.action === 'UPLOAD_ORIGINAL_EML'
      ? `<button class="email-usp-link" type="button" data-upgrade-evidence="eml" data-parent-scan="${escapeHtml(scanId || '')}">Add original .eml →</button>`
      : next?.action === 'USE_TRUSTED_RECEIVER'
        ? '<a class="email-usp-link" href="/gateway-powershell">Acquire trusted SMTP evidence →</a>'
        : '<span class="email-usp-complete">Highest available stage reached</span>';

    return `<section class="email-usp-summary" aria-label="Core VeriTrust forensic capabilities">
      <article class="email-usp-card" aria-label="Evidence acquisition ladder status">
        <div class="email-usp-icon" aria-hidden="true">01</div>
        <div><span>Progressive Evidence Escalation™</span><strong>${escapeHtml(currentStage)}</strong><small>${escapeHtml(titleCase(completeness.level || 'limited'))} evidence completeness</small>${nextAction}</div>
      </article>
      <article class="email-usp-card">
        <div class="email-usp-icon" aria-hidden="true">02</div>
        <div><span>Trust-Boundary GeoTrace™</span><strong>${escapeHtml(geoState)}</strong><small>${earliest ? `Earliest defensible node: ${escapeHtml(earliest.host || earliest.ip_address || 'recorded')}` : escapeHtml(infrastructureSummary.wording || 'Infrastructure context only; no physical-person attribution.')}</small></div>
      </article>
      <article class="email-usp-card">
        <div class="email-usp-icon" aria-hidden="true">03</div>
        <div><span>MailGraph Campaign Memory™</span><strong>${escapeHtml(campaignState)}</strong><small>${campaignMemory.campaign_id ? `Campaign ${escapeHtml(campaignMemory.campaign_id)}` : 'Requires sufficiently strong repeated forensic entities.'}</small></div>
      </article>
      <article class="email-usp-card">
        <div class="email-usp-icon" aria-hidden="true">04</div>
        <div><span>Evidence Passport™</span><strong>${escapeHtml(passportState)}</strong><small>${passport?.evidence_sha256 ? `SHA-256 ${escapeHtml(String(passport.evidence_sha256).slice(0, 16))}…` : 'Evidence integrity metadata not available.'}</small>${passport?.passport_id ? `<a class="email-usp-link" href="/verify-evidence?scan_id=${encodeURIComponent(scanId || '')}">Verify evidence →</a>` : ''}</div>
      </article>
    </section>`;
  }

  function resetInvestigationView() {
    const shell = one('#emailInvestigationResult');
    const target = one('#phishingResult');
    if (shell) shell.hidden = true;
    if (target) target.replaceChildren();
    document.body.classList.remove('vt-email-has-result');
    state.lastScanId = null;
    state.parentScanId = null;
    const form = one('#phishingForm');
    form?.reset();
    state.file = null;
    const fileLabel = one('#emailFileLabel');
    if (fileLabel) fileLabel.textContent = '.eml file, maximum 10 MB';
    const count = one('#emailCharacterCount');
    if (count) count.textContent = '0 / 12,000';
    const progress = one('#analysisProgress');
    const idle = one('#analysisIdle');
    if (progress) progress.hidden = true;
    if (idle) idle.hidden = false;
    setStatus('');
    setError('');
    setMode('text');
    try { global.history?.replaceState?.({}, '', '/phishing'); } catch { /* navigation state is optional */ }
    one('#emailSubject')?.focus({ preventScroll: true });
  }

  function renderResult(payload) {
    const evidence = payload.evidence || {};
    const decision = payload.gateway_decision || {};
    const specialistState = STATE_LABELS[evidence.state] ? evidence.state : 'UNCERTAIN';
    const observations = Array.isArray(evidence.observations) ? evidence.observations : [];
    const authentication = observations.filter((item) => item.protocol);
    const deterministic = observations.filter((item) => item.code);
    const relationships = Array.isArray(evidence.relationships) ? evidence.relationships : [];
    const infrastructure = Array.isArray(evidence.infrastructure) ? evidence.infrastructure : [];
    const children = Array.isArray(evidence.children) ? evidence.children : [];
    const model = Array.isArray(evidence.model_evidence) ? evidence.model_evidence[0] : null;
    const limitations = Array.isArray(evidence.limitations) ? evidence.limitations : [];
    const completeness = evidence.evidence_completeness || {};
    const infrastructureSummary = evidence.infrastructure_summary || {};
    const threatIntelligence = evidence.threat_intelligence || {};
    const campaignMemory = evidence.campaign_memory || {};
    const passport = evidence.evidence_passport || null;
    const riskValue = decisionRiskValue(decision, evidence);
    const risk = global.VeriTrustAnalysisResult.percent(riskValue);
    const modelLikelihood = Number.isFinite(Number(model?.p_phish)) ? `${Math.round(Number(model.p_phish) * 100)}%` : 'Unavailable';
    const stateCopy = {
      LIKELY_PHISHING: 'This email shows signs commonly associated with phishing. Do not click links, open attachments, reply, or share information until it is independently verified.',
      LIKELY_BENIGN: 'The available checks did not find strong phishing signs. This is not a guarantee of safety, especially where evidence was unavailable.',
      UNCERTAIN: 'The available evidence is not strong enough for a reliable conclusion. Verify the sender through a known phone number or official website.',
      UNSUPPORTED: 'Part of this email could not be safely processed within the service limits. Treat the result as incomplete and review it manually.',
      FAILED: 'A required check failed, so VeriTrust did not label the message as safe. Try again or review it manually.',
    }[specialistState];
    const recommendation = DECISION_LABELS[decision.recommendation] || 'Review manually';
    const signals = essentialSignals({ deterministic, authentication, relationships, children, threatIntelligence });
    const checkedDimensions = Number(completeness.checked_dimensions);
    const totalDimensions = Number(completeness.total_dimensions);
    const coverage = Number.isFinite(checkedDimensions) && Number.isFinite(totalDimensions) && totalDimensions > 0
      ? `${checkedDimensions}/${totalDimensions} evidence dimensions checked`
      : 'Coverage derived from the submitted evidence';
    const target = one('#phishingResult');
    const shell = one('#emailInvestigationResult');
    if (!target || !shell) return;

    target.innerHTML = `
      <article class="email-result-hero email-result-hero--compact" data-state="${specialistState}">
        <div class="email-result-primary">
          <p class="email-result-kicker">Investigation result</p>
          <h2 id="emailResultTitle">${escapeHtml(STATE_LABELS[specialistState])}</h2>
          <p>${escapeHtml(stateCopy)}</p>
          <div class="email-result-actions">
            <button class="btn btn-primary email-pdf-view" type="button" data-view-email-pdf>View Complete Report</button>
            <button class="btn btn-secondary" type="button" data-new-investigation>New investigation</button>
            ${['manual_review', 'hold', 'quarantine', 'block'].includes(decision.recommendation) ? '<a class="btn btn-secondary" href="cases.html">Open cases</a>' : ''}
          </div>
        </div>
        <aside class="email-result-decision" aria-label="Gateway decision summary">
          <div class="email-risk-score"><span>${helpLabel('Risk score', HELP.risk)}</span><strong>${escapeHtml(risk)}</strong><small>Gateway correlation</small></div>
          <div class="email-next-action"><span>Recommended action</span><strong>${escapeHtml(recommendation)}</strong><small>${decision.degraded ? 'Some checks were unavailable; review evidence gaps.' : 'Based on the evidence available to this investigation.'}</small></div>
        </aside>
      </article>
      <section class="email-result-metrics" aria-label="Investigation summary">
        <article><span>Evidence strength</span><strong>${escapeHtml(titleCase(completeness.level || 'limited'))}</strong><small>${escapeHtml(coverage)}</small></article>
        <article><span>AI content signal</span><strong>${escapeHtml(modelLikelihood)}</strong><small>${model?.status === 'completed' ? 'Supporting phishing likelihood' : 'Model evidence unavailable or incomplete'}</small></article>
        <article><span>Key findings</span><strong>${escapeHtml(String(deterministic.length))}</strong><small>Rule-based content/format signals</small></article>
        <article><span>Recorded limitations</span><strong>${escapeHtml(String(limitations.length))}</strong><small>Missing evidence is never treated as safe</small></article>
      </section>
      ${renderCompactUspSummary({ evidence, infrastructure, infrastructureSummary, campaignMemory, passport, scanId: payload.scan_id })}
      <section class="email-essential-signals" aria-labelledby="essentialSignalsTitle">
        <div><p class="email-result-kicker">Decision evidence</p><h3 id="essentialSignalsTitle">Key signals to review</h3></div>
        <div class="email-signal-chips">${signals.length ? signals.map((item) => `<span data-tone="${escapeHtml(item.tone)}">${escapeHtml(item.label)}</span>`).join('') : '<span data-tone="neutral">No high-priority deterministic signal was recorded; review the complete report for evidence coverage.</span>'}</div>
        <p>The browser view intentionally shows only decision-critical information. Authentication details, relay reconstruction, GeoTrace map, domain/IP intelligence, campaign entities, Evidence Passport hashes, provenance, limitations, and complete response data are preserved in the PDF.</p>
      </section>`;

    shell.hidden = false;
    document.body.classList.add('vt-email-has-result');
    enhanceHelpTerms(target);
    state.lastScanId = payload.scan_id || null;

    one('[data-new-investigation]', target)?.addEventListener('click', resetInvestigationView);
    one('[data-upgrade-evidence]', target)?.addEventListener('click', (event) => {
      state.parentScanId = event.currentTarget.dataset.parentScan || payload.scan_id || null;
      document.body.classList.remove('vt-email-has-result');
      shell.hidden = true;
      setMode('eml', true);
      setStatus('Evidence upgrade started. Select the original .eml; VeriTrust will link the new scan to this investigation.');
    });
    one('[data-view-email-pdf]', target)?.addEventListener('click', async (event) => {
      const button = event.currentTarget;
      const originalLabel = button.textContent;
      button.disabled = true;
      button.textContent = 'Opening report…';
      try {
        if (!global.VeriTrustEmailPdf?.openEmailReportPdf) throw new Error('The PDF report viewer did not load.');
        await global.VeriTrustEmailPdf.openEmailReportPdf(payload);
        button.textContent = 'Report opened';
        global.setTimeout(() => { button.textContent = originalLabel; button.disabled = false; }, 1800);
      } catch (error) {
        button.textContent = 'Could not open report';
        setError(`${error.message} Allow pop-ups for VeriTrust and try again.`);
        global.setTimeout(() => { button.textContent = originalLabel; button.disabled = false; }, 3200);
      }
    });
    shell.focus({ preventScroll: true });
  }

  function renderFailure(error) {
    const shell = one('#emailInvestigationResult');
    const target = one('#phishingResult');
    if (!shell || !target) return;
    const guidance = failureGuidance(error);
    target.innerHTML = `<article class="email-result-hero email-result-hero--compact" data-state="FAILED"><div class="email-result-primary"><p class="email-result-kicker">Investigation interrupted</p><h2 id="emailResultTitle">Check could not be completed</h2><p>${escapeHtml(error.message)} VeriTrust did not label the message as safe. ${escapeHtml(guidance.detail)}</p><div class="email-result-actions"><button class="btn btn-primary" type="button" data-new-investigation>Try a new investigation</button></div></div><aside class="email-result-decision"><div class="email-risk-score"><span>Risk score</span><strong>—</strong><small>No complete gateway decision</small></div><div class="email-next-action"><span>What to do</span><strong>Retry or review manually</strong><small>${helpLabel('Error details available', `Technical code: ${error.code || 'EMAIL_ANALYSIS_FAILED'}. Share this with support if the problem continues.`)}</small></div></aside></article>`;
    shell.hidden = false;
    document.body.classList.add('vt-email-has-result');
    enhanceHelpTerms(target);
    one('[data-new-investigation]', target)?.addEventListener('click', resetInvestigationView);
  }

  let activeHelpButton = null;
  let pinnedHelpButton = null;

  function positionHelpTooltip(button) {
    const tooltip = one('#emailHelpTooltip');
    if (!tooltip || !button || tooltip.hidden) return;
    const buttonRect = button.getBoundingClientRect();
    const tooltipRect = tooltip.getBoundingClientRect();
    const margin = 12;
    const centeredLeft = buttonRect.left + (buttonRect.width / 2) - (tooltipRect.width / 2);
    const left = Math.max(margin, Math.min(centeredLeft, global.innerWidth - tooltipRect.width - margin));
    const below = buttonRect.bottom + 10;
    const top = below + tooltipRect.height <= global.innerHeight - margin
      ? below
      : Math.max(margin, buttonRect.top - tooltipRect.height - 10);
    tooltip.style.left = `${Math.round(left)}px`;
    tooltip.style.top = `${Math.round(top)}px`;
  }

  function openHelp(button, pinned = false) {
    const tooltip = one('#emailHelpTooltip');
    const term = button.closest('[data-email-help]');
    if (!tooltip || !term) return;
    if (activeHelpButton && activeHelpButton !== button) activeHelpButton.setAttribute('aria-expanded', 'false');
    activeHelpButton = button;
    if (pinned) pinnedHelpButton = button;
    tooltip.textContent = term.dataset.emailHelp || '';
    tooltip.hidden = false;
    button.setAttribute('aria-expanded', 'true');
    button.setAttribute('aria-describedby', tooltip.id);
    global.requestAnimationFrame(() => positionHelpTooltip(button));
  }

  function closeHelp(force = false) {
    if (pinnedHelpButton && !force) return;
    const tooltip = one('#emailHelpTooltip');
    if (activeHelpButton) {
      activeHelpButton.setAttribute('aria-expanded', 'false');
      activeHelpButton.removeAttribute('aria-describedby');
    }
    if (tooltip) tooltip.hidden = true;
    activeHelpButton = null;
    if (force) pinnedHelpButton = null;
  }

  function enhanceHelpTerms(root = document) {
    all('[data-email-help]:not([data-email-help-ready])', root).forEach((term) => {
      term.dataset.emailHelpReady = 'true';
      term.classList.add('email-help-term');
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'email-help-button';
      button.setAttribute('aria-label', `Explain ${term.dataset.emailTerm || term.textContent.trim()}`);
      button.setAttribute('aria-expanded', 'false');
      button.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2.75 12s3.35-5.25 9.25-5.25S21.25 12 21.25 12 17.9 17.25 12 17.25 2.75 12 2.75 12Z"/><circle cx="12" cy="12" r="2.4"/></svg>';
      term.append(button);
      button.addEventListener('pointerenter', () => openHelp(button));
      button.addEventListener('pointerleave', () => { if (pinnedHelpButton !== button) closeHelp(); });
      button.addEventListener('focus', () => openHelp(button));
      button.addEventListener('blur', () => { if (pinnedHelpButton !== button) closeHelp(); });
      button.addEventListener('click', (event) => {
        event.preventDefault();
        event.stopPropagation();
        if (pinnedHelpButton === button) closeHelp(true);
        else openHelp(button, true);
      });
    });
  }

  function bindTabs() {
    const tabs = all('[data-email-mode]');
    tabs.forEach((tab, index) => {
      tab.addEventListener('click', () => setMode(tab.dataset.emailMode, true));
      tab.addEventListener('keydown', (event) => {
        if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
        event.preventDefault();
        let next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : (index + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
        tabs[next].focus();
        setMode(tabs[next].dataset.emailMode);
      });
    });
  }

  function init() {
    const form = one('#phishingForm[data-email-workbench]');
    if (!form) return;
    enhanceHelpTerms();
    document.addEventListener('click', () => closeHelp(true));
    document.addEventListener('keydown', (event) => { if (event.key === 'Escape') closeHelp(true); });
    global.addEventListener('resize', () => positionHelpTooltip(activeHelpButton));
    global.addEventListener('scroll', () => positionHelpTooltip(activeHelpButton), { passive: true });
    bindTabs();
    const text = one('#phishingText');
    text?.addEventListener('input', () => { const output = one('#emailCharacterCount'); if (output) output.textContent = `${text.value.length.toLocaleString()} / 12,000`; });
    const fileInput = one('#emailEmlFile');
    fileInput?.addEventListener('change', () => { try { chooseFile(fileInput.files?.[0]); setError(''); } catch (error) { state.file = null; setError(error.message); } });
    const dropzone = one('.email-dropzone');
    ['dragenter', 'dragover'].forEach((name) => dropzone?.addEventListener(name, (event) => { event.preventDefault(); dropzone.classList.add('is-dragging'); }));
    ['dragleave', 'drop'].forEach((name) => dropzone?.addEventListener(name, (event) => { event.preventDefault(); dropzone.classList.remove('is-dragging'); }));
    dropzone?.addEventListener('drop', (event) => { try { chooseFile(event.dataTransfer?.files?.[0]); setError(''); } catch (error) { state.file = null; setError(error.message); } });
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (state.busy) return;
      setError('');
      setBusy(true);
      analysisProgress.begin();
      const previousReport = one('#emailInvestigationResult');
      if (previousReport) previousReport.hidden = true;
      setStatus('Checking the message and available sender evidence...');
      try {
        const payload = await requestInvestigation();
        if (!payload.evidence && payload.status === 'processing' && payload.scan_id) {
          const shell = one('#emailInvestigationResult');
          const target = one('#phishingResult');
          if (shell && target) {
            target.innerHTML = `<h2 id="emailResultTitle">This scan is already processing</h2><p>A completed report is not available yet.</p><a class="btn btn-secondary" href="/phishing?scan_id=${encodeURIComponent(payload.scan_id)}">Follow this scan</a>`;
            shell.hidden = false;
          }
          analysisProgress.finish(null, { pending: true });
          setStatus('The server confirmed that the scan is still processing.');
          return;
        }
        if (!payload.evidence || !payload.gateway_decision) throw new Error('The server response did not contain the email evidence and policy decision.');
        renderResult(payload);
        analysisProgress.finish();
        setStatus('Check complete. Review the result and any missing evidence.');
      } catch (error) {
        analysisProgress.finish(error);
        setStatus('');
      } finally {
        setBusy(false);
      }
    });
    setMode('text');
    const savedScanId = queryParameter('scan_id');
    if (savedScanId) void loadSavedInvestigation(savedScanId);
  }

  document.addEventListener('DOMContentLoaded', init);
}(window));
