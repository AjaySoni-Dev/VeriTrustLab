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
    acquisitionStage: 'The acquisition stage tells you how the email evidence was obtained. Pasted text has the least transport context, an original .eml adds message structure and headers, and a trusted receiver adds facts observed directly at the SMTP boundary.',
    completeness: 'Evidence completeness measures how much of the forensic checklist could actually run. It does not say whether the email is safe or malicious.',
    trustedReceiver: 'A trusted receiver is a mail server or receiver integration configured by VeriTrust to record SMTP facts directly as the message arrives. Those facts are stronger than claims reconstructed later from message headers.',
    observedRelay: 'An observed relay is a server hop reconstructed from the email headers. Headers can be incomplete or forged, so VeriTrust keeps this evidence explicitly below the trusted-receiver level.',
    asn: 'An Autonomous System Number (ASN) identifies the network operator that announces an IP range on the Internet. It is infrastructure context, not proof of the person who sent the email.',
    geoContext: 'Geo context is an approximate location associated with network infrastructure. It does not identify the physical location of an attacker or sender.',
    campaignMemory: 'Campaign Memory compares privacy-minimized forensic entities from this investigation with prior investigations in the same workspace. It links scans only when the overlap is strong enough under conservative rules.',
    correlationWeight: 'Correlation weight is a deterministic importance score. More durable indicators, such as an exact attachment hash, contribute more than weak infrastructure or domain coincidences.',
    privacyMinimized: 'Privacy-minimized correlation uses normalized or hashed forensic entities instead of keeping full message bodies as the matching primitive.',
    evidencePassport: 'An Evidence Passport is a signed integrity package for the investigation. It binds the evidence and manifest to cryptographic hashes and a signing key so later changes can be detected.',
    sha256: 'SHA-256 is a cryptographic hash. If the packaged evidence changes, its SHA-256 value changes as well.',
    ed25519: 'Ed25519 is the digital-signature algorithm used to authenticate the Evidence Passport. Verification checks that the package matches the signature and expected signing key.',
    keyId: 'The signing key ID is a stable identifier derived from the public verification key. It helps distinguish trusted issuers and rotated keys.',
    manifest: 'The evidence manifest records the package structure and provenance metadata that are bound into the Evidence Passport.',
    stix: 'STIX 2.1 is a standard format for exchanging cyber-threat intelligence between security tools.',
    ioc: 'An IOC, or indicator of compromise, is a security-relevant artifact such as a domain, URL, IP address, or file hash that can be exported for further investigation.',
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
  const state = { mode: 'text', file: null, busy: false, lastScanId: null, parentScanId: null, lastIdempotencyKey: null, lastRequestBody: null };
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

  function resultPath(scanId, tab = '') {
    const id = String(scanId || '').trim();
    const params = new URLSearchParams();
    if (id) params.set('scan_id', id);
    if (tab) params.set('tab', tab);
    return `/phishing-result${params.toString() ? `?${params.toString()}` : ''}`;
  }

  function openNewInvestigation() {
    global.location.href = '/phishing';
  }

  function isResultPage() {
    const pathname = String(global.location?.pathname || '');
    return /\/phishing-result(?:\.html)?$/iu.test(pathname) || Boolean(document.body?.classList?.contains?.('vt-email-result-page'));
  }

  function setStatus(message) {
    const target = one('#activityLog');
    if (target) target.textContent = message;
  }

  function setError(message) {
    const target = one('#emailInputError');
    if (!target) {
      const status = one('#activityLog');
      if (status && message) status.textContent = message;
      return;
    }
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
    state.lastIdempotencyKey = idempotencyKey;
    state.lastScanId = null;
    if (state.mode === 'eml') {
      const file = validateFile(state.file || one('#emailEmlFile')?.files?.[0]);
      state.lastRequestBody = file;
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
    const jsonPayload = JSON.stringify({ subject, body, channel: 'email', retention_policy: 'metadata_only', org_id: context.organization.id, ...(state.parentScanId ? { parent_scan_id: state.parentScanId } : {}) });
    state.lastRequestBody = jsonPayload;
    return analysisProgress.request(endpoint('emailAnalyzeText', '/api/v1/gateway/email/analyze-text'), {
      signal,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Idempotency-Key': idempotencyKey },
      body: jsonPayload,
    });
  }


  async function loadSavedInvestigation(scanId) {
    const id = String(scanId || '').trim();
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(id)) return;
    setStatus('Loading the saved forensic investigation...');
    let lastError = null;
    for (let attempt = 0; attempt < 4; attempt += 1) {
      try {
        const response = await global.fetch(`/api/v2/phishing/evidence/${encodeURIComponent(id)}`, {
          method: 'GET', credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json' },
        });
        const payload = await parseResponse(response);
        if (!payload.evidence || !payload.gateway_decision) throw new Error('The saved scan does not contain a complete email decision.');
        renderResult(payload);
        setStatus('');
        return;
      } catch (error) {
        lastError = error;
        const retryable = error?.code === 'EMAIL_EVIDENCE_NOT_FOUND';
        if (!retryable || attempt >= 3) break;
        setStatus(`Finalizing saved evidence… retry ${attempt + 1} of 3.`);
        await new Promise((resolve) => global.setTimeout(resolve, 250 * (2 ** attempt)));
      }
    }
    renderFailure(lastError || new Error('The saved forensic investigation could not be loaded.'));
    setStatus('The saved forensic investigation could not be loaded.');
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


  function acquisitionStageIndex(mode) {
    return ({ plain_text: 0, raw_eml: 1, trusted_receiver_event: 2 })[mode] ?? 0;
  }

  function renderProgressiveEvidenceDetails(evidence, scanId) {
    const completeness = evidence.evidence_completeness || {};
    const dimensions = completeness.dimensions && typeof completeness.dimensions === 'object' ? completeness.dimensions : {};
    const lineage = evidence.investigation_lineage || {};
    const currentIndex = acquisitionStageIndex(evidence.input_mode);
    const stages = [
      ['Pasted text', 'Content, AI and visible links'],
      ['Original .eml', 'Headers, identity, MIME, attachments and relays'],
      ['Trusted receiver', 'Direct SMTP facts, SPF and trusted boundary'],
    ];
    const dimensionLabels = { content: 'Content', ai_model: 'AI', authentication: 'Authentication', identity: 'Identity', infrastructure: 'Infrastructure' };
    const stageMarkup = stages.map(([name, description], index) => {
      const stageState = index < currentIndex ? 'complete' : index === currentIndex ? 'current' : 'future';
      const marker = index < currentIndex ? '✓' : String(index + 1).padStart(2, '0');
      return `<article data-stage-state="${stageState}"><span>${marker}</span><div><strong>${escapeHtml(name)}</strong><small>${escapeHtml(description)}</small></div></article>`;
    }).join('');
    const visibleDimensions = ['content', 'ai_model', 'authentication', 'identity', 'infrastructure'];
    const matrix = visibleDimensions.filter((key) => key in dimensions).map((key) => {
      const value = dimensions[key];
      return `<div class="email-evidence-dimension"><span>${escapeHtml(dimensionLabels[key])}</span><strong data-coverage="${escapeHtml(String(value || 'UNKNOWN').toLowerCase())}">${escapeHtml(friendlyStatus(value || 'UNKNOWN'))}</strong></div>`;
    }).join('') + `<div class="email-evidence-dimension"><span>Attachments / Links</span><strong>${escapeHtml(friendlyStatus(dimensions.attachments || 'UNKNOWN'))} / ${escapeHtml(friendlyStatus(dimensions.links || 'UNKNOWN'))}</strong></div>`;
    const nextActions = Array.isArray(completeness.next_actions) ? completeness.next_actions : [];
    const nextMarkup = nextActions.length ? nextActions.map((item) => {
      const unlocks = Array.isArray(item.unlocks) ? item.unlocks : [];
      const action = item.action === 'UPLOAD_ORIGINAL_EML'
        ? `<a class="btn btn-secondary" href="/phishing?mode=eml&parent_scan_id=${encodeURIComponent(scanId || '')}">Add original .eml</a>`
        : item.action === 'USE_TRUSTED_RECEIVER'
          ? '<a class="btn btn-secondary" href="/gateway-powershell#live-smtp">Open trusted SMTP guide</a>'
          : '';
      return `<div class="email-evidence-upgrade"><div><strong>${escapeHtml(item.label || titleCase(item.action || 'Evidence upgrade'))}</strong>${unlocks.length ? `<div class="email-unlock-list" aria-label="Evidence unlocked by this upgrade">${unlocks.map((value) => `<span>${escapeHtml(titleCase(value))}</span>`).join('')}</div>` : ''}</div>${action}</div>`;
    }).join('') : '';
    const parent = lineage.parent_scan_id
      ? `<div class="email-lineage"><span>Investigation lineage</span><strong>Upgraded from a prior evidence stage</strong><a href="${resultPath(lineage.parent_scan_id, 'progressive')}">Open previous scan ${escapeHtml(String(lineage.parent_scan_id).slice(0, 8))}… →</a></div>`
      : '';

    return `<section class="email-usp-tabpanel" id="uspPanelProgressive" role="tabpanel" aria-labelledby="uspTabProgressive" data-usp-panel="progressive">
      <header class="email-usp-panel-header">
        <div><p class="email-result-kicker">USP 01 · Progressive Evidence Escalation™</p><h3>Evidence Acquisition &amp; Claim Boundaries</h3></div>
        <div class="email-usp-panel-state"><span>${helpLabel('Acquisition stage', HELP.acquisitionStage)}</span><strong>${escapeHtml(evidenceStageName(evidence.input_mode))}</strong></div>
      </header>
      <div class="email-ladder-track" aria-label="Evidence acquisition ladder">${stageMarkup}</div>
      <div class="email-section-heading"><h4>${helpLabel('Evidence coverage', HELP.completeness)}</h4></div>
      <div class="email-evidence-grid" aria-label="Evidence coverage by forensic dimension">${matrix || '<p>No dimension-level coverage was returned.</p>'}</div>
      ${parent}
      ${nextMarkup}
    </section>`;
  }

  function geoCoordinate(value, fallback) {
    const number = Number(value);
    return Number.isFinite(number) ? number : fallback;
  }

  function renderGeoTraceDetails(infrastructure, infrastructureSummary) {
    const allHops = Array.isArray(infrastructure) ? infrastructure : [];
    const publicHops = allHops.filter((hop) => hop.ip_classification === 'public');
    const geoHops = publicHops.filter((hop) => Number.isFinite(Number(hop.latitude)) && Number.isFinite(Number(hop.longitude)))
      .sort((a, b) => Number(a.hop_index || 0) - Number(b.hop_index || 0));
    const width = 720;
    const height = 360;
    // The background SVG is true equirectangular (-180..180, -90..90), so
    // markers use the identical projection with no decorative inset/padding.
    const pointFor = (hop) => {
      const lon = Math.max(-180, Math.min(180, geoCoordinate(hop.longitude, 0)));
      const lat = Math.max(-90, Math.min(90, geoCoordinate(hop.latitude, 0)));
      return {
        x: ((lon + 180) / 360) * width,
        y: ((90 - lat) / 180) * height,
      };
    };
    const points = geoHops.map((hop) => ({ hop, ...pointFor(hop) }));
    const polyline = points.length > 1 ? `<g class="email-geotrace-path"><polyline points="${points.map((point) => `${point.x.toFixed(2)},${point.y.toFixed(2)}`).join(' ')}"></polyline></g>` : '';
    const nodes = points.map((point, index) => {
      const hopNumber = Number(point.hop.hop_index ?? index) + 1;
      const location = [point.hop.city, point.hop.region, point.hop.country].filter(Boolean).join(', ') || 'Approximate infrastructure location unavailable';
      const network = [point.hop.host, point.hop.ip_address, point.hop.asn ? `AS${String(point.hop.asn).replace(/^AS/iu, '')}` : '', point.hop.asn_org].filter(Boolean).join(' · ') || 'Mail infrastructure hop';
      const trust = point.hop.trust_level === 'trusted_receiver' ? 'Trusted receiver observation' : 'Observed relay claim';
      return `<g class="email-geotrace-node ${point.hop.trust_level === 'trusted_receiver' ? 'is-trusted' : 'is-observed'}" transform="translate(${point.x.toFixed(2)} ${point.y.toFixed(2)})"><title>${escapeHtml(`Hop ${hopNumber}: ${network} · ${location} · ${trust}`)}</title><circle r="8"></circle><text text-anchor="middle" dominant-baseline="central">${hopNumber}</text></g>`;
    }).join('');
    const grid = [0.25, 0.5, 0.75].map((ratio) => `<line x1="${(width * ratio).toFixed(1)}" x2="${(width * ratio).toFixed(1)}" y1="0" y2="${height}"></line>`).join('')
      + [1 / 3, 2 / 3].map((ratio) => `<line x1="0" x2="${width}" y1="${(height * ratio).toFixed(1)}" y2="${(height * ratio).toFixed(1)}"></line>`).join('');
    const map = points.length
      ? `<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Approximate mail infrastructure map with numbered relay hops"><g class="email-geotrace-grid">${grid}</g>${polyline}${nodes}</svg>`
      : '<p>No public relay returned usable latitude/longitude enrichment. Relay provenance is still listed below.</p>';
    const hopRows = allHops.length ? allHops.map((hop, index) => {
      const location = [hop.city, hop.region, hop.country].filter(Boolean).join(', ') || 'Location unavailable';
      const networkBits = [hop.host, hop.ip_address, hop.asn ? `AS${String(hop.asn).replace(/^AS/iu, '')}` : '', hop.asn_org].filter(Boolean).join(' · ') || 'No infrastructure identity recorded';
      const trusted = hop.trust_level === 'trusted_receiver';
      return `<article class="email-hop-row" data-trust="${trusted ? 'trusted' : 'observed'}"><span>${Number(hop.hop_index ?? index) + 1}</span><div><strong>${escapeHtml(networkBits)}</strong><small>${escapeHtml(location)} · ${escapeHtml(titleCase(hop.ip_classification || 'unknown'))}</small></div><em>${trusted ? helpLabel('Trusted receiver', HELP.trustedReceiver) : helpLabel('Observed relay', HELP.observedRelay)}</em></article>`;
    }).join('') : '<p class="email-detail-empty">No relay infrastructure was available for this acquisition stage.</p>';
    const stateLabel = ({ TRUSTED_BOUNDARY_OBSERVED: 'Trusted boundary observed', OBSERVED_UNVERIFIED: 'Observed relays · origin unverified', UNAVAILABLE: 'Infrastructure unavailable' })[infrastructureSummary.state] || titleCase(infrastructureSummary.state || 'Unavailable');

    return `<section class="email-usp-tabpanel email-geotrace" id="uspPanelGeotrace" role="tabpanel" aria-labelledby="uspTabGeotrace" data-usp-panel="geotrace" hidden>
      <header class="email-usp-panel-header">
        <div><p class="email-result-kicker">USP 02 · Trust-Boundary GeoTrace™</p><h3>Infrastructure Provenance &amp; Boundary Verification</h3></div>
        <div class="email-usp-panel-state"><span>Trust state</span><strong>${escapeHtml(stateLabel)}</strong></div>
      </header>
      <div class="email-trust-banner" data-state="${escapeHtml(String(infrastructureSummary.state || 'UNAVAILABLE').toLowerCase())}"><strong>${escapeHtml(stateLabel)}</strong><span>${escapeHtml(infrastructureSummary.wording || 'Mail infrastructure context only; no physical-person attribution.')}</span></div>
      <div class="email-section-heading"><h4>Approximate infrastructure map</h4><p>Coordinates describe mail infrastructure only; they do not identify a sender or attacker.</p></div><div class="email-geotrace-map">${map}</div>
      <div class="email-geotrace-legend"><span data-trust="trusted">Trusted receiver observation</span><span data-trust="observed">Observed relay claim</span></div>
      <div class="email-section-heading"><h4>Mail infrastructure path</h4></div>
      <div class="email-hop-list">${hopRows}</div>
    </section>`;
  }

  function renderCampaignMemoryDetails(campaignMemory) {
    const related = Array.isArray(campaignMemory.related_scans)
      ? campaignMemory.related_scans.filter((item) => item?.scan_id)
      : [];
    const common = Array.isArray(campaignMemory.common_entities) ? campaignMemory.common_entities : [];
    const correlated = campaignMemory.state === 'CORRELATED';
    const weakCount = Number(campaignMemory.weak_candidate_count || 0);
    const summary = correlated
      ? `<div class="email-campaign-summary"><strong>${escapeHtml(campaignMemory.campaign_id || 'Correlated campaign')}</strong><span>${escapeHtml(String(campaignMemory.related_scan_count || related.length))} prior investigation(s) · strongest weighted match ${escapeHtml(String(campaignMemory.strongest_match_score ?? '—'))}</span></div>`
      : `<div class="email-campaign-summary"><strong>${campaignMemory.state === 'UNAVAILABLE' ? 'Campaign correlation unavailable' : 'No strong prior campaign match'}</strong><span>${weakCount ? `${escapeHtml(String(weakCount))} weak candidate${weakCount === 1 ? '' : 's'} rejected` : 'No sufficiently strong prior overlap'}</span></div>`;
    const entities = common.length
      ? `<div class="email-campaign-entities" aria-label="Matched campaign entities">${common.slice(0, 8).map((item) => `<article><div><strong>${escapeHtml(titleCase(item.entity_type || 'entity'))}</strong><code>${escapeHtml(item.entity_value || 'Unavailable')}</code></div><span>${helpLabel(`weight ${String(item.weight ?? '—')}`, HELP.correlationWeight)}</span><em>${escapeHtml(titleCase(item.trust_level || 'observed'))}</em></article>`).join('')}</div>`
      : '<p class="email-detail-empty">No campaign entity passed the conservative correlation threshold.</p>';
    const relatedLinks = related.length
      ? `<div class="email-related-scans"><strong>Related investigations</strong>${related.slice(0, 8).map((item) => `<a href="${resultPath(item.scan_id || '', 'campaign')}"><span>${escapeHtml(String(item.scan_id || '').slice(0, 12))}${item.scan_id ? '…' : 'Unknown scan'}</span><em>score ${escapeHtml(String(item.score ?? '—'))} →</em></a>`).join('')}</div>`
      : '';
    const stateLabel = correlated ? 'Correlated' : campaignMemory.state === 'UNAVAILABLE' ? 'Unavailable' : 'Conservative no-match';

    return `<section class="email-usp-tabpanel" id="uspPanelCampaign" role="tabpanel" aria-labelledby="uspTabCampaign" data-usp-panel="campaign" hidden>
      <header class="email-usp-panel-header">
        <div><p class="email-result-kicker">USP 03 · MailGraph Campaign Memory™</p><h3>Prior Campaign &amp; Infrastructure Correlation</h3></div>
        <div class="email-usp-panel-state"><span>${helpLabel('Campaign Memory', HELP.campaignMemory)}</span><strong>${escapeHtml(stateLabel)}</strong></div>
      </header>
      ${summary}
      <div class="email-section-heading"><h4>Matched forensic entities</h4><p>${helpLabel('Correlation weight', HELP.correlationWeight)} shows how much each repeated entity contributes.</p></div>
      ${entities}
      ${relatedLinks}
    </section>`;
  }

  function renderPassportDetails(passport, scanId) {
    const exportBase = scanId ? `/api/v2/phishing/export/${encodeURIComponent(scanId)}` : null;
    const exportActions = exportBase
      ? `<div class="email-export-actions" aria-label="Evidence export actions">
          <a class="btn btn-secondary" href="${exportBase}/json">Export Evidence JSON</a>
          ${scanId ? `<a class="btn btn-primary" href="/verify-evidence?scan_id=${encodeURIComponent(scanId)}">Verify Passport</a>` : ''}
          <details class="email-more-exports"><summary>More exports</summary><div><a href="${exportBase}/stix">STIX 2.1</a><a href="${exportBase}/csv">IOC CSV</a><a href="${exportBase}/iocs">IOC JSON</a></div></details>
        </div>`
      : '';
    const stateLabel = passport?.passport_id ? `${passport.signature_algorithm || 'Ed25519'} signed` : 'Unavailable';
    const body = !passport?.passport_id
      ? `<p class="email-detail-empty">This investigation does not contain a signed Evidence Passport.</p>${exportActions}`
      : `<div class="email-passport-card">
          <div><span>Passport ID</span><code>${escapeHtml(passport.passport_id)}</code></div>
          <div><span>${helpLabel('Signing algorithm', HELP.ed25519)}</span><strong>${escapeHtml(passport.signature_algorithm || 'Ed25519')}</strong></div>
          <div><span>${helpLabel('Signing key ID', HELP.keyId)}</span><code>${escapeHtml(passport.key_id || 'Unavailable')}</code></div>
          <div><span>Key source</span><strong>${escapeHtml(titleCase(passport.key_source || 'not recorded'))}</strong></div>
          <div><span>${helpLabel('Evidence SHA-256', HELP.sha256)}</span><code>${escapeHtml(passport.evidence_sha256 || 'Unavailable')}</code></div>
          <div><span>${helpLabel('Manifest SHA-256', HELP.manifest)}</span><code>${escapeHtml(passport.manifest_sha256 || 'Unavailable')}</code></div>
        </div>
        <div class="email-section-heading"><h4>Export &amp; Verification</h4></div>
        ${exportActions}`;

    return `<section class="email-usp-tabpanel" id="uspPanelPassport" role="tabpanel" aria-labelledby="uspTabPassport" data-usp-panel="passport" hidden>
      <header class="email-usp-panel-header">
        <div><p class="email-result-kicker">USP 04 · Evidence Passport™</p><h3>Cryptographic Provenance &amp; Verification</h3></div>
        <div class="email-usp-panel-state"><span>Passport state</span><strong>${escapeHtml(stateLabel)}</strong></div>
      </header>
      ${body}
    </section>`;
  }

  function renderUspTabs({ evidence, infrastructure, infrastructureSummary, campaignMemory, passport, scanId }) {
    const completeness = evidence.evidence_completeness || {};
    const publicHops = infrastructure.filter((hop) => hop.ip_classification === 'public');
    const trusted = publicHops.filter((hop) => hop.trust_level === 'trusted_receiver');
    const relatedCount = Number(campaignMemory.related_scan_count || campaignMemory.related_scans?.length || 0);
    const geoState = trusted.length ? 'Trusted boundary' : publicHops.length ? 'Observed relays' : 'Unavailable';
    const campaignState = campaignMemory.state === 'CORRELATED'
      ? `${relatedCount} linked`
      : campaignMemory.state === 'UNAVAILABLE' ? 'Unavailable' : 'No strong match';
    const passportState = passport?.passport_id ? 'Signed' : 'Unavailable';

    return `<section class="email-usp-workspace" aria-label="Forensic capability views">
      <div class="email-usp-tabs" role="tablist" aria-label="VeriTrust forensic capabilities">
        <button class="email-usp-tab" id="uspTabProgressive" type="button" role="tab" aria-selected="true" aria-controls="uspPanelProgressive" data-usp-tab="progressive">
          <span class="email-usp-tab-index">01</span><span class="email-usp-tab-label"><strong>Acquisition</strong></span><em>${escapeHtml(evidenceStageName(evidence.input_mode))} · ${escapeHtml(titleCase(completeness.level || 'limited'))}</em>
        </button>
        <button class="email-usp-tab" id="uspTabGeotrace" type="button" role="tab" aria-selected="false" aria-controls="uspPanelGeotrace" data-usp-tab="geotrace" tabindex="-1">
          <span class="email-usp-tab-index">02</span><span class="email-usp-tab-label"><strong>GeoTrace</strong></span><em>${escapeHtml(geoState)}</em>
        </button>
        <button class="email-usp-tab" id="uspTabCampaign" type="button" role="tab" aria-selected="false" aria-controls="uspPanelCampaign" data-usp-tab="campaign" tabindex="-1">
          <span class="email-usp-tab-index">03</span><span class="email-usp-tab-label"><strong>Campaign</strong></span><em>${escapeHtml(campaignState)}</em>
        </button>
        <button class="email-usp-tab" id="uspTabPassport" type="button" role="tab" aria-selected="false" aria-controls="uspPanelPassport" data-usp-tab="passport" tabindex="-1">
          <span class="email-usp-tab-index">04</span><span class="email-usp-tab-label"><strong>Passport</strong></span><em>${escapeHtml(passportState)}</em>
        </button>
      </div>
      <div class="email-usp-tabpanels">
        ${renderProgressiveEvidenceDetails(evidence, scanId)}
        ${renderGeoTraceDetails(infrastructure, infrastructureSummary)}
        ${renderCampaignMemoryDetails(campaignMemory)}
        ${renderPassportDetails(passport, scanId)}
      </div>
    </section>`;
  }

  function bindUspTabs(root, scanId) {
    const tabs = all('[data-usp-tab]', root);
    const panels = all('[data-usp-panel]', root);
    if (!tabs.length || !panels.length) return;
    const available = new Set(tabs.map((tab) => tab.dataset.uspTab));
    const requested = String(queryParameter('tab') || '').toLowerCase();
    const initial = available.has(requested) ? requested : 'progressive';

    const activate = (name, { focus = false, updateHistory = false } = {}) => {
      if (!available.has(name)) return;
      tabs.forEach((tab) => {
        const selected = tab.dataset.uspTab === name;
        tab.setAttribute('aria-selected', String(selected));
        tab.tabIndex = selected ? 0 : -1;
        tab.classList.toggle('is-active', selected);
        if (selected && focus) tab.focus();
      });
      panels.forEach((panel) => { panel.hidden = panel.dataset.uspPanel !== name; });
      if (updateHistory && scanId) {
        try { global.history?.replaceState?.({}, '', resultPath(scanId, name)); } catch { /* URL state is optional */ }
      }
    };

    tabs.forEach((tab, index) => {
      tab.addEventListener('click', () => activate(tab.dataset.uspTab, { updateHistory: true }));
      tab.addEventListener('keydown', (event) => {
        if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
        event.preventDefault();
        const nextIndex = event.key === 'Home'
          ? 0
          : event.key === 'End'
            ? tabs.length - 1
            : (index + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
        activate(tabs[nextIndex].dataset.uspTab, { focus: true, updateHistory: true });
      });
    });

    activate(initial);
  }

  function resetInvestigationView() {
    const shell = one('#emailInvestigationResult');
    const target = one('#phishingResult');
    if (shell) shell.hidden = true;
    if (target) target.replaceChildren();
    document.body?.classList?.remove('vt-email-has-result');
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
          <p class="email-result-kicker">Decision summary</p>
          <h2 id="emailResultTitle">${escapeHtml(STATE_LABELS[specialistState])}</h2>
          <p class="email-result-copy">${escapeHtml(stateCopy)}</p>
          <div class="email-signal-chips" aria-label="Key signals to review">
            ${signals.length ? signals.map((item) => `<span data-tone="${escapeHtml(item.tone)}">${escapeHtml(item.label)}</span>`).join('') : '<span data-tone="neutral">No high-priority deterministic signal was recorded; review the complete report for evidence coverage.</span>'}
          </div>
          <div class="email-result-actions">
            <button class="btn btn-primary email-pdf-view" type="button" data-view-email-pdf>View Complete Report</button>
            ${isResultPage() ? '' : '<button class="btn btn-secondary" type="button" data-new-investigation>New investigation</button>'}
            ${['manual_review', 'hold', 'quarantine', 'block'].includes(decision.recommendation) ? '<a class="btn btn-secondary" href="/cases">Open review queue</a>' : ''}
          </div>
        </div>
        <aside class="email-result-decision" aria-label="Gateway decision summary">
          <div class="email-risk-score"><span>${helpLabel('Risk score', HELP.risk)}</span><strong>${escapeHtml(risk)}</strong><small>Gateway correlation</small></div>
          <div class="email-next-action"><span>Recommended action</span><strong>${escapeHtml(recommendation)}</strong><small>${decision.degraded ? 'Some checks unavailable' : 'Available evidence basis'}</small></div>
          <div class="email-decision-metric"><span>Evidence</span><strong>${escapeHtml(titleCase(completeness.level || 'limited'))}</strong><small>${escapeHtml(evidenceStageName(evidence.input_mode))}</small></div>
          <div class="email-decision-metric"><span>AI signal</span><strong>${escapeHtml(modelLikelihood)}</strong><small>${model?.status === 'completed' ? 'Model likelihood' : 'Unavailable'}</small></div>
        </aside>
      </article>
      ${renderUspTabs({ evidence, infrastructure, infrastructureSummary, campaignMemory, passport, scanId: payload.scan_id })}`;

    shell.hidden = false;
    setStatus('');
    document.body?.classList?.add('vt-email-has-result');
    enhanceHelpTerms(target);
    state.lastScanId = payload.scan_id || null;
    bindUspTabs(target, payload.scan_id || null);

    one('[data-new-investigation]', target)?.addEventListener('click', () => {
      if (isResultPage()) openNewInvestigation();
      else resetInvestigationView();
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
    document.body?.classList?.add('vt-email-has-result');
    enhanceHelpTerms(target);
    one('[data-new-investigation]', target)?.addEventListener('click', () => {
      if (isResultPage()) openNewInvestigation();
      else resetInvestigationView();
    });
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
      button.innerHTML = '<span aria-hidden="true">i</span>';
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
    enhanceHelpTerms();
    document.addEventListener('click', () => closeHelp(true));
    document.addEventListener('keydown', (event) => { if (event.key === 'Escape') closeHelp(true); });
    global.addEventListener('resize', () => positionHelpTooltip(activeHelpButton));
    global.addEventListener('scroll', () => positionHelpTooltip(activeHelpButton), { passive: true });

    if (isResultPage()) {
      const savedScanId = String(queryParameter('scan_id') || '').trim();
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(savedScanId)) {
        const error = new Error('This result link is missing a valid investigation ID.');
        error.code = 'EMAIL_RESULT_SCAN_ID_INVALID';
        renderFailure(error);
        setStatus('Open an investigation from the dashboard or run a new email check.');
        return;
      }
      void loadSavedInvestigation(savedScanId);
      return;
    }

    const form = one('#phishingForm[data-email-workbench]');
    if (!form) return;
    bindTabs();

    const text = one('#phishingText');
    text?.addEventListener('input', () => {
      const output = one('#emailCharacterCount');
      if (output) output.textContent = `${text.value.length.toLocaleString()} / 12,000`;
    });

    const fileInput = one('#emailEmlFile');
    fileInput?.addEventListener('change', () => {
      try {
        chooseFile(fileInput.files?.[0]);
        setError('');
      } catch (error) {
        state.file = null;
        setError(error.message);
      }
    });

    const dropzone = one('.email-dropzone');
    ['dragenter', 'dragover'].forEach((name) => dropzone?.addEventListener(name, (event) => {
      event.preventDefault();
      dropzone.classList.add('is-dragging');
    }));
    ['dragleave', 'drop'].forEach((name) => dropzone?.addEventListener(name, (event) => {
      event.preventDefault();
      dropzone.classList.remove('is-dragging');
    }));
    dropzone?.addEventListener('drop', (event) => {
      try {
        chooseFile(event.dataTransfer?.files?.[0]);
        setError('');
      } catch (error) {
        state.file = null;
        setError(error.message);
      }
    });

    async function recoverInterruptedInvestigation(originalError) {
      const message = String(originalError?.message || '').toLowerCase();
      const isNetworkOrStreamFailure = !originalError?.status
        || Number(originalError?.status) >= 500
        || message.includes('network error')
        || message.includes('connection ended')
        || message.includes('failed to fetch')
        || message.includes('unreadable')
        || message.includes('timed out')
        || message.includes('timeout')
        || message.includes('load failed');
      if (!isNetworkOrStreamFailure) return false;

      const candidateScanId = state.lastScanId || analysisProgress.getLastScanId?.();

      // Strategy 1: If we have a scan ID, poll the evidence API
      if (candidateScanId && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(candidateScanId)) {
        setStatus('Finalizing forensic evidence from the server...');
        analysisProgress.update({ stage: 'decision', state: 'running', message: 'Retrieving final forensic investigation report from the server...' });
        for (let attempt = 0; attempt < 6; attempt += 1) {
          await new Promise((resolve) => global.setTimeout(resolve, 600 * (attempt + 1)));
          try {
            const response = await global.fetch(`/api/v2/phishing/evidence/${encodeURIComponent(candidateScanId)}`, {
              method: 'GET', credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json' },
            });
            if (response.ok) {
              const payload = await parseResponse(response);
              if (payload?.evidence && payload?.gateway_decision) {
                analysisProgress.finish();
                setStatus('Check complete. Opening the structured investigation result...');
                global.location.assign(resultPath(candidateScanId));
                return true;
              }
            }
          } catch { /* continue polling */ }
        }
      }

      // Strategy 2: Replay with the same Idempotency-Key (requesting application/json)
      if (state.lastIdempotencyKey && state.lastRequestBody) {
        setStatus('Re-synchronizing report with the server...');
        analysisProgress.update({ stage: 'decision', state: 'running', message: 'Re-synchronizing report with the server...' });
        const targetEndpoint = state.mode === 'eml'
          ? endpoint('emailAnalyzeEml', '/api/v1/gateway/email/analyze-eml')
          : endpoint('emailAnalyzeText', '/api/v1/gateway/email/analyze-text');
        const replayHeaders = {
          Accept: 'application/json',
          'Idempotency-Key': state.lastIdempotencyKey,
          ...(state.mode === 'eml'
            ? { 'Content-Type': 'message/rfc822', 'X-Retention-Policy': 'ephemeral_24h' }
            : { 'Content-Type': 'application/json' }),
          ...(state.parentScanId ? { 'X-VeriTrust-Parent-Scan-Id': state.parentScanId } : {}),
        };

        for (let attempt = 0; attempt < 4; attempt += 1) {
          await new Promise((resolve) => global.setTimeout(resolve, 800 * (attempt + 1)));
          try {
            const response = await global.fetch(targetEndpoint, {
              method: 'POST',
              credentials: 'same-origin',
              headers: replayHeaders,
              body: state.lastRequestBody,
            });
            if (response.ok) {
              const payload = await parseResponse(response);
              if (payload?.evidence && payload?.gateway_decision) {
                analysisProgress.finish();
                if (payload.scan_id) {
                  setStatus('Check complete. Opening the structured investigation result...');
                  global.location.assign(resultPath(payload.scan_id));
                  return true;
                }
                renderResult(payload);
                return true;
              }
              if (payload?.status === 'processing' && payload?.scan_id) {
                state.lastScanId = payload.scan_id;
                await loadSavedInvestigation(payload.scan_id);
                return true;
              }
            }
          } catch { /* retry */ }
        }
      }

      // Strategy 3: Check recent scans for the organization to recover recently saved scan
      try {
        const context = await global.VeriTrustSupabase?.getSessionContext?.();
        if (context?.organization?.id) {
          const recent = await global.VeriTrustSupabase.getRecentScans(context.organization.id, 3);
          const scans = Array.isArray(recent?.scans) ? recent.scans : (Array.isArray(recent) ? recent : []);
          const completedMatch = scans.find((s) => s?.id && (!candidateScanId || s.id === candidateScanId) && (s.status === 'completed' || s.risk_score !== null));
          if (completedMatch?.id) {
            analysisProgress.finish();
            setStatus('Check complete. Opening the structured investigation result...');
            global.location.assign(resultPath(completedMatch.id));
            return true;
          }
        }
      } catch { /* ignore */ }

      return false;
    }

    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (state.busy) return;
      setError('');
      setBusy(true);
      analysisProgress.begin();
      setStatus('Checking the message and available sender evidence...');
      try {
        const payload = await requestInvestigation();

        if (!payload.evidence && payload.status === 'processing' && payload.scan_id) {
          const shell = one('#emailInvestigationResult');
          const target = one('#phishingResult');
          if (shell && target) {
            target.innerHTML = `<h2 id="emailResultTitle">This scan is already processing</h2><p>A completed report is not available yet.</p><a class="btn btn-secondary" href="${resultPath(payload.scan_id)}">Follow this scan</a>`;
            shell.hidden = false;
          }
          analysisProgress.finish(null, { pending: true });
          setStatus('The server confirmed that the scan is still processing.');
          return;
        }

        if (!payload.evidence || !payload.gateway_decision) {
          throw new Error('The server response did not contain the email evidence and policy decision.');
        }

        analysisProgress.finish();
        if (payload.scan_id) {
          setStatus('Check complete. Opening the structured investigation result...');
          global.location.assign(resultPath(payload.scan_id));
          return;
        }

        // Defensive fallback for an invalid upstream response that omitted scan_id.
        renderResult(payload);
        setStatus('Check complete. Review the result and any missing evidence.');
      } catch (error) {
        const recovered = await recoverInterruptedInvestigation(error);
        if (!recovered) {
          analysisProgress.finish(error);
          setStatus('');
        }
      } finally {
        setBusy(false);
      }
    });

    const savedScanId = String(queryParameter('scan_id') || '').trim();
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(savedScanId)) {
      global.location.replace(resultPath(savedScanId, queryParameter('tab') || ''));
      return;
    }

    const requestedParent = String(queryParameter('parent_scan_id') || '').trim();
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(requestedParent)) {
      state.parentScanId = requestedParent;
      setStatus('Evidence upgrade linked to the previous investigation. Add the original .eml to create the next acquisition stage.');
    }

    const requestedMode = String(queryParameter('mode') || '').toLowerCase();
    setMode(requestedMode === 'eml' || state.parentScanId ? 'eml' : 'text');
  }

  document.addEventListener('DOMContentLoaded', init);
}(window));
