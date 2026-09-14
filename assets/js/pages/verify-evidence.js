(function evidenceVerifyPage(global) {
  'use strict';
  const MAX_BYTES = 1024 * 1024;
  const one = (selector) => document.querySelector(selector);
  const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));

  function setError(message) {
    const node = one('#verifyEvidenceError');
    if (!node) return;
    node.textContent = message || '';
    node.hidden = !message;
  }

  function normalizePackage(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('The evidence file must contain one JSON object.');
    if (input.passport && input.evidence) return { passport: input.passport, evidence: input.evidence };
    if (input.evidence && input.evidence.evidence_passport) return { passport: input.evidence.evidence_passport, evidence: input.evidence };
    if (input.evidence_passport) return { passport: input.evidence_passport, evidence: input };
    throw new Error('No VeriTrust Evidence Passport was found in this JSON package.');
  }

  async function verifyPackage(source) {
    const request = normalizePackage(source);
    const response = await global.fetch('/api/v2/phishing/verify-evidence', {
      method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(request),
    });
    let payload = null;
    try { payload = await response.json(); } catch { /* handled below */ }
    if (![200, 422].includes(response.status) || !payload?.verification) throw new Error(payload?.error?.message || 'The verification service returned an unreadable result.');
    return payload.verification;
  }

  function renderResult(result) {
    const root = one('#verifyEvidenceResult');
    if (!root) return;
    const checks = [
      ['Ed25519 signature', result.signature_valid, result.signature_valid ? 'The signed passport payload matches the embedded public key.' : 'The passport signature does not validate.'],
      ['Evidence SHA-256', result.evidence_hash_valid, result.evidence_hash_valid ? 'The evidence payload has not changed.' : 'The evidence payload differs from the signed hash.'],
      ['Manifest SHA-256', result.manifest_hash_valid, result.manifest_hash_valid ? 'The recorded evidence manifest is unchanged.' : 'The evidence manifest differs from the signed hash.'],
      ['Signing-key identity', result.key_id_valid, result.key_id_valid ? 'The public-key fingerprint matches the passport key ID.' : 'The public key does not match the recorded key ID.'],
      ['VeriTrust issuer trust', result.issuer_trusted, result.issuer_trusted ? 'The signing-key fingerprint is recognized by this VeriTrust deployment.' : "The signing key is not in this deployment's trusted issuer set."],
    ];
    root.dataset.state = result.valid ? 'valid' : 'invalid';
    root.innerHTML = `<div class="verify-result-header"><span>Verification result</span><h2>${result.valid ? 'Evidence integrity verified' : 'Verification failed'}</h2><p>${result.valid ? 'All cryptographic integrity checks passed for this package.' : 'One or more checks failed. Do not treat this package as an unchanged VeriTrust evidence record.'}</p></div>
      <div class="verify-checks">${checks.map(([label, pass, detail]) => `<div class="verify-check" data-pass="${Boolean(pass)}"><span>${pass ? '✓' : '!'}</span><div><strong>${escapeHtml(label)}</strong><small>${escapeHtml(detail)}</small></div></div>`).join('')}</div>
      <dl class="verify-meta"><div><dt>Passport ID</dt><dd>${escapeHtml(result.passport_id || 'Unavailable')}</dd></div><div><dt>Signing key</dt><dd>${escapeHtml(result.key_id || 'Unavailable')}</dd></div><div><dt>Algorithm</dt><dd>${escapeHtml(result.signature_algorithm || 'Ed25519')}</dd></div></dl>
      <p>This verifies integrity and recorded provenance only. It does not certify legal admissibility, attribution, or message safety.</p>`;
    root.hidden = false;
    root.focus();
  }

  async function parseFile(file) {
    if (!file) throw new Error('Choose a VeriTrust evidence JSON file.');
    if (!file.size) throw new Error('The selected file is empty.');
    if (file.size > MAX_BYTES) throw new Error('The verification package exceeds the 1 MiB limit.');
    const text = await file.text();
    try { return JSON.parse(text); } catch { throw new Error('The selected file is not valid JSON.'); }
  }

  async function loadScan(scanId) {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(scanId || '')) return;
    const submit = one('#verifyEvidenceSubmit');
    if (submit) { submit.disabled = true; submit.textContent = 'Loading evidence...'; }
    try {
      const response = await global.fetch(`/api/v2/phishing/evidence/${encodeURIComponent(scanId)}`, { credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json' } });
      const payload = await response.json().catch(() => null);
      if (!response.ok || !payload?.evidence) throw new Error(payload?.error?.message || 'Sign in to the workspace that owns this investigation, or upload an exported evidence file.');
      const textarea = one('#verifyEvidenceJson');
      if (textarea) textarea.value = JSON.stringify({ scan_id: scanId, evidence: payload.evidence }, null, 2);
      renderResult(await verifyPackage({ evidence: payload.evidence }));
    } catch (error) { setError(error.message); }
    finally { if (submit) { submit.disabled = false; submit.textContent = 'Verify integrity'; } }
  }

  function init() {
    const form = one('#verifyEvidenceForm');
    const fileInput = one('#verifyEvidenceFile');
    const textarea = one('#verifyEvidenceJson');
    fileInput?.addEventListener('change', async () => {
      setError('');
      try {
        const file = fileInput.files?.[0];
        const object = await parseFile(file);
        textarea.value = JSON.stringify(object, null, 2);
        const label = one('#verifyEvidenceFileLabel');
        if (label) label.textContent = `${file.name} · ${(file.size / 1024).toLocaleString(undefined, { maximumFractionDigits: 1 })} KiB`;
      } catch (error) { setError(error.message); }
    });
    form?.addEventListener('submit', async (event) => {
      event.preventDefault(); setError('');
      const button = one('#verifyEvidenceSubmit');
      try {
        const raw = textarea?.value.trim() || '';
        if (!raw) throw new Error('Choose or paste an exported VeriTrust evidence package.');
        if (new Blob([raw]).size > MAX_BYTES) throw new Error('The verification package exceeds the 1 MiB limit.');
        let object;
        try { object = JSON.parse(raw); } catch { throw new Error('The pasted package is not valid JSON.'); }
        if (button) { button.disabled = true; button.textContent = 'Verifying...'; }
        renderResult(await verifyPackage(object));
      } catch (error) { setError(error.message); }
      finally { if (button) { button.disabled = false; button.textContent = 'Verify integrity'; } }
    });
    one('#verifyEvidenceClear')?.addEventListener('click', () => {
      if (textarea) textarea.value = '';
      if (fileInput) fileInput.value = '';
      const result = one('#verifyEvidenceResult');
      if (result) result.hidden = true;
      setError('');
    });
    const scanId = new URLSearchParams(global.location.search).get('scan_id');
    if (scanId) void loadScan(scanId);
  }
  document.addEventListener('DOMContentLoaded', init);
}(window));
