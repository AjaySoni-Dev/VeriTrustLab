(function evidenceVerifyPage(global) {
  'use strict';
  const core = global.VeriTrustEvidencePassport;
  const MAX_BYTES = core?.MAX_EVIDENCE_PACKAGE_BYTES || (1024 * 1024);
  const one = (selector) => document.querySelector(selector);
  const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));
  let pendingFallbackRequest = null;

  function setError(message) {
    const node = one('#verifyEvidenceError');
    if (!node) return;
    node.textContent = message || '';
    node.hidden = !message;
  }

  function normalizePackage(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('The evidence file must contain one JSON object.');
    if (input.passport && input.evidence) return { passport: input.passport, evidence: input.evidence };
    if (input.passport && !input.evidence) return { passport: input.passport };
    if (input.evidence && input.evidence.evidence_passport) return { passport: input.evidence.evidence_passport, evidence: input.evidence };
    if (input.evidence_passport) return { passport: input.evidence_passport, evidence: input };
    if (input.passport_version && input.signature) return { passport: input };
    throw new Error('No VeriTrust Evidence Passport was found in this JSON.');
  }

  async function fetchTrustMetadata() {
    try {
      const response = await global.fetch('/api/v2/phishing/evidence-trust', {
        method: 'GET', credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json' },
      });
      const payload = await response.json().catch(() => null);
      if (!response.ok || payload?.schema_version !== 'veritrust-evidence-trust-1' || !Array.isArray(payload?.trusted_key_ids)) return null;
      return payload;
    } catch { return null; }
  }

  async function verifyPackageLocal(source) {
    if (!core?.verifyEvidencePackage) throw new Error('Local Evidence Passport verifier failed to load.');
    const request = normalizePackage(source);
    const trust = await fetchTrustMetadata();
    return core.verifyEvidencePackage(request, { trustedKeyIds: trust?.trusted_key_ids || null });
  }

  async function verifyPackageOnServer(request) {
    const response = await global.fetch('/api/v2/phishing/verify-evidence', {
      method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(request),
    });
    const payload = await response.json().catch(() => null);
    if (![200, 422].includes(response.status) || !payload?.verification) throw new Error(payload?.error?.message || 'The verification service returned an unreadable result.');
    return payload.verification;
  }

  function stateLabel(value, checked = true) {
    if (!checked) return 'NOT CHECKED';
    if (value === null || typeof value === 'undefined') return 'UNKNOWN';
    return value ? 'PASS' : 'FAIL';
  }

  function checkRow(label, value, checked, detail) {
    const state = stateLabel(value, checked);
    return `<div class="verify-check" data-state="${state.toLowerCase().replace(/ /g, '-')}"><span aria-hidden="true">${state === 'PASS' ? '✓' : state === 'FAIL' ? '!' : '–'}</span><div><strong>${escapeHtml(label)}</strong><small>${escapeHtml(detail)}</small></div><b>${escapeHtml(state)}</b></div>`;
  }

  function statusCopy(result) {
    const map = {
      VERIFIED: ['VERIFIED', 'The complete supplied package passed cryptographic checks and the signing key is in the current trusted VeriTrust issuer set.'],
      CRYPTOGRAPHICALLY_VALID_ISSUER_UNKNOWN: ['CRYPTOGRAPHICALLY VALID — ISSUER TRUST UNKNOWN', 'Cryptographic checks passed, but VeriTrust issuer trust could not be established from the public key registry.'],
      PASSPORT_SIGNATURE_VERIFIED_EVIDENCE_NOT_CHECKED: ['PASSPORT SIGNATURE VERIFIED — EVIDENCE NOT CHECKED', 'The Passport signature is valid and the issuer is trusted, but no external evidence payload was supplied for hash comparison.'],
      UNTRUSTED_ISSUER: ['UNTRUSTED ISSUER', 'The package is cryptographically self-consistent, but its signing key is not in the current trusted VeriTrust issuer set.'],
      VERIFICATION_FAILED: ['VERIFICATION FAILED', 'One or more structural, signature, Passport ID, or evidence-integrity checks failed.'],
    };
    return map[result.status] || ['VERIFICATION FAILED', 'The package could not be verified.'];
  }

  function metadataRow(label, value) {
    return `<div><dt>${escapeHtml(label)}</dt><dd><code>${escapeHtml(value ?? 'Unavailable')}</code></dd></div>`;
  }

  function renderResult(result, source = 'local') {
    const root = one('#verifyEvidenceResult');
    if (!root) return;
    const [title, explanation] = statusCopy(result);
    const structurePass = !result.errors?.some((code) => String(code).startsWith('PASSPORT_') || String(code).includes('DIGEST') || String(code).includes('PUBLIC_KEY') || String(code).startsWith('UNSUPPORTED_') || String(code).includes('SIGNATURE_ENCODING'));
    const issuerDetail = result.issuer_trusted === null
      ? 'Issuer registry was unavailable or not checked; mathematical validity is kept separate from issuer trust.'
      : result.issuer_trusted ? 'The key fingerprint is in the current trusted VeriTrust issuer registry.' : 'The signature may be valid, but this key is not currently trusted as a VeriTrust issuer.';
    const evidenceChecked = result.evidence_integrity_checked === true;
    const manifestChecked = result.manifest_integrity_checked === true;
    root.dataset.state = String(result.status || '').toLowerCase();
    root.innerHTML = `<div class="verify-result-header"><span>${source === 'server' ? 'SERVER FALLBACK RESULT' : 'LOCAL VERIFICATION RESULT'}</span><h2>${escapeHtml(title)}</h2><p>${escapeHtml(explanation)}</p></div>
      <div class="verify-scope"><strong>Scope</strong><span>${escapeHtml(result.verification_scope || 'UNKNOWN')}</span></div>
      <div class="verify-checks">
        ${checkRow('Package structure', structurePass, true, structurePass ? 'Required v1 fields and representations are structurally valid.' : 'The Passport contains malformed, unsupported, or inconsistent fields.')}
        ${checkRow('Ed25519 signature', result.signature_valid, true, result.signature_valid ? 'The signed Passport payload matches the embedded public key.' : 'The signature did not validate.')}
        ${checkRow('Signing-key fingerprint', result.key_id_valid, true, result.key_id_valid ? 'The public key derives to the recorded key ID.' : 'The embedded public key does not match the recorded key ID.')}
        ${checkRow('Passport ID', result.passport_id_valid, true, result.passport_id_valid ? 'The Passport ID matches the v1 ID derivation.' : 'The Passport ID is malformed or inconsistent with the signed hashes.')}
        ${checkRow('Trusted VeriTrust issuer', result.issuer_trusted, true, issuerDetail)}
        ${checkRow('Evidence SHA-256', result.evidence_hash_valid, evidenceChecked, evidenceChecked ? (result.evidence_hash_valid ? 'The supplied evidence matches the signed evidence digest.' : 'The supplied evidence differs from the signed evidence digest.') : 'No evidence payload was checked.')}
        ${checkRow('Manifest SHA-256', result.manifest_hash_valid, manifestChecked, manifestChecked ? (result.manifest_hash_valid ? 'The supplied manifest matches the signed manifest digest.' : 'The supplied manifest differs from the signed manifest digest.') : 'No evidence manifest was checked.')}
      </div>
      <dl class="verify-meta">${metadataRow('Passport ID', result.passport_id)}${metadataRow('Version', normalizePackageFromText()?.passport?.passport_version || 'veritrust-evidence-passport-1')}${metadataRow('Issued at', normalizePackageFromText()?.passport?.issued_at || 'Unavailable')}${metadataRow('Scan ID', normalizePackageFromText()?.passport?.scan_id || 'Unavailable')}${metadataRow('Artifact ID', normalizePackageFromText()?.passport?.artifact_id || 'Unavailable')}${metadataRow('Algorithm', result.signature_algorithm || 'Unavailable')}${metadataRow('Key fingerprint', result.key_id)}${metadataRow('Evidence SHA-256', normalizePackageFromText()?.passport?.evidence_sha256 || 'Unavailable')}${metadataRow('Manifest SHA-256', normalizePackageFromText()?.passport?.manifest_sha256 || 'Unavailable')}</dl>
      ${(result.errors?.length || result.warnings?.length) ? `<details class="verify-diagnostics"><summary>Verification diagnostics</summary>${result.errors?.length ? `<p><strong>Errors:</strong> ${escapeHtml(result.errors.join(', '))}</p>` : ''}${result.warnings?.length ? `<p><strong>Warnings:</strong> ${escapeHtml(result.warnings.join(', '))}</p>` : ''}</details>` : ''}
      <p class="verify-claim-boundary">This result verifies cryptographic integrity and recorded provenance only. It does not establish legal admissibility, sender/person identity, attacker identity, message safety, or correctness of the investigation verdict.</p>`;
    root.hidden = false;
    root.focus({ preventScroll: false });
  }

  function normalizePackageFromText() {
    try {
      const raw = one('#verifyEvidenceJson')?.value.trim();
      return raw ? normalizePackage(JSON.parse(raw)) : null;
    } catch { return null; }
  }

  async function parseFile(file) {
    if (!file) throw new Error('Choose a VeriTrust evidence JSON file.');
    if (!file.size) throw new Error('The selected file is empty.');
    if (file.size > MAX_BYTES) throw new Error('The verification package exceeds the 1 MiB limit.');
    const text = await file.text();
    try { return JSON.parse(text); } catch { throw new Error('The selected file is not valid JSON.'); }
  }

  async function verifyObject(object) {
    pendingFallbackRequest = null;
    const fallback = one('#verifyEvidenceFallback');
    if (fallback) fallback.hidden = true;
    try {
      const result = await verifyPackageLocal(object);
      renderResult(result, 'local');
    } catch (error) {
      if (['BROWSER_ED25519_UNAVAILABLE', 'BROWSER_CRYPTO_UNAVAILABLE'].includes(error?.code)) {
        pendingFallbackRequest = normalizePackage(object);
        if (fallback) fallback.hidden = false;
        setError('This browser cannot complete local Ed25519 verification. Evidence has not been uploaded. Use server fallback only if you consent to transmission.');
        return;
      }
      throw error;
    }
  }

  async function loadScan(scanId) {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(scanId || '')) return;
    const submit = one('#verifyEvidenceSubmit');
    if (submit) { submit.disabled = true; submit.textContent = 'Loading evidence…'; }
    try {
      const response = await global.fetch(`/api/v2/phishing/evidence/${encodeURIComponent(scanId)}`, { credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json' } });
      const payload = await response.json().catch(() => null);
      if (!response.ok || !payload?.evidence) throw new Error(payload?.error?.message || 'Sign in to the workspace that owns this investigation, or upload an exported evidence file.');
      if (!payload.evidence.evidence_passport) throw new Error('This historical report does not have an exact signed Evidence Passport package. Export it as reconstructed JSON (unsigned) instead.');
      const textarea = one('#verifyEvidenceJson');
      if (textarea) textarea.value = JSON.stringify({ scan_id: scanId, evidence: payload.evidence }, null, 2);
      await verifyObject({ evidence: payload.evidence });
    } catch (error) { setError(error.message); }
    finally { if (submit) { submit.disabled = false; submit.textContent = 'Verify locally'; } }
  }

  function setDroppedFile(file) {
    const textarea = one('#verifyEvidenceJson');
    return parseFile(file).then((object) => {
      if (textarea) textarea.value = JSON.stringify(object, null, 2);
      const label = one('#verifyEvidenceFileLabel');
      if (label) label.textContent = `${file.name} · ${(file.size / 1024).toLocaleString(undefined, { maximumFractionDigits: 1 })} KiB · ready for local verification`;
    });
  }

  function init() {
    const form = one('#verifyEvidenceForm');
    const fileInput = one('#verifyEvidenceFile');
    const textarea = one('#verifyEvidenceJson');
    const drop = one('#verifyEvidenceDrop');
    fileInput?.addEventListener('change', async () => { setError(''); try { await setDroppedFile(fileInput.files?.[0]); } catch (error) { setError(error.message); } });
    ['dragenter', 'dragover'].forEach((name) => drop?.addEventListener(name, (event) => { event.preventDefault(); drop.dataset.dragging = 'true'; }));
    ['dragleave', 'drop'].forEach((name) => drop?.addEventListener(name, (event) => { event.preventDefault(); delete drop.dataset.dragging; }));
    drop?.addEventListener('drop', async (event) => { setError(''); try { await setDroppedFile(event.dataTransfer?.files?.[0]); } catch (error) { setError(error.message); } });
    drop?.addEventListener('keydown', (event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); fileInput?.click(); } });

    form?.addEventListener('submit', async (event) => {
      event.preventDefault(); setError('');
      const button = one('#verifyEvidenceSubmit');
      try {
        const raw = textarea?.value.trim() || '';
        if (!raw) throw new Error('Choose, drop, or paste a VeriTrust Evidence Passport package.');
        if (new Blob([raw]).size > MAX_BYTES) throw new Error('The verification package exceeds the 1 MiB limit.');
        let object;
        try { object = JSON.parse(raw); } catch { throw new Error('The pasted package is not valid JSON.'); }
        if (button) { button.disabled = true; button.textContent = 'Verifying locally…'; }
        await verifyObject(object);
      } catch (error) { setError(error.message); }
      finally { if (button) { button.disabled = false; button.textContent = 'Verify locally'; } }
    });

    one('#verifyEvidenceServerFallback')?.addEventListener('click', async () => {
      if (!pendingFallbackRequest) return;
      const button = one('#verifyEvidenceServerFallback');
      setError('');
      try {
        if (button) { button.disabled = true; button.textContent = 'Sending for server verification…'; }
        const result = await verifyPackageOnServer(pendingFallbackRequest);
        renderResult(result, 'server');
      } catch (error) { setError(error.message); }
      finally { if (button) { button.disabled = false; button.textContent = 'Send evidence to server for verification'; } }
    });

    one('#verifyEvidenceClear')?.addEventListener('click', () => {
      if (textarea) textarea.value = '';
      if (fileInput) fileInput.value = '';
      const result = one('#verifyEvidenceResult');
      if (result) result.hidden = true;
      const fallback = one('#verifyEvidenceFallback');
      if (fallback) fallback.hidden = true;
      pendingFallbackRequest = null;
      setError('');
    });
    const scanId = new URLSearchParams(global.location.search).get('scan_id');
    if (scanId) void loadScan(scanId);
  }

  global.VeriTrustEvidenceVerifyPage = { fetchTrustMetadata, normalizePackage, verifyPackageLocal, verifyPackageOnServer };
  document.addEventListener('DOMContentLoaded', init);
}(window));
