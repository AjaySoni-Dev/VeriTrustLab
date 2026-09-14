document.addEventListener('DOMContentLoaded', async () => {
  const defaultStatusText = document.querySelector('[data-dashboard-status-text]')?.textContent?.trim()
    || 'Monitor scans, usage, and workspace activity.';
  const setText = (selector, value) => {
    const node = document.querySelector(selector);
    if (node) {
      node.classList.remove('dashboard-shimmer', 'dashboard-shimmer-text', 'dashboard-shimmer-number');
      node.removeAttribute('aria-hidden');
      node.style.removeProperty('--dashboard-shimmer-width');
      node.style.removeProperty('--dashboard-shimmer-height');
      node.textContent = value;
    }
  };

  const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  }[char]));

  const scanTypeLabel = (scanType) => {
    const normalized = String(scanType || '').toLowerCase();
    if (normalized === 'deepfake') return 'Deepfake Detection';
    if (normalized === 'phishing') return 'Email Investigation';
    if (normalized === 'link') return 'Link Intelligence';
    if (normalized === 'gateway') return 'Evidence Correlation';
    return scanType || 'Detection';
  };

  const titleCase = (value) => {
    const text = String(value || 'unknown').trim();
    if (!text) return 'Unknown';
    return text.charAt(0).toUpperCase() + text.slice(1).toLowerCase();
  };

  const verdictTone = (label) => {
    const normalized = String(label || '').toLowerCase();
    if (['phishing', 'deepfake', 'fake', 'suspicious', 'malicious', 'high', 'critical', 'block', 'quarantine'].includes(normalized)) {
      return 'danger';
    }
    if (['legitimate', 'real', 'safe', 'clean', 'low', 'allow'].includes(normalized)) {
      return 'safe';
    }
    return 'neutral';
  };

  let activeScanFilter = 'all';
  let cachedScans = [];
  let cachedApiKeys = [];
  let visibleScanLimit = 5;
  let currentProfile = {};
  let activeAvatarBlobUrl = null;
  const SCAN_BATCH_SIZE = 5;

  const riskBadgeClass = (level) => {
    const normalized = String(level || 'low').toLowerCase();
    return `risk-badge risk-badge-${['low', 'medium', 'high', 'critical'].includes(normalized) ? normalized : 'medium'}`;
  };

  const formatPercent = (value) => `${Math.round(Math.max(0, Math.min(1, Number(value) || 0)) * 100)}%`;

  const formatDateTime = (value) => {
    if (!value) return 'Never';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? 'Never' : date.toLocaleString();
  };

  const formatRole = (value) => titleCase(value || 'member');

  const safeNumber = (value, fallback = 0) => {
    const number = Number(value);
    return Number.isFinite(number) ? number : fallback;
  };

  const formatLimit = (used, limit) => {
    const safeLimit = safeNumber(limit);
    return `${safeNumber(used).toLocaleString()} / ${safeLimit.toLocaleString()}`;
  };

  const setMeter = (labelSelector, barSelector, used, limit) => {
    setText(labelSelector, formatLimit(used, limit));
    const bar = document.querySelector(barSelector);
    if (bar) {
      const percentage = safeNumber(limit) > 0 ? Math.min(100, Math.round((safeNumber(used) / safeNumber(limit)) * 100)) : 0;
      bar.style.width = `${percentage}%`;
      bar.classList.toggle('is-warning', percentage >= 70 && percentage < 90);
      bar.classList.toggle('is-danger', percentage >= 90);
    }
  };

  const renderBilling = (billing) => {
    const plan = billing?.plan || {};
    const subscription = billing?.subscription || {};
    const usage = billing?.usage || {};
    const limits = billing?.limits || {};
    const planCode = String(plan.code || 'workspace').toLowerCase();
    const status = subscription.status ? titleCase(subscription.status) : 'Active';
    const periodEnd = subscription.current_period_end ? formatDateTime(subscription.current_period_end) : 'Deployment policy';

    setText('[data-billing-plan]', plan.name || titleCase(planCode));
    setText('[data-billing-status]', status);
    setText('[data-billing-renewal]', periodEnd);
    const gatewayEnabled = billing?.features?.gateway_enabled !== false;
    setText('[data-billing-summary]', `${plan.name || titleCase(planCode)} workspace limits are enforced by the deployed policy. API access is ${billing?.features?.allow_api_access === false ? 'not enabled' : 'enabled'}; Evidence Correlation is ${gatewayEnabled ? 'enabled' : 'disabled'}.`);
    setMeter('[data-billing-web-label]', '[data-billing-web-bar]', usage.web_used || 0, limits.monthly_web_scan_limit || 100);
    setMeter('[data-billing-api-label]', '[data-billing-api-bar]', usage.api_used || 0, limits.monthly_api_limit || 100);
    setMeter('[data-billing-keys-label]', '[data-billing-keys-bar]', usage.api_keys_used || 0, limits.max_api_keys || 1);
    setMeter('[data-billing-gateway-daily-label]', '[data-billing-gateway-daily-bar]', usage.gateway_used_today || 0, limits.daily_gateway_scan_limit || 0);
    setMeter('[data-billing-gateway-monthly-label]', '[data-billing-gateway-monthly-bar]', usage.gateway_used_month || 0, limits.monthly_gateway_scan_limit || 0);
    setText('[data-billing-gateway-artifacts]', String(limits.max_gateway_artifacts ?? '—'));
    setText('[data-billing-gateway-parallel]', String(limits.max_gateway_parallel_models ?? '—'));
    setText('[data-billing-gateway-retention]', limits.gateway_max_raw_retention_hours == null ? '—' : `${limits.gateway_max_raw_retention_hours}h`);
    setText('[data-usage-gateway-today]', gatewayEnabled ? formatLimit(usage.gateway_used_today || 0, limits.daily_gateway_scan_limit || 0) : 'Disabled');
    setText('[data-usage-gateway-month]', gatewayEnabled ? formatLimit(usage.gateway_used_month || 0, limits.monthly_gateway_scan_limit || 0) : 'Disabled');
  };

  const scanResult = (scan) => {
    const result = scan.scan_results;
    if (Array.isArray(result)) return result[0] || {};
    return result || {};
  };

  const scanInput = (scan) => {
    const input = scan.scan_inputs;
    if (Array.isArray(input)) return input[0] || {};
    return input || {};
  };

  const modelRuns = (scan) => {
    if (Array.isArray(scan.scan_model_runs)) return scan.scan_model_runs;
    return [];
  };

  const modelLabel = (scan) => {
    const completed = modelRuns(scan).find((run) => run.status === 'completed') || null;
    return completed?.model_key || scan.selected_model_key || scan.metadata?.selected_model_key || 'unknown';
  };

  const modelDisplayName = (key) => {
    const normalized = String(key || '').toLowerCase();
    if (normalized === 'swift') return 'VeriTrust Swift';
    if (normalized === 'sentinel') return 'VeriTrust Sentinel';
    if (normalized === 'pixel') return 'VeriTrust Pixel';
    if (normalized === 'prism') return 'VeriTrust Prism';
    if (normalized === 'mailguard') return 'VeriTrust MailGuard';
    if (normalized === 'cortex') return 'VeriTrust Cortex';
    if (normalized === 'gateway') return 'VeriTrust Evidence Correlation';
    return titleCase(key || 'unknown');
  };

  const gatewaySignalType = (row = {}) => {
    const key = String(row.signal_type || row.kind || row.model_key || '').toLowerCase();
    if (/(?:swift|link|url)/u.test(key)) return 'link';
    if (/(?:pixel|prism|deepfake|image|media)/u.test(key)) return 'deepfake';
    if (/(?:mailguard|cortex|phishing|message|text)/u.test(key)) return 'phishing';
    return 'supporting';
  };

  const gatewaySignalLabel = (type) => ({
    phishing: 'Email threat analysis',
    link: 'Link analysis',
    deepfake: 'Deepfake analysis',
    supporting: 'Supporting analysis',
  }[type] || 'Supporting analysis');

  const indicatorText = (item) => {
    if (typeof item === 'string') return item;
    return item?.title || item?.description || item?.label || item?.code || '';
  };

  const renderGatewaySignals = (result) => {
    const rows = Array.isArray(result?.raw_scores) ? result.raw_scores : [];
    if (!rows.length) return '';
    return `
      <section class="scan-gateway-signals" aria-label="Evidence correlation signal results">
        <h4>Signal results</h4>
        <div class="scan-gateway-signal-grid">
          ${rows.map((row) => {
    const type = gatewaySignalType(row);
    const score = row.score === null || row.score === undefined || !Number.isFinite(Number(row.score))
      ? 'Score unavailable'
      : `Score ${formatPercent(Number(row.score))}`;
    const signalIndicators = [
      ...(Array.isArray(row.reason_codes) ? row.reason_codes : []),
      ...(Array.isArray(row.indicators) ? row.indicators : []),
    ].map(indicatorText).filter(Boolean);
    return `
            <article class="scan-gateway-signal" data-signal="${escapeHtml(type)}">
              <div class="scan-gateway-signal-head">
                <strong>${escapeHtml(gatewaySignalLabel(type))}</strong>
                <span>${escapeHtml(titleCase(row.status || 'unknown'))}</span>
              </div>
              <p>${escapeHtml(modelDisplayName(row.model_key))} &middot; ${escapeHtml(titleCase(row.verdict || 'unknown'))} &middot; ${escapeHtml(score)}</p>
              ${signalIndicators.length ? `<div class="scan-detail-signals">${signalIndicators.map((item) => `<span>${escapeHtml(String(item).replaceAll('_', ' '))}</span>`).join('')}</div>` : ''}
            </article>
          `;
  }).join('')}
        </div>
      </section>
    `;
  };

  const fallbackUsed = (scan) => {
    const completed = modelRuns(scan).filter((run) => run.status === 'completed');
    return completed.length > 0 && completed[0].model_key !== scan.selected_model_key;
  };

  const reportFromScan = (scan) => {
    const resultRow = scanResult(scan);
    const risk = titleCase(resultRow.risk_level || scan.risk_level || 'low');
    const confidence = Number(resultRow.confidence || scan.confidence || 0);
    const primaryScore = Number(resultRow.primary_score || 0);
    const secondaryScore = Number(resultRow.secondary_score || 0);
    const type = scan.scan_type || 'scan';
    const isDeepfake = type === 'deepfake';
    const isLink = type === 'link';
    const isGateway = type === 'gateway';
    const gatewayMetadata = scan.metadata?.gateway || {};
    const inputRow = scanInput(scan);
    const inputMetadata = inputRow.metadata || {};
    const extractedUrl = inputMetadata.normalized_url || inputRow.text_preview || '';
    let extracted = undefined;
    if (isLink && extractedUrl) {
      try {
        const parsedUrl = new URL(extractedUrl);
        extracted = {
          input_url: extractedUrl,
          normalized_url: parsedUrl.href,
          scheme: parsedUrl.protocol.replace(':', ''),
          hostname: parsedUrl.hostname,
          domain: parsedUrl.hostname.replace(/^www\./, ''),
          path: parsedUrl.pathname || '/',
          query_present: Boolean(parsedUrl.search),
          urls_found: inputMetadata.urls_found || [parsedUrl.href],
        };
      } catch {
        extracted = {
          input_url: extractedUrl,
          normalized_url: extractedUrl,
          urls_found: inputMetadata.urls_found || [extractedUrl],
        };
      }
    }
    return {
      title: isGateway
        ? 'VeriTrust Evidence Correlation Report'
        : isLink
          ? 'VeriTrust Link Intelligence Report'
          : 'VeriTrust Scan Report',
      scan_id: scan.id,
      scan_type: type,
      created_at: scan.created_at,
      model: {
        key: modelLabel(scan),
        name: modelDisplayName(modelLabel(scan)),
        fallback_used: fallbackUsed(scan),
      },
      result: {
        label: resultRow.label || scan.final_label || scan.status || 'Unknown',
        confidence,
        risk_level: risk,
        confidence_band: confidence >= 0.85 ? 'Strong' : confidence >= 0.65 ? 'Moderate' : 'Weak',
        summary: resultRow.explanation || 'Saved scan result.',
        indicators: resultRow.indicators || [],
        fake_score: isDeepfake ? primaryScore : undefined,
        real_score: isDeepfake ? secondaryScore : undefined,
        phishing_score: !isDeepfake && !isLink && !isGateway ? primaryScore : undefined,
        legitimate_score: !isDeepfake && !isLink && !isGateway ? secondaryScore : undefined,
        link_score: isLink ? primaryScore : undefined,
        model_score: isLink ? secondaryScore : undefined,
        gateway_risk_score: isGateway ? primaryScore : undefined,
        recommendation: isGateway ? gatewayMetadata.recommendation : undefined,
        reason_codes: isGateway ? gatewayMetadata.reason_codes || [] : undefined,
        degraded: isGateway ? Boolean(gatewayMetadata.degraded) : undefined,
        extracted,
        disclaimer: isDeepfake
          ? 'AI-assisted result. This is not legal, forensic, or final proof.'
          : isGateway
            ? 'Policy-correlated evidence result. Verify important findings with source context and human review.'
          : isLink
            ? 'AI-assisted result. Verify suspicious links through official channels before opening or submitting information.'
            : 'AI-assisted result. Verify suspicious messages through official channels before taking action.',
      },
      scores: resultRow.raw_scores || [],
      report: {
        title: isGateway ? 'VeriTrust Evidence Correlation Report' : 'VeriTrust Scan Report',
        disclaimer: 'AI-assisted result. Manual review is recommended.',
        exportable: true,
      },
    };
  };

  const downloadReport = (scan) => {
    const report = reportFromScan(scan);
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `veritrust-${report.scan_type}-report-${String(report.scan_id).slice(0, 8)}.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  const printReport = async (scan) => {
    const report = reportFromScan(scan);
    if (window.VeriTrustReporting?.printReport) {
      await window.VeriTrustReporting.printReport(report);
      return;
    }
    window.print();
  };

  const filteredScans = () => cachedScans.filter((scan) => {
    if (activeScanFilter === 'deepfake') return scan.scan_type === 'deepfake';
    if (activeScanFilter === 'phishing') return scan.scan_type === 'phishing';
    if (activeScanFilter === 'link') return scan.scan_type === 'link';
    if (activeScanFilter === 'gateway') return scan.scan_type === 'gateway';
    if (activeScanFilter === 'high') return ['high', 'critical'].includes(String(scan.risk_level || scanResult(scan).risk_level || '').toLowerCase());
    return true;
  });

  const renderFilters = () => {
    const filters = document.querySelector('[data-scan-filters]');
    if (!filters) return;
    const options = [
      ['all', 'All'],
      ...(window.VeriTrustModules?.isEnabled('deepfake') !== false ? [['deepfake', 'Deepfake']] : []),
      ...(window.VeriTrustModules?.isEnabled('phishing') !== false ? [['phishing', 'Email']] : []),
      ...(window.VeriTrustModules?.isEnabled('link') !== false ? [['link', 'Link']] : []),
      ...(window.VeriTrustModules?.isEnabled('gateway') !== false ? [['gateway', 'Gateway']] : []),
      ['high', 'High Risk'],
    ];
    filters.innerHTML = options.map(([value, label]) => `
      <button class="${activeScanFilter === value ? 'active' : ''}" type="button" data-scan-filter="${value}">${label}</button>
    `).join('');
    filters.querySelectorAll('[data-scan-filter]').forEach((button) => {
      button.addEventListener('click', () => {
        activeScanFilter = button.dataset.scanFilter || 'all';
        visibleScanLimit = SCAN_BATCH_SIZE;
        renderScans(cachedScans);
      });
    });
  };

  const summarizeScans = (scans) => {
    const total = scans.length;
    const highRisk = scans.filter((scan) => ['high', 'critical'].includes(String(scan.risk_level || scanResult(scan).risk_level || '').toLowerCase())).length;
    const deepfake = scans.filter((scan) => scan.scan_type === 'deepfake').length;
    const link = scans.filter((scan) => scan.scan_type === 'link').length;
    const phishing = scans.filter((scan) => scan.scan_type === 'phishing').length;
    const gateway = scans.filter((scan) => scan.scan_type === 'gateway').length;
    return { deepfake, gateway, highRisk, link, phishing, total };
  };

  const usageFromKeys = (keys) => {
    const active = keys.filter((key) => key.status === 'active');
    const usage = active.reduce((acc, key) => {
      const item = key.usage || {};
      acc.used += Number(item.used_today || 0);
      acc.limit += Number(item.limit_daily || key.usage_limit_daily || 0);
      acc.remaining += Number(item.remaining_today || 0);
      if (key.last_used_at && (!acc.lastUsed || new Date(key.last_used_at) > new Date(acc.lastUsed))) {
        acc.lastUsed = key.last_used_at;
      }
      return acc;
    }, { lastUsed: null, limit: 0, remaining: 0, used: 0 });
    return usage;
  };

  const setApiUsage = (keys) => {
    const usage = usageFromKeys(keys || []);
    setText('[data-api-usage-used]', String(usage.used));
    setText('[data-api-usage-limit]', String(usage.limit || 100));
    setText('[data-api-usage-remaining]', String(usage.remaining || Math.max(0, (usage.limit || 100) - usage.used)));
    setText('[data-api-last-used]', formatDateTime(usage.lastUsed));
    setText('[data-usage-api-today]', String(usage.used));
    setText('[data-usage-api-remaining]', String(usage.remaining || Math.max(0, (usage.limit || 100) - usage.used)));
  };

  const apiKeyStatusClass = (status) => String(status || '').toLowerCase() === 'active' ? 'status-pill ready' : 'status-pill warn';

  const renderApiKeys = (keys) => {
    cachedApiKeys = keys || [];
    setText('[data-usage-api-keys]', String(cachedApiKeys.filter((key) => key.status === 'active').length));
    setApiUsage(cachedApiKeys);
    const wrap = document.querySelector('[data-api-keys-list]');
    if (!wrap) return;

    if (!cachedApiKeys.length) {
      wrap.innerHTML = `
        <div class="empty-state-table">
          <strong>No API keys yet</strong>
          <p>Create a key to call VeriTrust from your own backend or notebooks.</p>
        </div>
      `;
      return;
    }

    wrap.innerHTML = `
      <div class="api-key-list">
        ${cachedApiKeys.map((key) => `
          <div class="api-key-row">
            <div class="api-key-main">
              <small>Key name</small>
              <strong>${escapeHtml(key.name || 'API Key')}</strong>
              <code>${escapeHtml(key.masked_key || key.key_prefix || '')}</code>
            </div>
            <div class="api-key-meta">
              <span><small>Created</small><strong>${escapeHtml(formatDateTime(key.created_at))}</strong></span>
              <span><small>Last used</small><strong>${escapeHtml(formatDateTime(key.last_used_at))}</strong></span>
              <span><small>Usage today</small><strong>${escapeHtml((key.usage?.used_today || 0))} of ${escapeHtml((key.usage?.limit_daily || key.usage_limit_daily || 100))} used</strong></span>
            </div>
            <div class="api-key-controls">
              <span class="${apiKeyStatusClass(key.status)} api-key-status">${escapeHtml(titleCase(key.status || 'active'))}</span>
              ${key.status === 'active' ? `<button class="btn btn-secondary" type="button" data-revoke-api-key="${escapeHtml(key.id)}">Revoke</button>` : ''}
            </div>
          </div>
        `).join('')}
      </div>
    `;

    wrap.querySelectorAll('[data-revoke-api-key]').forEach((button) => {
      button.addEventListener('click', async () => {
        const id = button.dataset.revokeApiKey;
        if (!id) return;
        button.disabled = true;
        button.textContent = 'Revoking...';
        try {
          await window.VeriTrustSupabase.callAppApi(`/api/api-keys?id=${encodeURIComponent(id)}`, {
            method: 'DELETE',
            cache: 'no-store',
          });
          await loadApiKeys();
        } catch (error) {
          button.disabled = false;
          button.textContent = 'Revoke';
          setText('[data-dashboard-status-text]', error.message || 'Unable to revoke API key.');
        }
      });
    });
  };

  async function loadApiKeys() {
    if (!window.VeriTrustSupabase?.callAppApi) return;
    const payload = await window.VeriTrustSupabase.callAppApi('/api/api-keys', { cache: 'no-store' });
    renderApiKeys(payload.api_keys || []);
  }

  const bindApiKeyForm = () => {
    const form = document.querySelector('[data-api-key-form]');
    if (!form || form.dataset.bound) return;
    form.dataset.bound = 'true';
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const button = form.querySelector('button[type="submit"]');
      const created = document.querySelector('[data-api-key-created]');
      const formData = new FormData(form);
      const name = String(formData.get('name') || '').trim() || 'Jupyter Test';
      if (button) {
        button.disabled = true;
        button.textContent = 'Creating...';
      }
      try {
        const payload = await window.VeriTrustSupabase.callAppApi('/api/api-keys', {
          method: 'POST',
          cache: 'no-store',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name }),
        });
        const key = payload.api_key || {};
        if (created) {
          created.hidden = false;
          created.innerHTML = `
            <strong>Copy this key now. It will not be shown again.</strong>
            <div class="api-key-secret">
              <code>${escapeHtml(key.key || '')}</code>
              <button class="btn btn-secondary" type="button" data-copy-created-key>Copy</button>
            </div>
          `;
          created.querySelector('[data-copy-created-key]')?.addEventListener('click', async () => {
            await navigator.clipboard?.writeText(key.key || '');
          });
        }
        form.reset();
        await loadApiKeys();
      } catch (error) {
        setText('[data-dashboard-status-text]', error.message || 'Unable to create API key.');
      } finally {
        if (button) {
          button.disabled = false;
          button.textContent = 'Create API Key';
        }
      }
    });
  };

  const setSessionPill = (signedIn) => {
    const pill = document.querySelector('[data-session-pill]');
    const dot = pill?.querySelector('.status-dot');
    setText('[data-session-label]', signedIn ? 'Signed in' : 'Signed out');
    if (pill) pill.classList.toggle('warn', !signedIn);
    if (dot) dot.classList.toggle('pending', !signedIn);
  };

  const setPrimaryAction = (signedIn) => {
    const action = document.querySelector('[data-account-primary-action]');
    if (!action) return;
    action.textContent = signedIn ? 'New Scan' : 'Sign In';
    action.href = signedIn ? 'detection.html' : 'auth.html';
  };

  const initials = (value) => String(value || 'VT')
    .trim().split(/\s+/).slice(0, 2).map((part) => part.charAt(0)).join('').toUpperCase() || 'VT';

  const renderAccountAvatar = async (profile) => {
    const avatar = document.querySelector('[data-account-avatar]');
    if (!avatar) return;
    avatar.textContent = initials(profile.full_name || profile.username);
    avatar.classList.remove('has-image');
    avatar.style.removeProperty('background-image');
    if (activeAvatarBlobUrl) {
      URL.revokeObjectURL(activeAvatarBlobUrl);
      activeAvatarBlobUrl = null;
    }
    if (!profile.avatar_url || !window.VeriTrustSupabase?.getAvatarBlobUrl) return;
    activeAvatarBlobUrl = await window.VeriTrustSupabase.getAvatarBlobUrl(profile.avatar_url);
    if (activeAvatarBlobUrl) {
      avatar.style.backgroundImage = `url("${activeAvatarBlobUrl}")`;
      avatar.classList.add('has-image');
    }
  };

  const bindProfileForm = () => {
    const edit = document.querySelector('[data-profile-edit]');
    const form = document.querySelector('[data-profile-form]');
    const cancel = document.querySelector('[data-profile-cancel]');
    if (!edit || !form || form.dataset.bound) return;
    form.dataset.bound = 'true';

    const close = () => { form.hidden = true; };
    edit.addEventListener('click', () => {
      form.elements.full_name.value = currentProfile.full_name || '';
      form.elements.username.value = currentProfile.username || '';
      form.hidden = false;
      form.elements.full_name.focus();
    });
    cancel?.addEventListener('click', close);
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const submit = form.querySelector('button[type="submit"]');
      submit.disabled = true;
      submit.textContent = 'Saving...';
      try {
        const avatarFile = form.elements.avatar.files?.[0] || null;
        const patch = {
          full_name: form.elements.full_name.value.trim(),
          username: form.elements.username.value.trim().toLowerCase() || null,
        };
        if (avatarFile) patch.avatar_url = await window.VeriTrustSupabase.uploadAvatar(avatarFile);
        currentProfile = await window.VeriTrustSupabase.updateProfile(patch);
        setText('[data-account-name]', currentProfile.full_name || currentProfile.username || 'Signed-in user');
        await renderAccountAvatar(currentProfile);
        form.reset();
        close();
        setText('[data-dashboard-status-text]', 'Profile updated successfully.');
      } catch (error) {
        setText('[data-dashboard-status-text]', error.message || 'Unable to update the profile.');
      } finally {
        submit.disabled = false;
        submit.textContent = 'Save Profile';
      }
    });
  };

  const renderScansLoading = () => {
    const table = document.querySelector('[data-recent-scans]');
    if (!table) return;
    table.setAttribute('aria-busy', 'true');
    table.innerHTML = `
      <div class="dashboard-loading-state" aria-hidden="true">
        <span></span>
        <span></span>
      </div>
    `;
  };

  const setDashboardLoading = (loading) => {
    document.body.classList.toggle('dashboard-is-loading', loading);
    document.querySelector('.dashboard-shell')?.setAttribute('aria-busy', String(loading));
    if (!loading) {
      document.querySelector('[data-recent-scans]')?.removeAttribute('aria-busy');
      return;
    }
    renderScansLoading();
  };

  const setSignedOut = () => {
    setDashboardLoading(false);
    setSessionPill(false);
    setPrimaryAction(false);
    setText('[data-dashboard-status-title]', 'Sign in to continue');
    setText('[data-dashboard-status-text]', defaultStatusText);
    setText('[data-account-name]', 'No active session');
    setText('[data-account-detail]', 'Sign in to view workspace activity.');
    setText('[data-workspace-name]', 'Not connected');
    setText('[data-workspace-role]', 'Sign in');
    setText('[data-workspace-members]', '0');
    setText('[data-usage-images]', '0');
    setText('[data-usage-messages]', '0');
    setText('[data-usage-links]', '0');
    setText('[data-usage-total-scans]', '0');
    setText('[data-usage-high-risk]', '0');
    setText('[data-usage-api-today]', '0');
    setText('[data-usage-api-remaining]', '100');
    setText('[data-api-usage-used]', '0');
    setText('[data-api-usage-limit]', '100');
    setText('[data-api-usage-remaining]', '100');
    setText('[data-api-last-used]', 'Never');
    renderBilling({
      plan: { code: 'free', name: 'Free' },
      subscription: null,
      usage: { web_used: 0, api_used: 0, api_keys_used: 0 },
      limits: { monthly_web_scan_limit: 100, monthly_api_limit: 100, max_api_keys: 1 },
      features: { allow_api_access: true },
    });
    renderApiKeys([]);
    const table = document.querySelector('[data-recent-scans]');
    if (table) {
      table.innerHTML = `
        <div class="empty-state-table">
          <div class="empty-state-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M12 9v4M12 17h.01"/><circle cx="12" cy="12" r="10"/>
            </svg>
          </div>
          <strong>Sign in to load scans</strong>
          <p>Saved reviews will appear here after you sign in.</p>
        </div>
      `;
    }
  };

  function renderScans(scans) {
    const table = document.querySelector('[data-recent-scans]');
    if (!table) return;
    table.removeAttribute('aria-busy');
    const nextScans = window.VeriTrustModules?.filterRecords(scans || []) || scans || [];
    if (nextScans !== cachedScans) visibleScanLimit = SCAN_BATCH_SIZE;
    cachedScans = nextScans;
    renderFilters();
    const matchingScans = filteredScans();
    const visibleScans = matchingScans.slice(0, visibleScanLimit);
    const hasMoreScans = visibleScans.length < matchingScans.length;

    if (!cachedScans.length) {
      table.innerHTML = `
        <div class="empty-state-table">
          <div class="empty-state-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M9 11l3 3L22 4"/>
              <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>
            </svg>
          </div>
          <strong>No scans yet.</strong>
          <p>Run your first scan to see reports here.</p>
        </div>
      `;
      return;
    }

    if (!matchingScans.length) {
      table.innerHTML = `
        <div class="empty-state-table">
          <div class="empty-state-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M4 6h16M4 12h16M4 18h16"/>
            </svg>
          </div>
          <strong>No scans match this filter.</strong>
          <p>Change the filter or run another scan to see more reports.</p>
        </div>
      `;
      return;
    }

    table.innerHTML = `
      <div class="scan-table" role="table" aria-label="Recent scans">
        <div class="scan-row scan-head" role="row">
          <span>Type</span><span>Verdict</span><span>Risk</span><span>Confidence</span><span>Model</span><span>Created</span><span>Actions</span>
        </div>
        ${visibleScans.map((scan, index) => {
    const result = scanResult(scan);
    const label = result.label || scan.final_label || scan.status;
    const risk = titleCase(result.risk_level || scan.risk_level || 'unknown');
    const confidence = Number(result.confidence || scan.confidence || 0);
    const indicators = Array.isArray(result.indicators) ? result.indicators : [];
    const gateway = scan.scan_type === 'gateway' ? (scan.metadata?.gateway || {}) : null;
    const detailIdentity = gateway
      ? `Gateway ID: ${escapeHtml(gateway.display_id || scan.id)} &middot; Source: ${escapeHtml(titleCase(gateway.source || scan.source || 'api'))} &middot; Scan ID: ${escapeHtml(scan.id)}`
      : `Scan ID: ${escapeHtml(scan.id)}`;
    return `
          <div class="scan-row scan-row-rich" role="row">
            <span data-label="Type">${escapeHtml(scanTypeLabel(scan.scan_type))}</span>
            <span data-label="Verdict" class="scan-verdict scan-verdict-${verdictTone(label)}">${escapeHtml(titleCase(label))}</span>
            <span data-label="Risk"><strong class="${riskBadgeClass(risk)}">${escapeHtml(risk)}</strong></span>
            <span data-label="Confidence">${escapeHtml(formatPercent(confidence))}</span>
            <span data-label="Model">${escapeHtml(modelDisplayName(modelLabel(scan)))}${fallbackUsed(scan) ? ' (fallback)' : ''}</span>
            <span data-label="Created">${escapeHtml(new Date(scan.created_at).toLocaleDateString())}</span>
            <span class="scan-actions" data-label="Reports">
              <button type="button" data-scan-action="download" data-scan-index="${index}">JSON Report</button>
              <button type="button" data-scan-action="print" data-scan-index="${index}">Save PDF Report</button>
            </span>
          </div>
          <details class="scan-detail-row">
            <summary>${gateway ? 'View full details' : 'View details'}</summary>
            <p>${escapeHtml(result.explanation || 'Saved scan result.')}</p>
            ${gateway
    ? renderGatewaySignals(result)
    : indicators.length
      ? `<div class="scan-detail-signals">${indicators.slice(0, 5).map((item) => `<span>${escapeHtml(indicatorText(item))}</span>`).join('')}</div>`
      : ''}
            <p class="scan-detail-id">${detailIdentity}</p>
          </details>
        `;
  }).join('')}
      </div>
      ${matchingScans.length > SCAN_BATCH_SIZE ? `
        <div class="scan-pagination">
          <p>Showing ${visibleScans.length} of ${matchingScans.length} scans</p>
          ${hasMoreScans ? '<button class="btn btn-secondary" type="button" data-load-more-scans>Load more</button>' : ''}
        </div>
      ` : ''}
    `;

    table.querySelectorAll('[data-scan-action]').forEach((button) => {
      button.addEventListener('click', () => {
        const scan = visibleScans[Number(button.dataset.scanIndex || 0)];
        if (!scan) return;
        if (button.dataset.scanAction === 'download') downloadReport(scan);
        if (button.dataset.scanAction === 'print') printReport(scan);
      });
    });

    table.querySelector('[data-load-more-scans]')?.addEventListener('click', () => {
      visibleScanLimit += SCAN_BATCH_SIZE;
      renderScans(cachedScans);
    });
  }

  setDashboardLoading(true);
  bindApiKeyForm();
  bindProfileForm();

  try {
    if (!window.VeriTrustSupabase?.isConfigured()) {
      setSignedOut();
      return;
    }

    const session = await window.VeriTrustSupabase.getSession();
    if (!session) {
      setSignedOut();
      return;
    }

    const context = await window.VeriTrustSupabase.getDashboard({ limit: 100 });
    const org = context.organization;
    const profile = context.profile || {};
    currentProfile = profile;
    const user = context.user || {};
    const stats = context.stats || {};
    const billing = context.billing || {};
    const usage = stats.usage_today || {};
    const monthlyWebUsage = billing.usage?.web_by_type || {};
    const scans = window.VeriTrustModules?.filterRecords(context.scans || []) || context.scans || [];
    const apiKeys = context.api_keys || [];

    setSessionPill(true);
    setPrimaryAction(true);
    setText('[data-dashboard-status-title]', org?.name || 'Workspace');
    setText('[data-dashboard-status-text]', defaultStatusText);
    setText('[data-account-name]', profile.full_name || user.email || 'Signed-in user');
    const profileEdit = document.querySelector('[data-profile-edit]');
    if (profileEdit) profileEdit.hidden = false;
    setText('[data-account-detail]', `${user.email || 'Authenticated'} - ${formatRole(context.role)} in ${org?.name || 'workspace'}`);
    setText('[data-workspace-name]', org?.name || 'Workspace');
    setText('[data-workspace-role]', formatRole(context.role));
    setText('[data-workspace-members]', stats.member_count == null ? 'Available' : String(stats.member_count));
    setText('[data-usage-total-scans]', String(billing.usage?.web_used || 0));
    setText('[data-usage-images]', String(monthlyWebUsage.phishing || 0));
    setText('[data-usage-messages]', String(monthlyWebUsage.phishing || 0));
    setText('[data-usage-links]', String(monthlyWebUsage.link || 0));
    setText('[data-usage-api-keys]', stats.api_key_count == null ? 'N/A' : String(stats.api_key_count));
    setText('[data-usage-api-today]', String(usage.api_count || 0));
    renderBilling(billing);
    await renderAccountAvatar(profile);

    renderApiKeys(apiKeys);
    if (org?.id) {
      const summary = summarizeScans(scans);
      setText('[data-usage-high-risk]', String(summary.highRisk));
      renderScans(scans);
    }
    setDashboardLoading(false);
  } catch (error) {
    setSignedOut();
    setText('[data-dashboard-status-title]', 'Dashboard unavailable');
    setText('[data-dashboard-status-text]', error.message || 'Unable to load scan history. Please try again.');
    const table = document.querySelector('[data-recent-scans]');
    if (table) {
      table.innerHTML = `
        <div class="empty-state-table">
          <strong>Unable to load scan history.</strong>
          <p>Please try again.</p>
        </div>
      `;
    }
  }
});
