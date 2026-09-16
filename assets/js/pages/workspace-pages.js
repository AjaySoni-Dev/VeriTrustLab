(function workspacePages(global) {
  'use strict';

  const hasApiPage = Boolean(document.querySelector('[data-api-key-form]'));
  const hasBillingPage = Boolean(document.querySelector('[data-billing-plan]'));
  const hasAccountPage = Boolean(document.querySelector('[data-account-name]'));
  if (!hasApiPage && !hasBillingPage && !hasAccountPage) return;

  const api = () => global.VeriTrustSupabase;
  const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[character]));
  const titleCase = (value) => String(value || 'unknown').replaceAll('_', ' ').replace(/\b\w/gu, (letter) => letter.toUpperCase());
  const formatDate = (value) => {
    if (!value) return 'Never';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? 'Never' : date.toLocaleString();
  };
  const safeNumber = (value, fallback = 0) => Number.isFinite(Number(value)) ? Number(value) : fallback;
  const setText = (selector, value) => {
    const node = document.querySelector(selector);
    if (node) node.textContent = String(value ?? '');
  };
  const setStatus = (message) => setText('[data-dashboard-status-text]', message);

  function setMeter(labelSelector, barSelector, used, limit) {
    const safeUsed = safeNumber(used);
    const safeLimit = safeNumber(limit);
    setText(labelSelector, `${safeUsed.toLocaleString()} / ${safeLimit.toLocaleString()}`);
    const bar = document.querySelector(barSelector);
    if (!bar) return;
    const percentage = safeLimit > 0 ? Math.min(100, Math.round((safeUsed / safeLimit) * 100)) : 0;
    bar.style.width = `${percentage}%`;
    bar.classList.toggle('is-warning', percentage >= 70 && percentage < 90);
    bar.classList.toggle('is-danger', percentage >= 90);
  }

  function renderBilling(billing = {}) {
    const plan = billing.plan || {};
    const subscription = billing.subscription || {};
    const usage = billing.usage || {};
    const limits = billing.limits || {};
    const features = billing.features || {};
    const planName = plan.name || titleCase(plan.code || 'workspace');
    const gatewayEnabled = features.gateway_enabled !== false;

    setText('[data-billing-plan]', planName);
    setText('[data-billing-status]', titleCase(subscription.status || 'active'));
    setText('[data-billing-renewal]', subscription.current_period_end ? formatDate(subscription.current_period_end) : 'Deployment policy');
    setText('[data-billing-summary]', `${planName} workspace limits are enforced by the deployed policy. API access is ${features.allow_api_access === false ? 'not enabled' : 'enabled'}; Evidence Correlation is ${gatewayEnabled ? 'enabled' : 'disabled'}.`);
    setMeter('[data-billing-web-label]', '[data-billing-web-bar]', usage.web_used, limits.monthly_web_scan_limit || 0);
    setMeter('[data-billing-api-label]', '[data-billing-api-bar]', usage.api_used, limits.monthly_api_limit || 0);
    setMeter('[data-billing-keys-label]', '[data-billing-keys-bar]', usage.api_keys_used, limits.max_api_keys || 0);
    setMeter('[data-billing-gateway-daily-label]', '[data-billing-gateway-daily-bar]', usage.gateway_used_today, limits.daily_gateway_scan_limit || 0);
    setMeter('[data-billing-gateway-monthly-label]', '[data-billing-gateway-monthly-bar]', usage.gateway_used_month, limits.monthly_gateway_scan_limit || 0);
    setText('[data-billing-gateway-artifacts]', limits.max_gateway_artifacts ?? '—');
    setText('[data-billing-gateway-parallel]', limits.max_gateway_parallel_models ?? '—');
    setText('[data-billing-gateway-retention]', limits.gateway_max_raw_retention_hours == null ? '—' : `${limits.gateway_max_raw_retention_hours}h`);
  }

  function apiUsage(keys) {
    return keys.filter((key) => key.status === 'active').reduce((total, key) => {
      total.used += safeNumber(key.usage?.used_today);
      total.limit += safeNumber(key.usage?.limit_daily || key.usage_limit_daily);
      total.remaining += safeNumber(key.usage?.remaining_today);
      if (key.last_used_at && (!total.lastUsed || new Date(key.last_used_at) > new Date(total.lastUsed))) total.lastUsed = key.last_used_at;
      return total;
    }, { used: 0, limit: 0, remaining: 0, lastUsed: null });
  }

  function renderApiKeys(keys = []) {
    const rows = Array.isArray(keys) ? keys : [];
    const usage = apiUsage(rows);
    setText('[data-api-usage-used]', usage.used);
    setText('[data-api-usage-limit]', usage.limit || 0);
    setText('[data-api-usage-remaining]', usage.remaining || Math.max(0, usage.limit - usage.used));
    setText('[data-api-last-used]', formatDate(usage.lastUsed));

    const target = document.querySelector('[data-api-keys-list]');
    if (!target) return;
    if (!rows.length) {
      target.innerHTML = '<div class="empty-state-table"><strong>No API keys yet</strong><p>Create a scoped key when API access is enabled for this workspace.</p></div>';
      return;
    }
    target.innerHTML = `<div class="api-key-list">${rows.map((key) => `
      <div class="api-key-row">
        <div class="api-key-main"><small>Key name</small><strong>${escapeHtml(key.name || 'API Key')}</strong><code>${escapeHtml(key.masked_key || key.key_prefix || '')}</code></div>
        <div class="api-key-meta">
          <span><small>Created</small><strong>${escapeHtml(formatDate(key.created_at))}</strong></span>
          <span><small>Last used</small><strong>${escapeHtml(formatDate(key.last_used_at))}</strong></span>
          <span><small>Usage today</small><strong>${escapeHtml(key.usage?.used_today || 0)} of ${escapeHtml(key.usage?.limit_daily || key.usage_limit_daily || 0)}</strong></span>
        </div>
        <div class="api-key-controls"><span class="status-pill ${key.status === 'active' ? 'ready' : 'warn'} api-key-status">${escapeHtml(titleCase(key.status || 'active'))}</span>${key.status === 'active' ? `<button class="btn btn-secondary" type="button" data-revoke-api-key="${escapeHtml(key.id)}">Revoke</button>` : ''}</div>
      </div>`).join('')}</div>`;

    target.querySelectorAll('[data-revoke-api-key]').forEach((button) => {
      button.addEventListener('click', async () => {
        const id = button.dataset.revokeApiKey;
        if (!id || !global.confirm('Revoke this API key? Existing clients using it will stop working.')) return;
        button.disabled = true;
        button.textContent = 'Revoking…';
        try {
          await api().callAppApi(`/api/api-keys?id=${encodeURIComponent(id)}`, { method: 'DELETE', cache: 'no-store' });
          await loadApiKeys();
        } catch (error) {
          setStatus(error.message || 'Unable to revoke the API key.');
          button.disabled = false;
          button.textContent = 'Revoke';
        }
      });
    });
  }

  async function loadApiKeys() {
    const payload = await api().callAppApi('/api/api-keys', { cache: 'no-store' });
    renderApiKeys(payload.api_keys || []);
  }

  function bindApiKeyForm(apiAllowed) {
    const form = document.querySelector('[data-api-key-form]');
    if (!form) return;
    const input = form.elements.name;
    const submit = form.querySelector('button[type="submit"]');
    if (!apiAllowed) {
      input.disabled = true;
      submit.disabled = true;
      setStatus('API access is not enabled for this workspace.');
      return;
    }
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const name = String(input.value || '').trim();
      if (!name) {
        input.focus();
        return;
      }
      submit.disabled = true;
      submit.textContent = 'Creating…';
      try {
        const payload = await api().callAppApi('/api/api-keys', {
          method: 'POST',
          cache: 'no-store',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name }),
        });
        const created = document.querySelector('[data-api-key-created]');
        const key = payload.api_key || {};
        if (created) {
          created.hidden = false;
          created.innerHTML = `<strong>Copy this key now. It will not be shown again.</strong><div class="api-key-secret"><code>${escapeHtml(key.key || '')}</code><button class="btn btn-secondary" type="button" data-copy-created-key>Copy</button></div>`;
          created.querySelector('[data-copy-created-key]')?.addEventListener('click', async (copyEvent) => {
            await navigator.clipboard?.writeText(key.key || '');
            copyEvent.currentTarget.textContent = 'Copied';
          });
        }
        form.reset();
        await loadApiKeys();
      } catch (error) {
        setStatus(error.message || 'Unable to create an API key.');
      } finally {
        submit.disabled = false;
        submit.textContent = 'Create API Key';
      }
    });
  }

  const initials = (value) => String(value || 'VT').trim().split(/\s+/u).slice(0, 2).map((part) => part.charAt(0)).join('').toUpperCase() || 'VT';

  function renderAccount(context) {
    const profile = context.profile || {};
    const user = context.user || {};
    const organization = context.organization || {};
    const name = profile.full_name || profile.username || user.email || 'Signed-in user';
    setText('[data-dashboard-status-title]', organization.name || 'Workspace');
    setText('[data-account-name]', name);
    setText('[data-account-detail]', `${user.email || 'Authenticated'} · ${titleCase(context.role || 'member')} in ${organization.name || 'workspace'}`);
    setText('[data-account-avatar]', initials(name));
    setText('[data-workspace-name]', organization.name || 'Workspace');
    setText('[data-workspace-role]', titleCase(context.role || 'member'));
    setText('[data-workspace-members]', context.stats?.member_count ?? 'Available');
    setText('[data-session-label]', 'Signed in');
    document.querySelector('[data-session-pill]')?.classList.remove('warn');
    document.querySelector('[data-session-pill] .status-dot')?.classList.remove('pending');
    const primary = document.querySelector('[data-account-primary-action]');
    if (primary) {
      primary.textContent = 'New Investigation';
      primary.href = '/phishing';
    }
    const edit = document.querySelector('[data-profile-edit]');
    if (edit) edit.hidden = false;
    bindProfileForm(profile);
  }

  function bindProfileForm(initialProfile) {
    const edit = document.querySelector('[data-profile-edit]');
    const form = document.querySelector('[data-profile-form]');
    const cancel = document.querySelector('[data-profile-cancel]');
    if (!edit || !form) return;
    let profile = { ...initialProfile };
    const close = () => { form.hidden = true; };
    edit.addEventListener('click', () => {
      form.elements.full_name.value = profile.full_name || '';
      form.elements.username.value = profile.username || '';
      form.hidden = false;
      form.elements.full_name.focus();
    });
    cancel?.addEventListener('click', close);
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const submit = form.querySelector('button[type="submit"]');
      submit.disabled = true;
      submit.textContent = 'Saving…';
      try {
        const avatar = form.elements.avatar.files?.[0] || null;
        const update = {
          full_name: form.elements.full_name.value.trim(),
          username: form.elements.username.value.trim().toLowerCase() || null,
        };
        if (avatar) await api().uploadAvatar(avatar);
        profile = await api().updateProfile(update);
        const name = profile.full_name || profile.username || 'Signed-in user';
        setText('[data-account-name]', name);
        setText('[data-account-avatar]', initials(name));
        close();
        form.reset();
        setStatus('Profile updated successfully.');
      } catch (error) {
        setStatus(error.message || 'Unable to update the profile.');
      } finally {
        submit.disabled = false;
        submit.textContent = 'Save Profile';
      }
    });
  }

  async function initialize() {
    if (!api()?.isConfigured?.()) throw new Error('Account services are not configured for this deployment.');
    const session = await api().getSession();
    if (!session) {
      global.location.href = `/auth?redirect=${encodeURIComponent(global.location.pathname)}`;
      return;
    }
    const context = await api().getDashboard({ limit: 20 });
    if (hasBillingPage) renderBilling(context.billing || {});
    if (hasAccountPage) renderAccount(context);
    if (hasApiPage) {
      const apiAllowed = context.billing?.features?.allow_api_access !== false;
      bindApiKeyForm(apiAllowed);
      if (apiAllowed) await loadApiKeys();
      else renderApiKeys([]);
    }
    document.body.classList.remove('dashboard-is-loading');
  }

  document.addEventListener('DOMContentLoaded', () => {
    initialize().catch((error) => {
      document.body.classList.remove('dashboard-is-loading');
      setStatus(error.message || 'Unable to load this workspace page.');
      if (hasApiPage) renderApiKeys([]);
    });
  }, { once: true });
})(window);
