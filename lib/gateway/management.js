const crypto = require('crypto');
const { serverConfig } = require('../config');
const { billingSnapshot } = require('../entitlements');
const { eq, supabaseFetch } = require('../supabase-server');
const { HttpError } = require('../veritrust-api');
const { compilePolicy } = require('./policy');
const { publishDecision } = require('./persistence');
const { encryptSecret } = require('./secrets');
const { assertPublicWebhookDestination, signWebhook } = require('./webhooks');

async function requireManager(auth) {
  if (auth.kind === 'user') {
    if (!['owner', 'admin'].includes(String(auth.role))) {
      throw new HttpError(403, 'Owner or admin role is required.', { code: 'MANAGER_ROLE_REQUIRED' });
    }
    return;
  }
  const userId = auth.user?.id;
  const orgId = auth.organization?.id;
  if (!userId || !orgId) throw new HttpError(403, 'Owner or admin role is required.', { code: 'MANAGER_ROLE_REQUIRED' });
  const rows = await supabaseFetch(`/rest/v1/organization_members?org_id=eq.${eq(orgId)}&user_id=eq.${eq(userId)}&status=eq.active&role=in.(owner,admin)&select=id&limit=1`, { service: true });
  if (!rows?.length) throw new HttpError(403, 'Owner or admin role is required.', { code: 'MANAGER_ROLE_REQUIRED' });
}

async function listPolicies(auth) {
  return supabaseFetch(`/rest/v1/gateway_policies?org_id=eq.${eq(auth.organization.id)}&select=*,gateway_policy_versions(*)&order=created_at.desc`, { service: true });
}

async function createPolicy(auth, body) {
  await requireManager(auth);
  const name = String(body?.name || '').trim();
  if (!name || name.length > 120) throw new HttpError(400, 'Policy name must contain 1 to 120 characters.', { code: 'POLICY_NAME_INVALID' });
  const compiled = compilePolicy(body.policy_document);
  const policies = await supabaseFetch('/rest/v1/gateway_policies?select=*', {
    method: 'POST', service: true,
    body: { org_id: auth.organization.id, name, description: String(body.description || '').slice(0, 500) || null, created_by: auth.user?.id || null },
    headers: { Prefer: 'return=representation' },
  });
  const policy = policies[0];
  try {
    const version = await supabaseFetch('/rest/v1/rpc/gateway_create_policy_version', {
      method: 'POST', service: true, body: {
        target_policy_id: policy.id, target_policy_document: body.policy_document,
        target_schema_version: '1.0', target_created_by: auth.user?.id || null,
      },
    });
    const versionId = Array.isArray(version) ? version[0] : version;
    if (body.activate !== false) await supabaseFetch('/rest/v1/rpc/gateway_activate_policy_version', { method: 'POST', service: true, body: { target_version_id: versionId, target_activated_by: auth.user?.id || null, target_reason: 'Gateway management API activation' } });
    return { policy_id: policy.id, version_id: versionId, checksum: compiled.checksum, active: body.activate !== false };
  } catch (error) {
    await supabaseFetch(`/rest/v1/gateway_policies?id=eq.${eq(policy.id)}&active_version_id=is.null`, { method: 'DELETE', service: true }).catch(() => null);
    throw error;
  }
}

async function activatePolicy(auth, versionId) {
  await requireManager(auth);
  const rows = await supabaseFetch(`/rest/v1/gateway_policy_versions?id=eq.${eq(versionId)}&org_id=eq.${eq(auth.organization.id)}&select=id&limit=1`, { service: true });
  if (!rows?.length) throw new HttpError(404, 'Policy version was not found.', { code: 'POLICY_VERSION_NOT_FOUND' });
  const result = await supabaseFetch('/rest/v1/rpc/gateway_activate_policy_version', { method: 'POST', service: true, body: { target_version_id: versionId, target_activated_by: auth.user?.id || null, target_reason: 'Gateway management API activation' } });
  return { activation_id: Array.isArray(result) ? result[0] : result, version_id: versionId };
}

async function listWebhooks(auth) {
  return supabaseFetch(`/rest/v1/gateway_webhook_endpoints?org_id=eq.${eq(auth.organization.id)}&select=id,integration_id,name,url,event_types,status,timeout_ms,max_attempts,replay_window_seconds,created_at,updated_at&order=created_at.desc`, { service: true });
}

async function createWebhook(auth, body) {
  await requireManager(auth);
  const url = await assertPublicWebhookDestination(body?.url);
  const endpointId = crypto.randomUUID();
  const secretId = crypto.randomUUID();
  const secret = crypto.randomBytes(32).toString('base64url');
  const encrypted = encryptSecret(secret, serverConfig.gatewayWebhookEncryptionKey);
  const name = String(body?.name || 'Gateway webhook').trim().slice(0, 120);
  await supabaseFetch('/rest/v1/gateway_webhook_endpoints', { method: 'POST', service: true, body: {
    id: endpointId, org_id: auth.organization.id, integration_id: body.integration_id || null, name, url,
    signing_secret_ref: secretId, event_types: Array.isArray(body.event_types) && body.event_types.length ? body.event_types : ['gateway.scan.completed'],
    status: 'active', created_by: auth.user?.id || null,
  }});
  try {
    await supabaseFetch('/rest/v1/gateway_webhook_secrets', { method: 'POST', service: true, body: { id: secretId, org_id: auth.organization.id, endpoint_id: endpointId, ...encrypted, key_version: 'v1', created_by: auth.user?.id || null } });
  } catch (error) {
    await supabaseFetch(`/rest/v1/gateway_webhook_endpoints?id=eq.${eq(endpointId)}`, { method: 'DELETE', service: true }).catch(() => null);
    throw error;
  }
  return { endpoint_id: endpointId, signing_secret: secret, signing_version: 'v1' };
}

async function disableWebhook(auth, endpointId) {
  await requireManager(auth);
  const rows = await supabaseFetch(`/rest/v1/gateway_webhook_endpoints?id=eq.${eq(endpointId)}&org_id=eq.${eq(auth.organization.id)}&select=id`, { method: 'PATCH', service: true, body: { status: 'disabled' }, headers: { Prefer: 'return=representation' } });
  if (!rows?.length) throw new HttpError(404, 'Webhook endpoint was not found.', { code: 'WEBHOOK_NOT_FOUND' });
  await supabaseFetch(`/rest/v1/gateway_webhook_secrets?endpoint_id=eq.${eq(endpointId)}&revoked_at=is.null`, { method: 'PATCH', service: true, body: { revoked_at: new Date().toISOString() } });
  return { endpoint_id: endpointId, status: 'disabled' };
}

async function testWebhook(auth, endpointId) {
  await requireManager(auth);
  const endpoints = await supabaseFetch(`/rest/v1/gateway_webhook_endpoints?id=eq.${eq(endpointId)}&org_id=eq.${eq(auth.organization.id)}&select=*&limit=1`, { service: true });
  const endpoint = endpoints?.[0];
  if (!endpoint) throw new HttpError(404, 'Webhook endpoint was not found.', { code: 'WEBHOOK_NOT_FOUND' });
  const secrets = await supabaseFetch(`/rest/v1/gateway_webhook_secrets?endpoint_id=eq.${eq(endpointId)}&revoked_at=is.null&select=*&limit=1`, { service: true });
  const { decryptSecret } = require('./secrets');
  const secret = decryptSecret(secrets[0], serverConfig.gatewayWebhookEncryptionKey);
  const url = await assertPublicWebhookDestination(endpoint.url);
  const payload = JSON.stringify({ event_id: crypto.randomUUID(), event_type: 'gateway.webhook.test', schema_version: '1.0', created_at: new Date().toISOString() });
  const timestamp = Math.floor(Date.now() / 1000);
  const response = await fetch(url, { method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(endpoint.timeout_ms), headers: { 'Content-Type': 'application/json', 'X-VeriTrust-Timestamp': String(timestamp), 'X-VeriTrust-Signature': signWebhook(secret, timestamp, payload) }, body: payload });
  response.body?.cancel().catch(() => null);
  return { endpoint_id: endpointId, response_status: response.status, delivered: response.status >= 200 && response.status < 300 };
}

async function listReviews(auth) {
  return supabaseFetch(`/rest/v1/gateway_review_cases?org_id=eq.${eq(auth.organization.id)}&select=*&order=created_at.desc&limit=100`, { service: true });
}

async function resolveReview(auth, reviewId, body) {
  await requireManager(auth);
  const recommendation = String(body?.recommendation || '').toLowerCase();
  if (!['allow', 'warn', 'manual_review', 'quarantine', 'block', 'hold'].includes(recommendation)) throw new HttpError(400, 'Review recommendation is invalid.', { code: 'REVIEW_RESOLUTION_INVALID' });
  const rows = await supabaseFetch(`/rest/v1/gateway_review_cases?id=eq.${eq(reviewId)}&org_id=eq.${eq(auth.organization.id)}&status=in.(open,assigned)&select=*&limit=1`, { service: true });
  const review = rows?.[0];
  if (!review) throw new HttpError(404, 'Open review case was not found.', { code: 'REVIEW_NOT_FOUND' });
  const decisions = await supabaseFetch(`/rest/v1/gateway_decisions?id=eq.${eq(review.decision_id)}&scan_id=eq.${eq(review.scan_id)}&select=*&limit=1`, { service: true });
  const previous = decisions?.[0];
  const overrideId = await publishDecision(review.scan_id, {
    decision_state: 'override', risk: Number(previous.risk_score), verdict: previous.verdict,
    recommendation, degraded: previous.degraded,
    reason_codes: [...new Set([...(previous.reason_codes || []), 'HUMAN_REVIEW_OVERRIDE'])],
    evidence_ids: previous.evidence_ids || [], correlation_version: previous.correlation_version,
    manual_review_required: false,
  }, auth.user?.id || null);
  await supabaseFetch(`/rest/v1/gateway_review_cases?id=eq.${eq(review.id)}`, { method: 'PATCH', service: true, body: {
    status: 'resolved', resolution: recommendation, resolution_note: String(body.note || '').slice(0, 2000) || null,
    resolved_by: auth.user?.id || null, resolved_at: new Date().toISOString(),
  }});
  return { review_id: review.id, override_decision_id: overrideId, recommendation, status: 'resolved' };
}

async function operations(auth) {
  await requireManager(auth);
  const [health, jobs, billing] = await Promise.all([
    supabaseFetch('/rest/v1/rpc/gateway_schema_health', { method: 'POST', service: true, body: {} }),
    supabaseFetch(`/rest/v1/gateway_jobs?org_id=eq.${eq(auth.organization.id)}&select=status,queue_name,attempt_count,created_at&order=created_at.desc&limit=500`, { service: true }),
    billingSnapshot(auth.organization.id),
  ]);
  return {
    schema: Array.isArray(health) ? health[0] : health,
    jobs,
    quota: {
      usage: {
        today: billing.usage.gateway_used_today,
        month: billing.usage.gateway_used_month,
        artifacts_month: billing.usage.gateway_artifacts_month,
        model_runs_month: billing.usage.gateway_model_runs_month,
        submitted_bytes_month: billing.usage.gateway_submitted_bytes_month,
      },
      limits: {
        daily_scans: billing.limits.daily_gateway_scan_limit,
        monthly_scans: billing.limits.monthly_gateway_scan_limit,
        max_artifacts_per_scan: billing.limits.max_gateway_artifacts,
        max_parallel_models: billing.limits.max_gateway_parallel_models,
        max_raw_retention_hours: billing.limits.gateway_max_raw_retention_hours,
      },
      enforcement_enabled: billing.features.gateway_enforcement_enabled,
    },
  };
}

module.exports = { activatePolicy, createPolicy, createWebhook, disableWebhook, listPolicies, listReviews, listWebhooks, operations, resolveReview, testWebhook };
