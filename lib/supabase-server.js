const crypto = require('crypto');
const { getOptionalEnv, serverConfig } = require('./config');
const { accessCookie } = require('./browser-session');
const {
  mergeScanHistories,
  normalizeGatewayScan,
} = require('./gateway/dashboard-history');
const { filterEnabledScans, isModuleEnabled, isScanTypeEnabled, sanitizeModuleData } = require('./modules');

class SupabaseError extends Error {
  constructor(status, message, details = null, code = null) {
    super(message);
    this.name = 'SupabaseError';
    this.status = status;
    this.details = details;
    this.code = code;
  }
}

function supabaseUrl() {
  return serverConfig.supabaseUrl;
}

function anonKey() {
  return serverConfig.supabaseAnonKey;
}

function serviceRoleKey() {
  return serverConfig.supabaseServiceRoleKey;
}

function isSupabaseConfigured() {
  return Boolean(getOptionalEnv('SUPABASE_URL') && getOptionalEnv('SUPABASE_ANON_KEY'));
}

function isServiceRoleConfigured() {
  return Boolean(getOptionalEnv('SUPABASE_SERVICE_ROLE_KEY'));
}

function requireServiceRole() {
  if (!isServiceRoleConfigured()) {
    throw new SupabaseError(500, 'Server persistence is not configured.', null, 'SERVER_CONFIG_ERROR');
  }
}

function bearerToken(req) {
  const header = req.headers.authorization || req.headers.Authorization || '';
  const match = String(header).match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : accessCookie(req);
}

async function readBoundedText(response, maxBytes = 4 * 1024 * 1024) {
  const declaredSize = Number(response.headers.get('content-length') || 0);
  if (declaredSize > maxBytes) {
    response.body?.cancel().catch(() => null);
    throw new SupabaseError(502, 'Supabase response exceeded the size limit.', null, 'UPSTREAM_RESPONSE_TOO_LARGE');
  }
  if (!response.body?.getReader) {
    const buffer = Buffer.from(await response.arrayBuffer());
    if (buffer.length > maxBytes) {
      throw new SupabaseError(502, 'Supabase response exceeded the size limit.', null, 'UPSTREAM_RESPONSE_TOO_LARGE');
    }
    return buffer.toString('utf8');
  }

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new SupabaseError(502, 'Supabase response exceeded the size limit.', null, 'UPSTREAM_RESPONSE_TOO_LARGE');
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks, total).toString('utf8');
}

async function readResponse(response, maxBytes) {
  const raw = await readBoundedText(response, maxBytes);
  let data = null;
  try {
    data = raw ? JSON.parse(raw) : null;
  } catch {
    data = raw;
  }

  if (!response.ok) {
    const message = data?.message || data?.msg || data?.error_description || data?.error || `Supabase request failed with status ${response.status}.`;
    const upstreamCode = typeof data?.code === 'string' && data.code
      ? `SUPABASE_${data.code.toUpperCase()}`
      : null;
    throw new SupabaseError(response.status, message, data, upstreamCode);
  }

  return data;
}

async function supabaseFetch(path, options = {}) {
  const key = options.service ? serviceRoleKey() : anonKey();
  if (options.service) requireServiceRole();

  const headers = {
    apikey: key,
    Authorization: `Bearer ${options.accessToken || key}`,
    Accept: 'application/json',
    ...(options.body ? { 'Content-Type': 'application/json' } : {}),
    ...(options.headers || {}),
  };

  const timeoutMs = Math.max(1000, Math.min(120000, Number(options.timeoutMs || 30000)));
  const response = await fetch(`${supabaseUrl()}${path}`, {
    method: options.method || 'GET',
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
    signal: options.signal || AbortSignal.timeout(timeoutMs),
  });

  return readResponse(response, Math.max(1024, Math.min(4 * 1024 * 1024, Number(options.maxResponseBytes || 4 * 1024 * 1024))));
}

async function getUserFromRequest(req) {
  const token = bearerToken(req);
  if (!token) {
    throw new SupabaseError(401, 'Sign in to use VeriTrust scans.');
  }

  const user = await supabaseFetch('/auth/v1/user', {
    accessToken: token,
  });

  return { token, user };
}

function eq(value) {
  return encodeURIComponent(String(value));
}

function slugForUser(userId) {
  return `org-${String(userId || '').replace(/-/g, '')}`;
}

function fallbackWorkspaceName(user) {
  const metadata = user?.user_metadata || user?.raw_user_meta_data || {};
  const workspaceName = String(metadata.workspace_name || '').trim();
  if (workspaceName) return workspaceName;

  const emailPrefix = String(user?.email || 'workspace').split('@')[0] || 'workspace';
  return `${emailPrefix}'s Workspace`;
}

function fallbackProfileName(user) {
  const metadata = user?.user_metadata || user?.raw_user_meta_data || {};
  return String(metadata.full_name || '').trim() || user?.email || null;
}

async function serviceSelect(path) {
  if (!isServiceRoleConfigured()) return null;
  return supabaseFetch(path, { service: true });
}

async function ensureProfile(user) {
  if (!isServiceRoleConfigured()) return null;

  const rows = await supabaseFetch('/rest/v1/profiles?on_conflict=id&select=*', {
    method: 'POST',
    service: true,
    body: {
      id: user.id,
      full_name: fallbackProfileName(user),
    },
    headers: {
      Prefer: 'resolution=merge-duplicates,return=representation',
    },
  });

  return rows?.[0] || null;
}

async function ensureDefaultWorkspace(user, profile) {
  if (!isServiceRoleConfigured()) return null;

  const preferredOrgId = profile?.default_org_id;
  if (preferredOrgId) {
    const rows = await serviceSelect(`/rest/v1/organization_members?org_id=eq.${eq(preferredOrgId)}&user_id=eq.${eq(user.id)}&status=eq.active&select=role,organizations(*,plans(code,daily_scan_limit,learning_catalog_access,learning_certificate_access,learning_admin_access,learning_seat_limit,learning_assignment_limit,learning_export_access,learning_proctored_exam_access))`);
    if (rows?.[0]?.organizations) {
      return {
        organization: rows[0].organizations,
        role: rows[0].role,
      };
    }
  }

  const existingMembershipRows = await serviceSelect(`/rest/v1/organization_members?user_id=eq.${eq(user.id)}&status=eq.active&select=role,organizations(*,plans(code,daily_scan_limit,learning_catalog_access,learning_certificate_access,learning_admin_access,learning_seat_limit,learning_assignment_limit,learning_export_access,learning_proctored_exam_access))&limit=1`);
  const existingMembership = existingMembershipRows?.[0] || null;
  if (existingMembership?.organizations) {
    await supabaseFetch(`/rest/v1/profiles?id=eq.${eq(user.id)}`, {
      method: 'PATCH',
      service: true,
      body: { default_org_id: existingMembership.organizations.id },
    });
    return {
      organization: existingMembership.organizations,
      role: existingMembership.role,
    };
  }

  const planRows = await serviceSelect('/rest/v1/plans?code=eq.free&select=id,code,daily_scan_limit&limit=1');
  const freePlan = planRows?.[0] || null;
  const freePlanId = freePlan?.id;
  if (!freePlanId) {
    throw new SupabaseError(500, 'The free plan is missing from Supabase. Run the production schema seed.');
  }

  const orgRows = await supabaseFetch('/rest/v1/organizations?on_conflict=slug&select=*', {
    method: 'POST',
    service: true,
    body: {
      plan_id: freePlanId,
      name: fallbackWorkspaceName(user),
      slug: slugForUser(user.id),
      created_by: user.id,
    },
    headers: {
      Prefer: 'resolution=merge-duplicates,return=representation',
    },
  });
  const organization = orgRows?.[0] || null;
  if (!organization) {
    throw new SupabaseError(500, 'Unable to create a VeriTrust workspace for this user.');
  }

  await supabaseFetch('/rest/v1/organization_members?on_conflict=org_id,user_id', {
    method: 'POST',
    service: true,
    body: {
      org_id: organization.id,
      user_id: user.id,
      role: 'owner',
      status: 'active',
    },
    headers: {
      Prefer: 'resolution=merge-duplicates',
    },
  });

  await supabaseFetch(`/rest/v1/profiles?id=eq.${eq(user.id)}`, {
    method: 'PATCH',
    service: true,
    body: { default_org_id: organization.id },
  });

  return {
    organization: {
      ...organization,
      plans: freePlan ? { code: freePlan.code, daily_scan_limit: freePlan.daily_scan_limit } : undefined,
    },
    role: 'owner',
  };
}

async function getProfileContext(req, preferredOrgId = null) {
  const auth = await getUserFromRequest(req);
  // The access token is used only to establish the verified Supabase user.
  // Resolve that user's workspace through the server role when available so
  // authenticated clients do not need direct SELECT grants on tenant tables.
  const contextReadOptions = isServiceRoleConfigured()
    ? { service: true }
    : { accessToken: auth.token };
  const profileRows = await supabaseFetch(`/rest/v1/profiles?id=eq.${eq(auth.user.id)}&select=*`, {
    ...contextReadOptions,
  });
  let profile = profileRows?.[0] || null;
  if (!profile && isServiceRoleConfigured()) {
    profile = await ensureProfile(auth.user);
  }

  const orgId = preferredOrgId || profile?.default_org_id;

  if (!orgId) {
    const repaired = await ensureDefaultWorkspace(auth.user, profile);
    if (!repaired) {
      throw new SupabaseError(403, 'No VeriTrust workspace is available for this user.');
    }
    const repairedProfileRows = await supabaseFetch(`/rest/v1/profiles?id=eq.${eq(auth.user.id)}&select=*`, {
      ...contextReadOptions,
    });
    return {
      token: auth.token,
      user: auth.user,
      profile: repairedProfileRows?.[0] || profile,
      organization: repaired.organization,
      role: repaired.role,
    };
  }

  const memberRows = await supabaseFetch(`/rest/v1/organization_members?org_id=eq.${eq(orgId)}&user_id=eq.${eq(auth.user.id)}&status=eq.active&select=role,organizations(*,plans(code,daily_scan_limit,learning_catalog_access,learning_certificate_access,learning_admin_access,learning_seat_limit,learning_assignment_limit,learning_export_access,learning_proctored_exam_access))`, {
    ...contextReadOptions,
  });
  const membership = memberRows?.[0] || null;
  const organization = membership?.organizations || null;

  if (!membership || !organization) {
    if (!preferredOrgId && isServiceRoleConfigured()) {
      const repaired = await ensureDefaultWorkspace(auth.user, profile);
      if (repaired) {
        const repairedProfileRows = await supabaseFetch(`/rest/v1/profiles?id=eq.${eq(auth.user.id)}&select=*`, {
          ...contextReadOptions,
        });
        return {
          token: auth.token,
          user: auth.user,
          profile: repairedProfileRows?.[0] || profile,
          organization: repaired.organization,
          role: repaired.role,
        };
      }
    }
    throw new SupabaseError(403, 'You do not have access to this VeriTrust workspace.');
  }

  return {
    token: auth.token,
    user: auth.user,
    profile,
    organization,
    role: membership.role,
  };
}

async function rpc(functionName, body, options = {}) {
  return supabaseFetch(`/rest/v1/rpc/${functionName}`, {
    method: 'POST',
    body,
    accessToken: options.accessToken,
    service: options.service,
    headers: {
      Prefer: 'return=representation',
      ...(options.headers || {}),
    },
  });
}

async function dashboardSnapshot(req, options = {}) {
  const token = bearerToken(req);
  if (!token) {
    throw new SupabaseError(401, 'Sign in to view the dashboard.');
  }
  const limit = Math.max(1, Math.min(100, Number(options.limit) || 100));
  const offset = Math.max(0, Math.min(10000, Number(options.offset) || 0));
  const dashboard = await rpc('get_dashboard', {
    target_org_id: options.orgId || null,
    recent_limit: limit,
    recent_offset: offset,
  }, { accessToken: token });

  if (!dashboard || Array.isArray(dashboard)) return dashboard;
  const filteredDashboard = sanitizeModuleData({
    ...dashboard,
    scans: filterEnabledScans(dashboard.scans || []),
  });

  if (offset > 0 || !dashboard.organization?.id || !isServiceRoleConfigured() || !isModuleEnabled('gateway')) {
    return filteredDashboard;
  }

  try {
    const gatewayScans = await recentGatewayScans(dashboard.organization.id, limit);
    return sanitizeModuleData({
      ...dashboard,
      scans: filterEnabledScans(mergeScanHistories(filteredDashboard.scans, gatewayScans, limit)),
    });
  } catch (error) {
    console.error('VeriTrust gateway dashboard history unavailable', {
      organization_id: dashboard.organization.id,
      message: error.message,
    });
    return filteredDashboard;
  }
}

function textHash(text) {
  return crypto.createHash('sha256').update(String(text || ''), 'utf8').digest('hex');
}

function riskLevel(value) {
  const normalized = String(value || '').toLowerCase();
  if (['low', 'medium', 'high', 'critical'].includes(normalized)) return normalized;
  return 'unknown';
}

function primaryScoreForPayload(payload) {
  const result = payload?.result || {};
  if (payload?.type === 'deepfake') return Number(result.fake_score || 0);
  if (payload?.type === 'link' || payload?.scan_type === 'link') return Number(result.link_score || 0);
  return Number(result.phishing_score || 0);
}

function secondaryScoreForPayload(payload) {
  const result = payload?.result || {};
  if (payload?.type === 'deepfake') return Number(result.real_score || 0);
  if (payload?.type === 'link' || payload?.scan_type === 'link') return Number(result.model_score || 0);
  return Number(result.legitimate_score || 0);
}

function logicalScanType(scan) {
  const scanMetadata = scan?.metadata || {};
  const inputs = Array.isArray(scan?.scan_inputs) ? scan.scan_inputs : [scan?.scan_inputs].filter(Boolean);
  const isLink = scanMetadata.logical_scan_type === 'link'
    || scanMetadata.original_scan_type === 'link'
    || inputs.some((input) => input?.input_kind === 'url'
      || input?.metadata?.logical_scan_type === 'link'
      || input?.metadata?.original_scan_type === 'link'
      || Boolean(input?.metadata?.normalized_url));
  return isLink ? 'link' : scan?.scan_type;
}

async function createScanRecord(context, options) {
  const metadata = options.scanType === 'link' ? {
    ...(options.metadata || {}),
    logical_scan_type: 'link',
  } : (options.metadata || {});
  const requestId = String(options.requestId || `web:${options.scanType}:${crypto.randomUUID()}`);
  const fingerprint = crypto.createHash('sha256').update(JSON.stringify({
    org_id: context.organization.id,
    scan_type: options.scanType,
    input_kind: options.inputKind,
    model_key: options.modelKey || null,
    project_id: options.projectId || null,
    text_hash: options.textHash || null,
    metadata,
  })).digest('hex');
  const result = await rpc('create_scan_record_atomic', {
    target_org_id: context.organization.id,
    target_scan_type: options.scanType,
    target_input_kind: options.inputKind,
    target_selected_model_key: options.modelKey || null,
    target_project_id: options.projectId || null,
    target_text_preview: options.textPreview || null,
    target_text_hash: options.textHash || null,
    target_metadata: metadata,
    target_source: 'web',
    target_endpoint: options.endpoint || null,
    target_request_id: requestId,
    target_request_fingerprint: fingerprint,
  }, { accessToken: context.token });
  if (!result?.allowed) {
    throw new SupabaseError(
      Number(result?.status || 429),
      result?.message || 'Plan limit reached.',
      result,
      result?.code || 'PLAN_LIMIT_REACHED',
    );
  }
  if (result.duplicate) {
    throw new SupabaseError(
      409,
      'This Idempotency-Key is already reserved or completed.',
      result,
      'IDEMPOTENCY_REPLAY',
    );
  }
  if (!result.scan_id) throw new SupabaseError(500, 'Atomic scan creation returned no scan id.');
  return result.scan_id;
}

async function completeScanRecord(scanId, payload, modelRuns = []) {
  const body = {
    target_scan_id: scanId,
    result_label: payload.result?.label || 'Unknown',
    result_confidence: Number(payload.result?.confidence || 0),
    result_risk_level: riskLevel(payload.result?.risk_level),
    result_primary_score: primaryScoreForPayload(payload),
    result_secondary_score: secondaryScoreForPayload(payload),
    result_explanation: payload.result?.summary || payload.result?.explanation || '',
    result_indicators: payload.result?.indicators || payload.result?.evidence || [],
    result_raw_scores: payload.scores || [],
    model_runs: modelRuns,
  };

  return rpc('complete_scan_record_atomic', body, { service: true });
}

async function failScanRecord(scanId, message) {
  return rpc('fail_scan_record_atomic', {
    target_scan_id: scanId,
    failure_message: message,
  }, {
    service: true,
  });
}

function scanIdempotencyKey(req, scope) {
  const supplied = String(req?.headers?.['idempotency-key'] || '').trim();
  if (supplied && (supplied.length < 8 || supplied.length > 200 || !/^[A-Za-z0-9._:-]+$/u.test(supplied))) {
    throw new SupabaseError(400, 'Idempotency-Key must contain 8-200 safe characters.', null, 'INVALID_IDEMPOTENCY_KEY');
  }
  const value = supplied || crypto.randomUUID();
  const digest = crypto.createHash('sha256').update(value).digest('hex');
  return `web:${scope}:${digest}`;
}

async function runScanLifecycle(context, options, operation) {
  const progress = options.onProgress || (() => {});
  progress('record', 'running', 'Creating the scan record and checking workspace quota.');
  const scanId = await createScanRecord(context, options);
  progress('record', 'completed', 'Scan record created.');
  try {
    const outcome = await operation(scanId);
    progress('save', 'running', 'Saving the result and model evidence to your workspace.');
    await completeScanRecord(scanId, outcome.payload, outcome.modelRuns || []);
    progress('save', 'completed', 'Report saved to your workspace.');
    return { ...outcome, scanId };
  } catch (error) {
    try {
      await failScanRecord(scanId, error.message || 'Scan processing failed.');
    } catch (finalizeError) {
      console.error('VeriTrust atomic scan failure finalization failed', {
        scan_id: scanId,
        message: finalizeError.message,
      });
    }
    throw error;
  }
}

async function recentScans(context, limit = 20) {
  const safeLimit = Math.max(1, Math.min(100, Number(limit) || 20));
  const rows = await supabaseFetch(`/rest/v1/scans?org_id=eq.${eq(context.organization.id)}&select=id,scan_type,status,selected_model_key,final_label,confidence,risk_level,metadata,created_at,completed_at,error_message,scan_inputs(input_kind,text_preview,metadata),scan_results(label,confidence,risk_level,primary_score,secondary_score,explanation,indicators,raw_scores),scan_model_runs(model_key,provider,status,latency_ms,error_message,created_at)&order=created_at.desc&limit=${safeLimit}`, {
    accessToken: context.token,
  });
  const regularScans = (rows || []).map((scan) => ({
    ...scan,
    scan_type: logicalScanType(scan),
  }));
  if (!isServiceRoleConfigured() || !isModuleEnabled('gateway')) return sanitizeModuleData(filterEnabledScans(regularScans));

  try {
    const gatewayScans = await recentGatewayScans(context.organization.id, safeLimit);
    return sanitizeModuleData(filterEnabledScans(mergeScanHistories(regularScans, gatewayScans, safeLimit)));
  } catch (error) {
    console.error('VeriTrust gateway scan history unavailable', {
      organization_id: context.organization.id,
      message: error.message,
    });
    return sanitizeModuleData(filterEnabledScans(regularScans));
  }
}

async function recentGatewayScans(orgId, limit = 20) {
  if (!isModuleEnabled('gateway')) return [];
  const safeLimit = Math.max(1, Math.min(100, Number(limit) || 20));
  const scans = await supabaseFetch(`/rest/v1/gateway_scans?org_id=eq.${eq(orgId)}&select=id,display_id,org_id,submitted_by,status,source,processing_mode,degraded,metadata,created_at,completed_at,failure_code,policy_version_id,correlation_version,preliminary_decision_id,final_decision_id&order=created_at.desc&limit=${safeLimit}`, {
    service: true,
  });
  if (!scans?.length) return [];

  const scanFilter = scans.map((scan) => eq(scan.id)).join(',');
  const [decisions, evidence] = await Promise.all([
    supabaseFetch(`/rest/v1/gateway_decisions?org_id=eq.${eq(orgId)}&scan_id=in.(${scanFilter})&select=id,scan_id,sequence,decision_kind,risk_score,verdict,recommendation,degraded,reason_codes,policy_version_id,correlation_version,created_at&order=sequence.desc`, { service: true }),
    supabaseFetch(`/rest/v1/gateway_evidence?org_id=eq.${eq(orgId)}&scan_id=in.(${scanFilter})&select=id,scan_id,model_key,status,score,verdict,confidence,confidence_value,indicators,reason_codes,model_version,created_at&order=created_at.asc`, { service: true }),
  ]);

  const decisionsByScan = new Map();
  for (const decision of decisions || []) {
    const rows = decisionsByScan.get(decision.scan_id) || [];
    rows.push(decision);
    decisionsByScan.set(decision.scan_id, rows);
  }
  const evidenceByScan = new Map();
  for (const item of evidence || []) {
    const rows = evidenceByScan.get(item.scan_id) || [];
    rows.push(item);
    evidenceByScan.set(item.scan_id, rows);
  }

  return scans.map((scan) => normalizeGatewayScan(
    scan,
    decisionsByScan.get(scan.id) || [],
    evidenceByScan.get(scan.id) || [],
  ));
}

const CASE_STATUSES = new Set(['open', 'in_review', 'decided', 'closed']);
const CASE_PRIORITIES = new Set(['low', 'normal', 'high', 'urgent']);
const CASE_OUTCOMES = new Set(['safe', 'suspicious', 'malicious', 'manipulated', 'inconclusive']);
const CASE_WRITE_ROLES = new Set(['owner', 'admin', 'analyst']);

function caseWriteAccess(context) {
  if (!CASE_WRITE_ROLES.has(String(context?.role || '').toLowerCase())) {
    throw new SupabaseError(403, 'Analyst access is required for case decisions.', null, 'CASE_ANALYST_REQUIRED');
  }
}

function uuid(value, fieldName = 'ID') {
  const normalized = String(value || '').trim().toLowerCase();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(normalized)) {
    throw new SupabaseError(400, `${fieldName} is invalid.`, null, 'INVALID_INPUT');
  }
  return normalized;
}

function caseSource(row) {
  if (row.standard_scan_id) return { kind: 'scan', id: row.standard_scan_id };
  return { kind: 'gateway', id: row.gateway_scan_id };
}

async function listCases(context, options = {}) {
  requireServiceRole();
  const limit = Math.max(1, Math.min(100, Number(options.limit) || 50));
  const status = String(options.status || '').toLowerCase();
  const priority = String(options.priority || '').toLowerCase();
  const assigned = String(options.assigned || '').toLowerCase();
  const filters = [
    `org_id=eq.${eq(context.organization.id)}`,
    `select=id,display_id,org_id,standard_scan_id,gateway_scan_id,created_by,assigned_to,title,status,priority,risk_level,summary,current_decision_id,opened_at,decided_at,closed_at,created_at,updated_at`,
    'order=updated_at.desc',
    `limit=${limit}`,
  ];
  if (CASE_STATUSES.has(status)) filters.push(`status=eq.${eq(status)}`);
  if (CASE_PRIORITIES.has(priority)) filters.push(`priority=eq.${eq(priority)}`);
  if (assigned === 'me') filters.push(`assigned_to=eq.${eq(context.user.id)}`);
  if (assigned === 'unassigned') filters.push('assigned_to=is.null');

  let rows = await supabaseFetch(`/rest/v1/cases?${filters.join('&')}`, { service: true });
  rows = (rows || []).filter((row) => !row.gateway_scan_id || isModuleEnabled('gateway'));
  const standardScanIds = rows.map((row) => row.standard_scan_id).filter(Boolean);
  if (standardScanIds.length) {
    const scans = await supabaseFetch(`/rest/v1/scans?id=in.(${standardScanIds.map(eq).join(',')})&select=id,scan_type,metadata,scan_inputs(input_kind,metadata)`, { service: true });
    const enabledScanIds = new Set((scans || [])
      .filter((scan) => isScanTypeEnabled(logicalScanType(scan)))
      .map((scan) => scan.id));
    rows = rows.filter((row) => !row.standard_scan_id || enabledScanIds.has(row.standard_scan_id));
  }
  if (!rows.length) return [];
  const caseIds = rows.map((row) => eq(row.id)).join(',');
  const decisionIds = rows.map((row) => row.current_decision_id).filter(Boolean).map(eq).join(',');
  const [decisions, evidence] = await Promise.all([
    decisionIds
      ? supabaseFetch(`/rest/v1/case_decisions?id=in.(${decisionIds})&select=id,case_id,sequence,decision_kind,outcome,risk_level,rationale,decided_by,created_at`, { service: true })
      : Promise.resolve([]),
    supabaseFetch(`/rest/v1/case_evidence?case_id=in.(${caseIds})&select=id,case_id`, { service: true }),
  ]);
  const decisionsById = new Map();
  for (const decision of decisions || []) {
    decisionsById.set(decision.id, decision);
  }
  const evidenceCount = new Map();
  for (const item of evidence || []) {
    evidenceCount.set(item.case_id, (evidenceCount.get(item.case_id) || 0) + 1);
  }
  return sanitizeModuleData(rows.map((row) => ({
    ...row,
    source: caseSource(row),
    current_decision: decisionsById.get(row.current_decision_id) || null,
    evidence_count: evidenceCount.get(row.id) || 0,
  })));
}

async function getCase(context, caseId) {
  requireServiceRole();
  const targetCaseId = uuid(caseId, 'Case ID');
  const rows = await supabaseFetch(`/rest/v1/cases?id=eq.${eq(targetCaseId)}&org_id=eq.${eq(context.organization.id)}&select=*`, { service: true });
  const caseRow = rows?.[0] || null;
  if (!caseRow) throw new SupabaseError(404, 'Case was not found.', null, 'CASE_NOT_FOUND');
  if (caseRow.gateway_scan_id && !isModuleEnabled('gateway')) {
    throw new SupabaseError(404, 'Case was not found.', null, 'CASE_NOT_FOUND');
  }
  if (caseRow.standard_scan_id) {
    const scans = await supabaseFetch(`/rest/v1/scans?id=eq.${eq(caseRow.standard_scan_id)}&select=id,scan_type,metadata,scan_inputs(input_kind,metadata)&limit=1`, { service: true });
    if (!scans?.[0] || !isScanTypeEnabled(logicalScanType(scans[0]))) {
      throw new SupabaseError(404, 'Case was not found.', null, 'CASE_NOT_FOUND');
    }
  }
  const [evidence, decisions, events] = await Promise.all([
    supabaseFetch(`/rest/v1/case_evidence?case_id=eq.${eq(targetCaseId)}&select=id,case_id,source_type,source_id,evidence_type,title,summary,verdict,confidence,risk_level,indicators,provenance,created_at&order=created_at.asc`, { service: true }),
    supabaseFetch(`/rest/v1/case_decisions?case_id=eq.${eq(targetCaseId)}&select=id,case_id,sequence,decision_kind,outcome,risk_level,rationale,evidence_ids,source_type,source_id,decided_by,created_at&order=sequence.asc`, { service: true }),
    supabaseFetch(`/rest/v1/case_events?case_id=eq.${eq(targetCaseId)}&select=id,event_type,actor_id,event_data,created_at&order=created_at.asc&limit=200`, { service: true }),
  ]);
  return sanitizeModuleData({
    ...caseRow,
    source: caseSource(caseRow),
    evidence: evidence || [],
    decisions: decisions || [],
    events: events || [],
  });
}

async function recordCaseDecision(context, caseId, input = {}) {
  requireServiceRole();
  caseWriteAccess(context);
  const targetCaseId = uuid(caseId, 'Case ID');
  const outcome = String(input.outcome || '').toLowerCase();
  if (!CASE_OUTCOMES.has(outcome)) {
    throw new SupabaseError(400, 'Select a valid analyst outcome.', null, 'INVALID_INPUT');
  }
  const rationale = String(input.rationale || '').trim();
  if (rationale.length < 4 || rationale.length > 8000) {
    throw new SupabaseError(400, 'Decision rationale must contain 4 to 8000 characters.', null, 'INVALID_INPUT');
  }
  const evidenceIds = [...new Set((Array.isArray(input.evidence_ids) ? input.evidence_ids : []).map((id) => uuid(id, 'Evidence ID')))];
  if (evidenceIds.length > 100) {
    throw new SupabaseError(400, 'Select no more than 100 evidence items.', null, 'INVALID_INPUT');
  }
  await getCase(context, targetCaseId);
  return rpc('case_record_analyst_decision', {
    target_case_id: targetCaseId,
    target_outcome: outcome,
    target_risk_level: riskLevel(input.risk_level),
    target_rationale: rationale,
    target_evidence_ids: evidenceIds,
    target_actor: context.user.id,
  }, { service: true });
}

async function updateCaseWorkflow(context, caseId, input = {}) {
  requireServiceRole();
  caseWriteAccess(context);
  const targetCaseId = uuid(caseId, 'Case ID');
  const current = await getCase(context, targetCaseId);
  const status = String(input.status || current.status || '').toLowerCase();
  const priority = String(input.priority || current.priority || '').toLowerCase();
  if (!CASE_STATUSES.has(status) || !CASE_PRIORITIES.has(priority)) {
    throw new SupabaseError(400, 'Case status or priority is invalid.', null, 'INVALID_INPUT');
  }
  let assignedTo = current.assigned_to || null;
  if (Object.prototype.hasOwnProperty.call(input, 'assigned_to')) {
    assignedTo = input.assigned_to ? uuid(input.assigned_to, 'Assignee ID') : null;
  }
  return rpc('case_update_workflow', {
    target_case_id: targetCaseId,
    target_status: status,
    target_priority: priority,
    target_assigned_to: assignedTo,
    target_actor: context.user.id,
  }, { service: true });
}

async function countRows(path, accessToken) {
  const rows = await supabaseFetch(path, {
    accessToken,
    headers: {
      Prefer: 'count=exact',
    },
  });
  return Array.isArray(rows) ? rows.length : 0;
}

async function workspaceStats(context) {
  const orgId = context.organization.id;
  const today = new Date().toISOString().slice(0, 10);
  const stats = {
    member_count: null,
    api_key_count: null,
    usage_today: {
      deepfake_count: 0,
      link_count: 0,
      phishing_count: 0,
      api_count: 0,
    },
  };

  try {
    stats.member_count = await countRows(`/rest/v1/organization_members?org_id=eq.${eq(orgId)}&status=eq.active&select=user_id`, context.token);
  } catch {
    stats.member_count = null;
  }

  try {
    stats.api_key_count = await countRows(`/rest/v1/api_keys?org_id=eq.${eq(orgId)}&status=eq.active&select=id`, context.token);
  } catch {
    stats.api_key_count = null;
  }

  try {
    const usageRows = await supabaseFetch(`/rest/v1/user_usage_daily?org_id=eq.${eq(orgId)}&user_id=eq.${eq(context.user.id)}&usage_date=eq.${today}&select=deepfake_count,phishing_count,link_count,api_count`, {
      accessToken: context.token,
    });
    if (usageRows?.[0]) {
      stats.usage_today = {
        deepfake_count: Number(usageRows[0].deepfake_count || 0),
        link_count: Number(usageRows[0].link_count || 0),
        phishing_count: Number(usageRows[0].phishing_count || 0),
        api_count: Number(usageRows[0].api_count || 0),
      };
    }
  } catch {
    stats.usage_today = {
      deepfake_count: 0,
      link_count: 0,
      phishing_count: 0,
      api_count: 0,
    };
  }

  return stats;
}

module.exports = {
  SupabaseError,
  bearerToken,
  completeScanRecord,
  createScanRecord,
  dashboardSnapshot,
  eq,
  failScanRecord,
  getUserFromRequest,
  getProfileContext,
  getCase,
  isServiceRoleConfigured,
  isSupabaseConfigured,
  recentScans,
  listCases,
  recordCaseDecision,
  requireServiceRole,
  riskLevel,
  runScanLifecycle,
  scanIdempotencyKey,
  serviceRoleKey,
  supabaseFetch,
  textHash,
  updateCaseWorkflow,
  workspaceStats,
};
