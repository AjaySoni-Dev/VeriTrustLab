const {
  normalizeScopes,
  requireApiKey,
} = require('../api-keys');
const {
  eq,
  getProfileContext,
  requireServiceRole,
  supabaseFetch,
} = require('../supabase-server');
const { HttpError } = require('../veritrust-api');
const { resolveModelContract } = require('../model-contracts');
const { persistenceArtifact } = require('./extractor');

function bearer(req) {
  const header = req.headers.authorization || req.headers.Authorization || '';
  const match = String(header).match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : '';
}

function gatewayApiKeyBearer(req) {
  const token = bearer(req);
  return token.startsWith('vtg_') ? token : '';
}

function includesAction(integration, action) {
  return Array.isArray(integration?.allowed_actions) && integration.allowed_actions.includes(action);
}

async function ensureApiKeyIntegration(auth) {
  const existing = await supabaseFetch(`/rest/v1/gateway_integrations?api_key_id=eq.${eq(auth.row.id)}&org_id=eq.${eq(auth.row.org_id)}&status=eq.active&select=*&limit=1`, { service: true });
  if (existing?.[0]) return existing[0];
  const allowedActions = normalizeScopes(auth.row.scopes).filter((scope) => scope.startsWith('gateway:'));
  if (!allowedActions.length) throw new HttpError(403, 'API key has no gateway permissions.', { code: 'INSUFFICIENT_SCOPE' });
  const rows = await supabaseFetch('/rest/v1/gateway_integrations?on_conflict=api_key_id&select=*', {
    method: 'POST',
    service: true,
    body: {
      org_id: auth.row.org_id,
      api_key_id: auth.row.id,
      name: `API key: ${String(auth.row.name || auth.row.key_prefix || auth.row.id).slice(0, 100)}`,
      source_type: 'api',
      auth_mode: 'api_key',
      external_id: `api-key:${auth.row.id}`,
      allowed_actions: allowedActions,
      status: 'active',
      created_by: auth.row.user_id || auth.row.created_by || null,
      metadata: { managed_by: 'gateway-api' },
    },
    headers: { Prefer: 'resolution=merge-duplicates,return=representation' },
  });
  return rows?.[0];
}

async function ensureDashboardIntegration(context) {
  const orgId = context.organization.id;
  if (context.organization.gateway_enabled === false) {
    throw new HttpError(403, 'Gateway is disabled for this workspace.', { code: 'GATEWAY_DISABLED' });
  }

  const path = `/rest/v1/gateway_integrations?org_id=eq.${eq(orgId)}&source_type=eq.dashboard&external_id=eq.${eq(`dashboard:${orgId}`)}&auth_mode=eq.supabase_jwt&status=eq.active&select=*&limit=1`;
  const existing = await supabaseFetch(path, { service: true });
  if (existing?.[0]) return existing[0];

  try {
    const rows = await supabaseFetch('/rest/v1/gateway_integrations?select=*', {
      method: 'POST',
      service: true,
      body: {
        org_id: orgId,
        name: 'VeriTrust Dashboard',
        source_type: 'dashboard',
        auth_mode: 'supabase_jwt',
        external_id: `dashboard:${orgId}`,
        allowed_actions: ['gateway:scan', 'gateway:read', 'gateway:cancel'],
        status: 'active',
        created_by: context.user?.id || null,
        metadata: { managed_by: 'gateway-dashboard', auto_provisioned: true },
      },
      headers: { Prefer: 'return=representation' },
    });
    if (rows?.[0]) return rows[0];
  } catch (error) {
    // Concurrent first-use requests can race on the existing unique
    // (org_id, source_type, external_id) index. Re-read the winning row.
    if (![409, 422].includes(Number(error?.status))) throw error;
  }

  const winner = await supabaseFetch(path, { service: true });
  if (!winner?.[0]) {
    throw new HttpError(503, 'Dashboard gateway integration could not be provisioned.', { code: 'GATEWAY_INTEGRATION_UNAVAILABLE' });
  }
  return winner[0];
}

async function authenticate(req, requiredAction) {
  requireServiceRole();
  if (gatewayApiKeyBearer(req)) {
    const auth = await requireApiKey(req, requiredAction);
    const integration = await ensureApiKeyIntegration(auth);
    if (!includesAction(integration, requiredAction)) throw new HttpError(403, 'Integration is not allowed to perform this gateway action.', { code: 'INTEGRATION_ACTION_DENIED' });
    return {
      kind: 'api_key',
      organization: auth.organization,
      user: auth.user,
      apiKeyId: auth.row.id,
      integration,
      apiAuth: auth,
    };
  }

  const context = await getProfileContext(req);
  const integrations = await supabaseFetch(`/rest/v1/gateway_integrations?org_id=eq.${eq(context.organization.id)}&auth_mode=eq.supabase_jwt&status=eq.active&select=*&order=created_at.asc&limit=1`, { service: true });
  const integration = integrations?.[0] || await ensureDashboardIntegration(context);
  const managementAllowed = ['owner', 'admin'].includes(String(context.role))
    && ['gateway:policy:read', 'gateway:policy:write', 'gateway:webhook:manage'].includes(requiredAction);
  if (!integration || (!includesAction(integration, requiredAction) && !managementAllowed)) {
    throw new HttpError(403, 'No active dashboard integration allows this gateway action.', { code: 'INTEGRATION_ACTION_DENIED' });
  }
  return {
    kind: 'user',
    organization: context.organization,
    user: context.user,
    apiKeyId: null,
    integration,
    token: context.token,
    role: context.role,
  };
}

async function resolveIntegration(auth, requestedId, requiredAction) {
  if (!requestedId || requestedId === auth.integration.id) return auth.integration;
  if (auth.kind === 'api_key') throw new HttpError(403, 'API keys cannot select a different integration.', { code: 'INTEGRATION_ACTION_DENIED' });
  const rows = await supabaseFetch(`/rest/v1/gateway_integrations?id=eq.${eq(requestedId)}&org_id=eq.${eq(auth.organization.id)}&status=eq.active&select=*&limit=1`, { service: true });
  const integration = rows?.[0];
  if (!integration || !includesAction(integration, requiredAction)) throw new HttpError(403, 'Selected integration is unavailable or not permitted.', { code: 'INTEGRATION_ACTION_DENIED' });
  return integration;
}

async function activePolicyVersionId(orgId, policyId) {
  if (!policyId) return null;
  const rows = await supabaseFetch(`/rest/v1/gateway_policies?id=eq.${eq(policyId)}&org_id=eq.${eq(orgId)}&status=eq.active&select=active_version_id&limit=1`, { service: true });
  if (!rows?.[0]?.active_version_id) throw new HttpError(404, 'Active gateway policy was not found.', { code: 'GATEWAY_POLICY_NOT_FOUND' });
  return rows[0].active_version_id;
}

async function submitScan(input) {
  const rows = await supabaseFetch('/rest/v1/rpc/gateway_submit_scan', {
    method: 'POST',
    service: true,
    body: {
      target_org_id: input.orgId,
      target_integration_id: input.integrationId,
      target_idempotency_key: input.idempotencyKey,
      target_request_hash: input.requestHash,
      target_api_key_id: input.apiKeyId || null,
      target_submitted_by: input.submittedBy || null,
      target_processing_mode: input.processingMode,
      target_source: input.source,
      target_external_event_id: input.externalEventId || null,
      target_request_id: input.requestId,
      target_trace_id: input.traceId,
      target_policy_version_id: input.policyVersionId || null,
      target_deadline_at: input.deadlineAt,
      target_metadata: input.metadata || {},
    },
  });
  return Array.isArray(rows) ? rows[0] : rows;
}

async function getPolicyVersion(id, orgId) {
  const rows = await supabaseFetch(`/rest/v1/gateway_policy_versions?id=eq.${eq(id)}&org_id=eq.${eq(orgId)}&validation_status=eq.valid&select=*&limit=1`, { service: true });
  if (!rows?.[0]) throw new HttpError(500, 'The selected gateway policy version is unavailable.', { code: 'GATEWAY_POLICY_UNAVAILABLE' });
  return rows[0];
}

async function createArtifacts(orgId, scanId, artifacts) {
  const existing = await supabaseFetch(`/rest/v1/gateway_artifacts?scan_id=eq.${eq(scanId)}&org_id=eq.${eq(orgId)}&select=*&order=ordinal.asc`, { service: true });
  if (existing?.length) {
    const byOrdinal = new Map(existing.map((row) => [Number(row.ordinal), row]));
    return artifacts.map((artifact) => ({ ...artifact, id: byOrdinal.get(artifact.ordinal)?.id }));
  }
  const rows = await supabaseFetch('/rest/v1/gateway_artifacts?select=*', {
    method: 'POST',
    service: true,
    body: artifacts.map((artifact) => ({ org_id: orgId, scan_id: scanId, ...persistenceArtifact(artifact) })),
    headers: { Prefer: 'return=representation' },
  });
  const byOrdinal = new Map((rows || []).map((row) => [Number(row.ordinal), row]));
  return artifacts.map((artifact) => ({ ...artifact, id: byOrdinal.get(artifact.ordinal)?.id }));
}

async function claimScan(orgId, scanId) {
  const rows = await supabaseFetch(`/rest/v1/gateway_scans?id=eq.${eq(scanId)}&org_id=eq.${eq(orgId)}&status=eq.accepted&select=*`, {
    method: 'PATCH',
    service: true,
    body: { status: 'processing', started_at: new Date().toISOString() },
    headers: { Prefer: 'return=representation' },
  });
  return rows?.[0] || null;
}

async function completeArtifacts(orgId, scanId) {
  return supabaseFetch(`/rest/v1/gateway_artifacts?scan_id=eq.${eq(scanId)}&org_id=eq.${eq(orgId)}&status=in.(ready,processing)&select=id`, {
    method: 'PATCH',
    service: true,
    body: { status: 'completed' },
    headers: { Prefer: 'return=representation' },
  });
}

async function completeArtifact(orgId, scanId, artifactId) {
  return supabaseFetch(`/rest/v1/gateway_artifacts?id=eq.${eq(artifactId)}&scan_id=eq.${eq(scanId)}&org_id=eq.${eq(orgId)}&select=id`, {
    method: 'PATCH', service: true, body: { status: 'completed' }, headers: { Prefer: 'return=representation' },
  });
}

async function uploadsForSubmission(orgId, uploadIds) {
  if (!uploadIds.length) return [];
  const filter = uploadIds.map((id) => `\"${String(id).replace(/\"/g, '')}\"`).join(',');
  const rows = await supabaseFetch(`/rest/v1/gateway_uploads?org_id=eq.${eq(orgId)}&id=in.(${filter})&status=eq.uploaded&select=*`, { service: true });
  if ((rows || []).length !== new Set(uploadIds).size) throw new HttpError(400, 'One or more media uploads are missing, expired, or already attached.', { code: 'UPLOAD_NOT_READY' });
  return rows;
}

async function attachUpload(uploadId, scanId, artifactId, finalPath) {
  const result = await supabaseFetch('/rest/v1/rpc/gateway_attach_upload', {
    method: 'POST', service: true, body: {
      target_upload_id: uploadId, target_scan_id: scanId, target_artifact_id: artifactId, target_final_path: finalPath,
    },
  });
  if (!(Array.isArray(result) ? result[0] : result)) throw new HttpError(409, 'Upload attachment state changed.', { code: 'UPLOAD_STATE_CONFLICT' });
  return true;
}

async function prepareUploadAttachment(uploadId, scanId, artifactId, finalPath) {
  const result = await supabaseFetch('/rest/v1/rpc/gateway_prepare_upload_attachment', {
    method: 'POST', service: true, body: {
      target_upload_id: uploadId, target_scan_id: scanId, target_artifact_id: artifactId, target_final_path: finalPath,
    },
  });
  if (!(Array.isArray(result) ? result[0] : result)) throw new HttpError(409, 'Upload could not be prepared for attachment.', { code: 'UPLOAD_STATE_CONFLICT' });
  return true;
}

async function enqueueJob(input) {
  const result = await supabaseFetch('/rest/v1/rpc/gateway_enqueue_job', {
    method: 'POST', service: true, body: {
      target_org_id: input.orgId, target_scan_id: input.scanId, target_job_type: input.jobType,
      target_dedupe_key: input.dedupeKey, target_artifact_id: input.artifactId || null,
      target_payload: input.payload || {}, target_priority: input.priority || 100,
      target_available_at: input.availableAt || new Date().toISOString(), target_max_attempts: input.maxAttempts || 5,
    },
  });
  return Array.isArray(result) ? result[0] : result;
}

async function failScan(orgId, scanId, error) {
  return supabaseFetch(`/rest/v1/gateway_scans?id=eq.${eq(scanId)}&org_id=eq.${eq(orgId)}&status=in.(accepted,queued,processing,partially_completed)&select=id`, {
    method: 'PATCH',
    service: true,
    body: {
      status: 'failed',
      failure_code: String(error?.code || 'GATEWAY_ORCHESTRATION_FAILED').slice(0, 120),
      failure_detail: { error_code: String(error?.code || 'GATEWAY_ORCHESTRATION_FAILED').slice(0, 120) },
      completed_at: new Date().toISOString(),
    },
    headers: { Prefer: 'return=representation' },
  });
}

function orderedModelVersions(rows, orgId = null) {
  const rolloutPriority = { active: 2, canary: 1 };
  return [...(rows || [])].sort((left, right) => {
    const leftTenant = orgId && left.org_id === orgId ? 1 : 0;
    const rightTenant = orgId && right.org_id === orgId ? 1 : 0;
    if (leftTenant !== rightTenant) return rightTenant - leftTenant;
    const rolloutDifference = (rolloutPriority[right.rollout_status] || 0) - (rolloutPriority[left.rollout_status] || 0);
    if (rolloutDifference) return rolloutDifference;
    return Date.parse(right.created_at || 0) - Date.parse(left.created_at || 0);
  });
}

async function modelVersion(orgId, modelKey, artifactType) {
  const path = `/rest/v1/gateway_model_versions?model_key=eq.${eq(modelKey)}&rollout_status=in.(active,canary)&or=(org_id.is.null,org_id.eq.${eq(orgId)})&select=*&order=created_at.desc`;
  const rows = await supabaseFetch(path, { service: true });
  const ordered = orderedModelVersions(rows, orgId);
  const selected = ordered.find((row) => Array.isArray(row.supported_artifacts) && row.supported_artifacts.includes(artifactType));
  if (!selected) throw new HttpError(503, `No active model version is available for ${modelKey}.`, { code: 'GATEWAY_MODEL_UNAVAILABLE' });
  return selected;
}

async function modelRegistryHealth() {
  const rows = await supabaseFetch(
    '/rest/v1/gateway_model_versions?model_key=in.(mailguard,swift)&rollout_status=in.(active,canary)'
      + '&select=model_key,version,provider,rollout_status,supported_artifacts,configuration,org_id,created_at'
      + '&order=created_at.desc',
    { service: true },
  );
  const requirements = { mailguard: 'email', swift: 'url' };
  return Object.fromEntries(Object.entries(requirements).map(([modelKey, artifactType]) => {
    const candidates = orderedModelVersions((rows || []).filter((row) => row.model_key === modelKey));
    const checks = candidates.map((row) => {
      if (!Array.isArray(row.supported_artifacts) || !row.supported_artifacts.includes(artifactType)) {
        return { usable: false, code: 'GATEWAY_MODEL_ARTIFACT_UNSUPPORTED', scope: row.org_id ? 'organization' : 'global' };
      }
      try {
        const resolved = qualifiedModelConfiguration(row);
        if (String(row.provider || '').toLowerCase() !== resolved.contract.provider) {
          return { usable: false, code: 'GATEWAY_MODEL_PROVIDER_MISMATCH', scope: row.org_id ? 'organization' : 'global' };
        }
        return {
          usable: true,
          source: resolved.source,
          qualification_state: resolved.contract.qualification_state,
          scope: row.org_id ? 'organization' : 'global',
        };
      } catch (error) {
        return { usable: false, code: error.code || 'GATEWAY_MODEL_CONTRACT_INVALID', scope: row.org_id ? 'organization' : 'global' };
      }
    });
    const globalChecks = checks.filter((_, index) => !candidates[index]?.org_id);
    const selectedGlobal = globalChecks[0] || null;
    return [modelKey, {
      ready: Boolean(selectedGlobal?.usable),
      required_artifact: artifactType,
      active_candidate_count: candidates.length,
      usable_candidate_count: checks.filter((item) => item.usable).length,
      selected_global: selectedGlobal,
      tenant_override_count: candidates.filter((item) => item.org_id).length,
      invalid_tenant_override_count: checks.filter((item, index) => candidates[index]?.org_id && !item.usable).length,
      checks,
    }];
  }));
}

function qualifiedModelConfiguration(version) {
  try {
    return resolveModelContract(version?.model_key, version?.configuration, {
      source: 'database',
      allowEnvironmentFallback: true,
      requireRuntimeMatch: true,
    });
  } catch (error) {
    const codeMap = {
      MODEL_CONTRACT_UNRESOLVED: 'GATEWAY_MODEL_CONTRACT_UNRESOLVED',
      MODEL_CONTRACT_MISSING_FOR_CONFIGURED_PATH: 'GATEWAY_MODEL_CONTRACT_UNRESOLVED',
      MODEL_IDENTITY_UNRESOLVED: 'GATEWAY_MODEL_IDENTITY_UNRESOLVED',
      MODEL_IDENTITY_MISMATCH: 'GATEWAY_MODEL_IDENTITY_MISMATCH',
      MODEL_RUNTIME_REGISTRY_MISMATCH: 'GATEWAY_MODEL_RUNTIME_REGISTRY_MISMATCH',
      MODEL_NOT_QUALIFIED: 'GATEWAY_MODEL_NOT_QUALIFIED',
    };
    throw new HttpError(503, error.message, { code: codeMap[error.code] || error.code || 'GATEWAY_MODEL_CONTRACT_INVALID' });
  }
}

async function prepareModelRun(orgId, scanId, artifact, modelKey) {
  const version = await modelVersion(orgId, modelKey, artifact.type);
  const resolved = qualifiedModelConfiguration(version);
  const configuration = resolved.contract;
  if (String(version.provider || '').toLowerCase() !== configuration.provider) {
    throw new HttpError(503, `Model provider metadata is inconsistent for ${version.model_key}.`, { code: 'GATEWAY_MODEL_PROVIDER_MISMATCH' });
  }
  // Do not send a client-clock started_at. PostgreSQL owns created_at, and the
  // timestamp-guard trigger initializes started_at from that same database
  // value. Without the trigger, NULL is still valid and cannot block inference.
  const rows = await supabaseFetch('/rest/v1/gateway_model_runs?select=*', {
    method: 'POST',
    service: true,
    body: {
      org_id: orgId,
      scan_id: scanId,
      artifact_id: artifact.id,
      model_version_id: version.id,
      model_key: version.model_key,
      status: 'running',
      provider: version.provider,
      provider_model_version: `${configuration.repository_id}@${configuration.revision_sha}`,
      calibration_version: version.calibration_version,
      preprocessing_version: version.preprocessing_version,
      metrics: {
        registry_resolved_before_inference: true,
        registry_schema: configuration.registry_schema,
        registry_source: resolved.source,
        module_contract_version: 'veritrust-module-command-1',
        module_key: modelKey === 'swift' ? 'link' : (modelKey === 'mailguard' ? 'phishing' : modelKey),
        module_execution_mode: modelKey === 'swift' ? 'single_consumer_queue' : 'direct_internal',
        runtime_source: 'bundled-pinned',
      },
    },
    headers: { Prefer: 'return=representation' },
  });
  return { run: rows?.[0], version, configuration, configurationSource: resolved.source };
}

async function recordEvidence(orgId, scanId, artifact, evidence, prepared = null) {
  const resolved = prepared || await prepareModelRun(orgId, scanId, artifact, evidence.modelKey);
  const { run, version } = resolved;
  const result = await supabaseFetch('/rest/v1/rpc/gateway_record_evidence', {
    method: 'POST',
    service: true,
    body: {
      target_model_run_id: run.id,
      target_status: evidence.status,
      target_score: evidence.score,
      target_verdict: evidence.verdict,
      target_confidence: evidence.confidence,
      target_confidence_value: evidence.confidenceValue,
      target_indicators: evidence.indicators || [],
      target_reason_codes: evidence.reasonCodes || [],
      target_raw_response_redacted: evidence.rawResponseRedacted || {},
    },
  });
  const id = Array.isArray(result) ? result[0] : result;
  if (['failed', 'timed_out'].includes(evidence.status)) {
    await supabaseFetch(`/rest/v1/gateway_model_runs?id=eq.${eq(run.id)}&org_id=eq.${eq(orgId)}&scan_id=eq.${eq(scanId)}&select=id`, {
      method: 'PATCH',
      service: true,
      body: {
        error_code: String(evidence.errorCode || 'MODEL_EXECUTION_FAILED').slice(0, 120),
        error_detail: {
          error_code: String(evidence.errorCode || 'MODEL_EXECUTION_FAILED').slice(0, 120),
          upstream_status: Number(evidence.rawResponseRedacted?.upstream_status) || null,
          stage: evidence.rawResponseRedacted?.stage || null,
          runtime_error_name: evidence.rawResponseRedacted?.runtime_error_name || null,
          module_contract_version: evidence.rawResponseRedacted?.module_contract_version || null,
          module_correlation_id: evidence.rawResponseRedacted?.module_correlation_id || null,
        },
      },
      headers: { Prefer: 'return=minimal' },
    });
  }
  return { ...evidence, id, modelVersionId: version.id, modelVersion: version.version, calibrationVersion: version.calibration_version };
}

async function publishDecision(scanId, decision, createdBy) {
  const keyMaterial = `${decision.decision_state}:${decision.correlation_version}:${decision.evidence_ids.join(',')}:${decision.risk}:${decision.recommendation}`;
  const decisionKey = require('crypto').createHash('sha256').update(keyMaterial).digest('hex');
  const result = await supabaseFetch('/rest/v1/rpc/gateway_publish_decision', {
    method: 'POST',
    service: true,
    body: {
      target_scan_id: scanId,
      target_decision_key: decisionKey,
      target_decision_kind: decision.decision_state,
      target_risk_score: decision.risk,
      target_verdict: decision.verdict,
      target_recommendation: decision.recommendation,
      target_degraded: decision.degraded,
      target_reason_codes: decision.reason_codes,
      target_evidence_ids: decision.evidence_ids,
      target_correlation_version: decision.correlation_version,
      target_created_by: createdBy || null,
      target_create_review: decision.manual_review_required,
    },
  });
  return Array.isArray(result) ? result[0] : result;
}

async function storeIdempotentResponse(scanId, status, body) {
  return supabaseFetch('/rest/v1/rpc/gateway_store_idempotent_response', {
    method: 'POST',
    service: true,
    body: { target_scan_id: scanId, target_response_status: status, target_response_body: body },
  });
}

async function scanReport(orgId, scanId) {
  const scanRows = await supabaseFetch(`/rest/v1/gateway_scans?id=eq.${eq(scanId)}&org_id=eq.${eq(orgId)}&select=*&limit=1`, { service: true });
  const scan = scanRows?.[0];
  if (!scan) throw new HttpError(404, 'Gateway scan was not found.', { code: 'GATEWAY_SCAN_NOT_FOUND' });
  const [artifacts, runs, evidence, decisions, reviews] = await Promise.all([
    supabaseFetch(`/rest/v1/gateway_artifacts?scan_id=eq.${eq(scanId)}&org_id=eq.${eq(orgId)}&select=*&order=ordinal.asc`, { service: true }),
    supabaseFetch(`/rest/v1/gateway_model_runs?scan_id=eq.${eq(scanId)}&org_id=eq.${eq(orgId)}&select=*&order=created_at.asc`, { service: true }),
    supabaseFetch(`/rest/v1/gateway_evidence?scan_id=eq.${eq(scanId)}&org_id=eq.${eq(orgId)}&select=*&order=created_at.asc`, { service: true }),
    supabaseFetch(`/rest/v1/gateway_decisions?scan_id=eq.${eq(scanId)}&org_id=eq.${eq(orgId)}&select=*&order=sequence.asc`, { service: true }),
    supabaseFetch(`/rest/v1/gateway_review_cases?scan_id=eq.${eq(scanId)}&org_id=eq.${eq(orgId)}&select=*&order=created_at.asc`, { service: true }),
  ]);
  return { scan, artifacts, model_runs: runs, evidence, decisions, review_cases: reviews };
}

async function listScans(orgId, options = {}) {
  const limit = Math.max(1, Math.min(100, Number(options.limit) || 20));
  return supabaseFetch(`/rest/v1/gateway_scans?org_id=eq.${eq(orgId)}&select=id,display_id,status,processing_mode,source,degraded,created_at,completed_at,preliminary_decision_id,final_decision_id&order=created_at.desc&limit=${limit}`, { service: true });
}

async function cancelScan(orgId, scanId) {
  await scanReport(orgId, scanId);
  const result = await supabaseFetch('/rest/v1/rpc/gateway_request_cancel', {
    method: 'POST',
    service: true,
    body: { target_scan_id: scanId },
  });
  return Array.isArray(result) ? result[0] : result;
}

module.exports = {
  activePolicyVersionId,
  attachUpload,
  authenticate,
  cancelScan,
  claimScan,
  completeArtifact,
  completeArtifacts,
  createArtifacts,
  enqueueJob,
  failScan,
  gatewayApiKeyBearer,
  getPolicyVersion,
  listScans,
  modelRegistryHealth,
  orderedModelVersions,
  publishDecision,
  prepareUploadAttachment,
  prepareModelRun,
  qualifiedModelConfiguration,
  recordEvidence,
  resolveIntegration,
  scanReport,
  storeIdempotentResponse,
  submitScan,
  uploadsForSubmission,
};
