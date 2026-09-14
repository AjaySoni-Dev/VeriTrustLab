const { HttpError } = require('./veritrust-api');
const {
  eq,
  requireServiceRole,
  supabaseFetch,
} = require('./supabase-server');
const { createSignedDownload } = require('./gateway/storage');

function rpc(name, body, options = {}) {
  return supabaseFetch(`/rest/v1/rpc/${name}`, {
    method: 'POST',
    body,
    service: Boolean(options.service),
    accessToken: options.accessToken,
  });
}

function requireWorkspaceAdmin(context) {
  if (!['owner', 'admin'].includes(String(context?.role || '').toLowerCase())) {
    throw new HttpError(403, 'Workspace administrator access is required.', {
      code: 'WORKSPACE_ADMIN_REQUIRED',
    });
  }
}

async function listDataRightsRequests(context) {
  requireServiceRole();
  const rows = await supabaseFetch(
    `/rest/v1/data_rights_requests?org_id=eq.${eq(context.organization.id)}`
      + `&or=(requester_user_id.eq.${eq(context.user.id)},subject_user_id.eq.${eq(context.user.id)})`
      + '&select=id,display_id,request_type,status,verification_status,due_at,job_id,result_bucket,result_path,result_sha256,result_expires_at,failure_code,created_at,updated_at,completed_at,cancelled_at'
      + '&order=created_at.desc&limit=50',
    { service: true },
  );

  return Promise.all((rows || []).map(async (row) => {
    const expiresAt = row.result_expires_at ? Date.parse(row.result_expires_at) : 0;
    if (row.status !== 'completed' || !row.result_bucket || !row.result_path || expiresAt <= Date.now()) {
      return { ...row, download_url: null };
    }
    try {
      const signed = await createSignedDownload(row.result_bucket, row.result_path, 300);
      return { ...row, download_url: signed?.signedURL || signed?.signedUrl || signed?.signed_url || null };
    } catch {
      return { ...row, download_url: null };
    }
  }));
}

async function privacyPolicy(context) {
  requireServiceRole();
  const rows = await supabaseFetch(
    `/rest/v1/privacy_policies?org_id=eq.${eq(context.organization.id)}`
      + '&select=raw_artifact_retention_hours,scan_metadata_retention_days,billing_event_payload_days,operational_event_days,export_expiry_hours,request_due_days,billing_minimization_enabled,retention_enforcement_enabled,policy_version,approved_at&limit=1',
    { service: true },
  );
  const policy = rows?.[0] || null;
  if (!policy) throw new HttpError(503, 'Workspace privacy policy is not provisioned.', { code: 'PRIVACY_POLICY_MISSING' });
  return policy;
}

async function requestDataRightsAction(context, requestType, scope = {}) {
  const normalizedType = String(requestType || '').trim().toLowerCase();
  if (!['export', 'erasure'].includes(normalizedType)) {
    throw new HttpError(400, 'Choose export or erasure.', { code: 'INVALID_DATA_RIGHTS_TYPE' });
  }
  if (!scope || typeof scope !== 'object' || Array.isArray(scope)) {
    throw new HttpError(400, 'Data-rights scope must be an object.', { code: 'INVALID_DATA_RIGHTS_SCOPE' });
  }
  return rpc('request_data_rights_action', {
    target_org_id: context.organization.id,
    target_request_type: normalizedType,
    target_scope: scope,
    target_subject_user_id: context.user.id,
  }, { accessToken: context.token });
}

async function platformJobStatus(context, jobId) {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(jobId || ''))) {
    throw new HttpError(400, 'A valid job ID is required.', { code: 'INVALID_JOB_ID' });
  }
  return rpc('get_platform_job_status', { target_job_id: jobId }, { accessToken: context.token });
}

async function publishedModelCards(modelKey = null) {
  return rpc('get_published_model_cards', {
    target_model_key: modelKey || null,
  });
}

async function platformHealth() {
  requireServiceRole();
  return rpc('platform_health_snapshot', {}, { service: true });
}

async function legalHolds(context) {
  requireWorkspaceAdmin(context);
  requireServiceRole();
  return supabaseFetch(
    `/rest/v1/legal_holds?org_id=eq.${eq(context.organization.id)}&status=eq.active`
      + '&select=id,subject_type,subject_key,reason,status,placed_at,expires_at&order=placed_at.desc&limit=100',
    { service: true },
  );
}

module.exports = {
  legalHolds,
  listDataRightsRequests,
  platformHealth,
  platformJobStatus,
  privacyPolicy,
  publishedModelCards,
  requestDataRightsAction,
  requireWorkspaceAdmin,
  rpc,
};
