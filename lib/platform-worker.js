const crypto = require('crypto');
const { serverConfig } = require('./config');
const {
  completeScanRecord,
  eq,
  failScanRecord,
  supabaseFetch,
} = require('./supabase-server');
const { runDeepfakeDetection, runLinkDetection, runPhishingDetection } = require('./detection-service');
const { deleteObject, downloadObject, uploadObject } = require('./gateway/storage');
const logger = require('./gateway/logging');

function rpc(name, body) {
  return supabaseFetch(`/rest/v1/rpc/${name}`, { method: 'POST', service: true, body });
}

async function claimPlatformJobs(workerId, limit = 5, visibilitySeconds = 240) {
  return rpc('claim_platform_jobs', {
    target_worker_id: workerId,
    target_limit: Math.max(1, Math.min(25, Number(limit) || 5)),
    target_visibility_seconds: Math.max(30, Math.min(900, Number(visibilitySeconds) || 240)),
  });
}

function heartbeatPlatformJob(job, visibilitySeconds = 240, checkpoint = null) {
  return rpc('heartbeat_platform_job', {
    target_job_id: job.job_id,
    target_lease_token: job.lease_token,
    target_visibility_seconds: visibilitySeconds,
    target_checkpoint: checkpoint,
  });
}

function completePlatformJob(job, result = {}) {
  return rpc('complete_platform_job', {
    target_job_id: job.job_id,
    target_lease_token: job.lease_token,
    target_result_summary: result,
  });
}

function failPlatformJob(job, error) {
  return rpc('fail_platform_job', {
    target_job_id: job.job_id,
    target_lease_token: job.lease_token,
    target_error_code: String(error?.code || 'PLATFORM_JOB_FAILED').slice(0, 120),
    target_error_detail: { message: String(error?.message || 'Platform job failed.').slice(0, 500) },
    target_retry_seconds: Math.max(0, Math.min(3600, Number(error?.retrySeconds) || 30)),
  });
}

function recordOperationalEvent(options) {
  return rpc('record_operational_event', {
    target_component: options.component || 'worker',
    target_operation: options.operation,
    target_outcome: options.outcome,
    target_severity: options.severity || 'info',
    target_org_id: options.orgId || null,
    target_trace_id: options.traceId || null,
    target_duration_ms: options.durationMs ?? null,
    target_provider: options.provider || null,
    target_model_key: options.modelKey || null,
    target_cost_micros: options.costMicros ?? null,
    target_error_code: options.errorCode || null,
    target_attributes: options.attributes || {},
  }).catch(() => null);
}

async function exportRows(path) {
  return supabaseFetch(path, { service: true, maxResponseBytes: 4 * 1024 * 1024, timeoutMs: 60000 });
}

async function exportPaged(path, options = {}) {
  const pageSize = Math.max(100, Math.min(2000, Number(options.pageSize) || 1000));
  const maxRows = Math.max(pageSize, Math.min(250000, Number(options.maxRows) || 100000));
  const rows = [];
  for (let offset = 0; offset < maxRows; offset += pageSize) {
    const page = await exportRows(`${path}${path.includes('?') ? '&' : '?'}limit=${pageSize}&offset=${offset}`);
    if (!Array.isArray(page)) throw Object.assign(new Error('Privacy export query returned an invalid page.'), { code: 'PRIVACY_EXPORT_INVALID_PAGE' });
    rows.push(...page);
    if (page.length < pageSize) return rows;
  }
  throw Object.assign(new Error('Privacy export exceeded the governed row limit and was not truncated.'), { code: 'PRIVACY_EXPORT_ROW_LIMIT' });
}

async function buildPrivacyExport(job) {
  const requestId = job.payload?.request_id || job.subject_id;
  const requests = await exportRows(`/rest/v1/data_rights_requests?id=eq.${eq(requestId)}&org_id=eq.${eq(job.org_id)}&select=*&limit=1`);
  const request = requests?.[0];
  if (!request) throw Object.assign(new Error('Data-rights request was not found.'), { code: 'DATA_RIGHTS_REQUEST_NOT_FOUND' });
  if (request.request_type !== 'export') throw Object.assign(new Error('The request is not an export.'), { code: 'INVALID_DATA_RIGHTS_JOB' });
  const userId = request.subject_user_id;
  await rpc('record_data_rights_result', { target_request_id: request.id, target_status: 'processing' });

  const [profile, memberships, policyRows, scans, casesCreated, caseDecisions, usage, audit] = await Promise.all([
    exportRows(`/rest/v1/profiles?id=eq.${eq(userId)}&select=id,full_name,username,avatar_url,preferences,created_at,updated_at`),
    exportRows(`/rest/v1/organization_members?org_id=eq.${eq(job.org_id)}&user_id=eq.${eq(userId)}&select=org_id,user_id,role,status,created_at,updated_at`),
    exportRows(`/rest/v1/privacy_policies?org_id=eq.${eq(job.org_id)}&select=export_expiry_hours&limit=1`),
    exportPaged(`/rest/v1/scans?org_id=eq.${eq(job.org_id)}&user_id=eq.${eq(userId)}&select=id,scan_type,status,selected_model_key,final_label,confidence,risk_level,source,metadata,created_at,started_at,completed_at,scan_inputs(input_kind,retention,text_preview,text_hash,mime_type,size_bytes,metadata,created_at),scan_results(label,confidence,risk_level,primary_score,secondary_score,explanation,indicators,created_at)&order=created_at.asc`),
    exportPaged(`/rest/v1/cases?org_id=eq.${eq(job.org_id)}&created_by=eq.${eq(userId)}&select=id,display_id,title,status,priority,risk_level,summary,opened_at,decided_at,closed_at,created_at,updated_at&order=created_at.asc`),
    exportPaged(`/rest/v1/case_decisions?org_id=eq.${eq(job.org_id)}&decided_by=eq.${eq(userId)}&select=id,case_id,sequence,decision_kind,outcome,risk_level,rationale,evidence_ids,created_at&order=created_at.asc`),
    exportPaged(`/rest/v1/usage_events?org_id=eq.${eq(job.org_id)}&user_id=eq.${eq(userId)}&select=source,scan_type,endpoint,status,units,request_id,metadata,created_at&order=created_at.asc`),
    exportPaged(`/rest/v1/audit_logs?org_id=eq.${eq(job.org_id)}&actor_user_id=eq.${eq(userId)}&select=action,target_table,target_id,metadata,created_at&order=created_at.asc`),
  ]);

  const document = {
    schema: 'veritrust.data-export.v1',
    generated_at: new Date().toISOString(),
    request: { id: request.id, display_id: request.display_id, scope: request.scope },
    subject: { user_id: userId, organization_id: job.org_id },
    data: { profile, memberships, scans, cases: casesCreated, analyst_decisions: caseDecisions, usage_events: usage, audit_events: audit },
    notices: [
      'Secrets, API-key hashes, provider credentials, internal security fields, and unrelated organization records are excluded.',
      'Storage objects are not embedded; their governed metadata is included where applicable.',
    ],
  };
  const buffer = Buffer.from(JSON.stringify(document, null, 2), 'utf8');
  if (buffer.length > 250 * 1024 * 1024) throw Object.assign(new Error('Privacy export exceeds the configured object limit.'), { code: 'PRIVACY_EXPORT_TOO_LARGE' });
  const digest = crypto.createHash('sha256').update(buffer).digest('hex');
  const path = `${job.org_id}/${userId}/${request.id}.json`;
  // The request ID makes this path deterministic. Upsert allows a worker retry to
  // finish after an upload succeeded but the database status update was interrupted.
  await uploadObject('privacy-exports', path, buffer, 'application/json', { upsert: true });
  const expiryHours = Math.max(1, Math.min(168, Number(policyRows?.[0]?.export_expiry_hours) || 24));
  const expiresAt = new Date(Date.now() + expiryHours * 60 * 60 * 1000).toISOString();
  await rpc('record_data_rights_result', {
    target_request_id: request.id,
    target_status: 'completed',
    target_result_bucket: 'privacy-exports',
    target_result_path: path,
    target_result_sha256: digest,
    target_result_expires_at: expiresAt,
  });
  return { request_id: request.id, bytes: buffer.length, sha256: digest, expires_at: expiresAt };
}

async function prepareErasureReview(job) {
  const requestId = job.payload?.request_id || job.subject_id;
  const holds = await exportRows(`/rest/v1/legal_holds?org_id=eq.${eq(job.org_id)}&status=eq.active&or=(subject_type.eq.organization,subject_type.eq.user)&select=id,subject_type,subject_key,reason,expires_at`);
  await rpc('record_data_rights_result', {
    target_request_id: requestId,
    target_status: 'awaiting_review',
    target_failure_detail: {
      automated_preflight_complete: true,
      active_hold_count: (holds || []).length,
      review_required: true,
      reason: 'Account deletion requires an authorized review of legal holds, organization-owned evidence, Auth sessions, backups, and subprocessors.',
    },
  });
  return { request_id: requestId, status: 'awaiting_review', active_hold_count: (holds || []).length };
}

async function purgeStoredFile(job) {
  const fileId = job.payload?.stored_file_id || job.subject_id;
  const rows = await exportRows(`/rest/v1/stored_files?id=eq.${eq(fileId)}&org_id=eq.${eq(job.org_id)}&select=*&limit=1`);
  const file = rows?.[0];
  if (!file) return { stored_file_id: fileId, already_absent: true };
  const holds = await exportRows(`/rest/v1/legal_holds?org_id=eq.${eq(job.org_id)}&status=eq.active&or=(and(subject_type.eq.stored_file,subject_key.eq.${eq(file.id)}),and(subject_type.eq.organization,subject_key.eq.${eq(job.org_id)}))&select=id&limit=1`);
  if (holds?.length) throw Object.assign(new Error('Retention purge is blocked by an active legal hold.'), { code: 'LEGAL_HOLD_ACTIVE', retrySeconds: 3600 });
  await deleteObject(file.bucket_id, file.object_path);
  await supabaseFetch(`/rest/v1/stored_files?id=eq.${eq(file.id)}&org_id=eq.${eq(job.org_id)}`, { method: 'DELETE', service: true });
  return { stored_file_id: file.id, object_deleted: true, metadata_deleted: true };
}

async function runAsyncScan(job) {
  const scanId = job.payload?.scan_id || job.subject_id;
  const scans = await exportRows(`/rest/v1/scans?id=eq.${eq(scanId)}&org_id=eq.${eq(job.org_id)}&select=*,scan_inputs(*)&limit=1`);
  const scan = scans?.[0];
  if (!scan) throw Object.assign(new Error('Scan was not found.'), { code: 'SCAN_NOT_FOUND' });
  if (['completed', 'failed', 'cancelled'].includes(scan.status)) return { scan_id: scan.id, status: scan.status, duplicate: true };
  const input = Array.isArray(scan.scan_inputs) ? scan.scan_inputs[0] : scan.scan_inputs;
  if (!input?.file_id) throw Object.assign(new Error('Asynchronous scan input must reference a private stored file.'), { code: 'ASYNC_SCAN_INPUT_MISSING' });
  const files = await exportRows(`/rest/v1/stored_files?id=eq.${eq(input.file_id)}&org_id=eq.${eq(job.org_id)}&select=*&limit=1`);
  const file = files?.[0];
  if (!file) throw Object.assign(new Error('Asynchronous scan input file was not found.'), { code: 'ASYNC_SCAN_FILE_MISSING' });
  const object = await downloadObject(file.bucket_id, file.object_path);
  await rpc('mark_scan_processing_atomic', { target_scan_id: scan.id, target_worker_id: serverConfig.gatewayWorkerId });
  try {
    let outcome;
    if (scan.scan_type === 'deepfake') {
      outcome = await runDeepfakeDetection({ upload: { buffer: object.buffer, mimeType: object.mimeType, size: object.buffer.length, filename: file.original_name || 'scan-image' }, modelKey: scan.selected_model_key || 'pixel', scanId: scan.id });
    } else if (scan.scan_type === 'phishing') {
      outcome = await runPhishingDetection({ text: object.buffer.toString('utf8'), modelKey: scan.selected_model_key || 'mailguard', scanId: scan.id });
    } else if (scan.scan_type === 'link') {
      outcome = await runLinkDetection({ url: object.buffer.toString('utf8').trim(), modelKey: scan.selected_model_key || 'swift', scanId: scan.id });
    } else {
      throw Object.assign(new Error('Unsupported asynchronous scan type.'), { code: 'ASYNC_SCAN_TYPE_UNSUPPORTED' });
    }
    await completeScanRecord(scan.id, outcome.payload, outcome.modelRuns || []);
    return { scan_id: scan.id, status: 'completed' };
  } catch (error) {
    await failScanRecord(scan.id, error.message).catch(() => null);
    throw error;
  }
}

const PLATFORM_HANDLERS = Object.freeze({
  'privacy.export': buildPrivacyExport,
  'privacy.erase': prepareErasureReview,
  'retention.purge': purgeStoredFile,
  'scan.inference': runAsyncScan,
  'telemetry.rollup': async () => ({ status: 'no_op', reason: 'Health metrics are calculated from indexed operational records.' }),
});

async function processPlatformQueue(workerId, options = {}) {
  const limit = Math.max(1, Math.min(10, Number(options.limit) || 5));
  const visibilitySeconds = Math.max(60, Math.min(900, Number(options.visibilitySeconds) || 240));
  const jobs = await claimPlatformJobs(workerId, limit, visibilitySeconds);
  for (const job of jobs || []) {
    const started = Date.now();
    const handler = PLATFORM_HANDLERS[job.job_type];
    let leaseLost = false;
    const heartbeat = setInterval(() => {
      heartbeatPlatformJob(job, visibilitySeconds).then((ok) => { leaseLost = !ok; }).catch(() => { leaseLost = true; });
    }, Math.max(15000, Math.floor(visibilitySeconds * 500)));
    heartbeat.unref();
    try {
      if (!handler) throw Object.assign(new Error('No worker handler is registered for this platform job.'), { code: 'PLATFORM_HANDLER_MISSING' });
      const result = await handler(job);
      if (leaseLost) throw Object.assign(new Error('The platform job lease was lost.'), { code: 'JOB_LEASE_LOST' });
      await completePlatformJob(job, result || {});
      await recordOperationalEvent({ operation: job.job_type, outcome: 'success', orgId: job.org_id, durationMs: Date.now() - started, attributes: { job_id: job.job_id } });
    } catch (error) {
      await failPlatformJob(job, error).catch(() => null);
      await recordOperationalEvent({ operation: job.job_type, outcome: 'failure', severity: 'error', orgId: job.org_id, durationMs: Date.now() - started, errorCode: error.code || 'PLATFORM_JOB_FAILED', attributes: { job_id: job.job_id } });
      logger.error('platform.job.failed', { job_id: job.job_id, job_type: job.job_type, org_id: job.org_id, error_code: error.code || 'PLATFORM_JOB_FAILED' });
    } finally {
      clearInterval(heartbeat);
    }
  }
  return (jobs || []).length;
}

async function processBillingOutbox(workerId, limit = 25) {
  const rows = await rpc('claim_billing_outbox', { target_worker_id: workerId, target_limit: Math.max(1, Math.min(100, Number(limit) || 25)), target_lease_seconds: 120 });
  for (const row of rows || []) {
    try {
      if (row.event_type !== 'scan.completed') throw Object.assign(new Error('Unsupported billing outbox event.'), { code: 'BILLING_OUTBOX_EVENT_UNSUPPORTED' });
      await recordOperationalEvent({ component: 'billing', operation: 'scan_usage_committed', outcome: 'success', orgId: row.org_id, attributes: { outbox_id: row.outbox_id, aggregate_id: row.aggregate_id, event_key: row.event_key } });
      await rpc('complete_billing_outbox', { target_outbox_id: row.outbox_id, target_lock_token: row.lock_token });
    } catch (error) {
      await rpc('fail_billing_outbox', { target_outbox_id: row.outbox_id, target_lock_token: row.lock_token, target_error: error.message, target_retry_seconds: 60 }).catch(() => null);
    }
  }
  return (rows || []).length;
}

module.exports = {
  buildPrivacyExport,
  claimPlatformJobs,
  exportPaged,
  processBillingOutbox,
  processPlatformQueue,
  runAsyncScan,
};
