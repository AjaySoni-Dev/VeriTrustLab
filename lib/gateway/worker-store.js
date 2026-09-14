const { eq, supabaseFetch } = require('../supabase-server');

async function rpc(name, body) {
  const result = await supabaseFetch(`/rest/v1/rpc/${name}`, { method: 'POST', service: true, body });
  return Array.isArray(result) && result.length === 1 ? result[0] : result;
}

async function claimJobs(queue, workerId, limit = 5, visibilitySeconds = 120) {
  const result = await rpc('gateway_claim_jobs', {
    target_queue: queue, target_worker_id: workerId, target_limit: limit, target_visibility_seconds: visibilitySeconds,
  });
  return Array.isArray(result) ? result : result ? [result] : [];
}

async function completeJob(job) {
  const completed = await rpc('gateway_complete_job', { target_job_id: job.job_id, target_lease_token: job.lease_token });
  if (!completed) { const error = new Error('The job lease was lost before completion.'); error.code = 'JOB_LEASE_LOST'; throw error; }
  return true;
}

async function heartbeatJob(job, visibilitySeconds = 180) {
  return Boolean(await rpc('gateway_heartbeat_job', {
    target_job_id: job.job_id, target_lease_token: job.lease_token,
    target_visibility_seconds: visibilitySeconds,
  }));
}

async function failJob(job, error) {
  return rpc('gateway_fail_job', {
    target_job_id: job.job_id,
    target_lease_token: job.lease_token,
    target_error_code: String(error.code || 'WORKER_ERROR').slice(0, 120),
    target_error_detail: { error_code: String(error.code || 'WORKER_ERROR').slice(0, 120) },
    target_retry_seconds: Math.max(0, Math.min(86400, Number(error.retrySeconds || 30))),
  });
}

async function loadArtifact(orgId, scanId, artifactId) {
  const rows = await supabaseFetch(`/rest/v1/gateway_artifacts?id=eq.${eq(artifactId)}&scan_id=eq.${eq(scanId)}&org_id=eq.${eq(orgId)}&select=*&limit=1`, { service: true });
  return rows?.[0] || null;
}

async function actionableMediaJobs(scanId, excludeJobId) {
  const exclusion = excludeJobId ? `&id=neq.${eq(excludeJobId)}` : '';
  const rows = await supabaseFetch(`/rest/v1/gateway_jobs?scan_id=eq.${eq(scanId)}&job_type=eq.media${exclusion}&status=in.(queued,retry,leased)&select=id`, { service: true });
  return rows || [];
}

async function webhookDelivery(eventId) {
  const events = await supabaseFetch(`/rest/v1/gateway_webhook_events?id=eq.${eq(eventId)}&select=*&limit=1`, { service: true });
  const event = events?.[0];
  if (!event) return null;
  const endpoints = await supabaseFetch(`/rest/v1/gateway_webhook_endpoints?id=eq.${eq(event.endpoint_id)}&org_id=eq.${eq(event.org_id)}&select=*&limit=1`, { service: true });
  const secrets = await supabaseFetch(`/rest/v1/gateway_webhook_secrets?endpoint_id=eq.${eq(event.endpoint_id)}&org_id=eq.${eq(event.org_id)}&revoked_at=is.null&select=*&limit=1`, { service: true });
  return { event, endpoint: endpoints?.[0], secret: secrets?.[0] };
}

async function recordWebhookAttempt(eventId, input) {
  return rpc('gateway_record_webhook_attempt', {
    target_event_id: eventId, target_outcome: input.outcome,
    target_response_code: input.responseCode || null, target_latency_ms: input.latencyMs || null,
    target_retry_at: input.retryAt || null, target_error_code: input.errorCode || null,
    target_error_detail: input.errorDetail || {},
  });
}

async function recordRetentionReceipt(artifactId, workerId, detail) {
  return rpc('gateway_record_retention_receipt', {
    target_artifact_id: artifactId, target_object_deleted: true, target_metadata_scrubbed: true,
    target_verified: true, target_worker_id: workerId, target_verification_detail: detail || {},
  });
}

async function claimExpiredUploads(limit = 25) {
  const rows = await rpc('gateway_claim_expired_uploads', { target_limit: limit });
  return Array.isArray(rows) ? rows : rows ? [rows] : [];
}

async function markUploadDeleted(uploadId) {
  return Boolean(await rpc('gateway_mark_upload_deleted', { target_upload_id: uploadId }));
}

async function mediaScansAwaitingFinalization(limit = 25) {
  return supabaseFetch(`/rest/v1/gateway_scans?status=eq.partially_completed&final_decision_id=is.null&select=id,org_id&order=created_at.asc&limit=${Math.max(1, Math.min(100, Number(limit) || 25))}`, { service: true });
}

async function retentionArtifactsAwaitingCleanup(limit = 25) {
  const deadline = encodeURIComponent(new Date().toISOString());
  return supabaseFetch(`/rest/v1/gateway_artifacts?retention_until=lte.${deadline}&scrubbed_at=is.null&storage_path=not.is.null&select=id,org_id,scan_id&order=retention_until.asc&limit=${Math.max(1, Math.min(100, Number(limit) || 25))}`, { service: true });
}

async function ensureRetentionJob(artifact) {
  return rpc('gateway_enqueue_job', {
    target_org_id: artifact.org_id, target_scan_id: artifact.scan_id, target_job_type: 'retention',
    target_dedupe_key: `retention:${artifact.id}`, target_artifact_id: artifact.id,
    target_payload: { artifact_id: artifact.id }, target_priority: 100,
    target_available_at: new Date().toISOString(), target_max_attempts: 8,
  });
}

module.exports = {
  actionableMediaJobs,
  claimExpiredUploads,
  claimJobs,
  completeJob,
  ensureRetentionJob,
  failJob,
  heartbeatJob,
  loadArtifact,
  markUploadDeleted,
  mediaScansAwaitingFinalization,
  recordRetentionReceipt,
  recordWebhookAttempt,
  retentionArtifactsAwaitingCleanup,
  webhookDelivery,
};
