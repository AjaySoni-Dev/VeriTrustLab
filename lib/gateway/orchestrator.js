const { serverConfig } = require('../config');
const { HttpError } = require('../veritrust-api');
const { hasDetectionModule, invokeDetectionModule, invokeDetectionModuleQueue } = require('../module-communication');
const { correlate } = require('./correlation');
const { buildArtifacts } = require('./extractor');
const { canonicalRequestHash } = require('./idempotency');
const logger = require('./logging');
const { compilePolicy } = require('./policy');
const {
  activePolicyVersionId,
  attachUpload,
  claimScan,
  completeArtifacts,
  createArtifacts,
  enqueueJob,
  failScan,
  getPolicyVersion,
  publishDecision,
  prepareUploadAttachment,
  prepareModelRun,
  recordEvidence,
  resolveIntegration,
  scanReport,
  storeIdempotentResponse,
  submitScan,
  uploadsForSubmission,
} = require('./persistence');
const { routeArtifacts } = require('./router');
const { moveObject } = require('./storage');
const { sanitizeModuleData } = require('../modules');
const { mapWithConcurrency, modelTimeoutMs } = require('./execution');

const MODEL_KIND = Object.freeze({
  mailguard: 'phishing',
  cortex: 'phishing',
  swift: 'link',
  sentinel: 'link',
  pixel: 'deepfake_image',
  prism: 'deepfake_image',
});

function asCorrelationEvidence(row, routesByArtifact) {
  const route = routesByArtifact.get(row.artifact_id);
  return {
    id: row.id,
    artifactId: row.artifact_id,
    kind: MODEL_KIND[row.model_key] || route?.kind || 'unknown',
    modelKey: row.model_key,
    status: row.status,
    score: row.score === null ? null : Number(row.score),
    verdict: row.verdict,
    confidence: row.confidence,
    confidenceValue: row.confidence_value === null ? null : Number(row.confidence_value),
    indicators: row.indicators || [],
    reasonCodes: row.reason_codes || [],
    degraded: false,
    required: route?.required !== false,
  };
}

function publicReport(report) {
  const decisions = (report.decisions || []).map((decision) => ({
    id: decision.id,
    kind: decision.decision_kind,
    risk: Number(decision.risk_score),
    verdict: decision.verdict,
    recommendation: decision.recommendation,
    degraded: decision.degraded,
    reason_codes: decision.reason_codes,
    policy_version_id: decision.policy_version_id,
    correlation_version: decision.correlation_version,
    created_at: decision.created_at,
  }));
  const finalDecision = [...decisions].reverse().find((decision) => decision.kind === 'final') || null;
  const preliminaryDecision = [...decisions].reverse().find((decision) => decision.kind === 'preliminary') || null;
  return sanitizeModuleData({
    schema_version: report.scan.schema_version,
    scan_id: report.scan.id,
    display_id: report.scan.display_id,
    submission_request_id: report.scan.request_id,
    trace_id: report.scan.trace_id,
    status: report.scan.status,
    processing_mode: report.scan.processing_mode,
    degraded: report.scan.degraded,
    created_at: report.scan.created_at,
    completed_at: report.scan.completed_at,
    policy_version_id: report.scan.policy_version_id,
    correlation_version: report.scan.correlation_version,
    decision: finalDecision || preliminaryDecision,
    artifacts: (report.artifacts || []).map((artifact) => ({
      id: artifact.id,
      parent_artifact_id: artifact.parent_artifact_id,
      type: artifact.artifact_type,
      status: artifact.status,
      mime_type: artifact.mime_type,
      size_bytes: artifact.size_bytes,
      metadata: artifact.metadata,
    })),
    evidence: (report.evidence || []).map((item) => ({
      id: item.id,
      artifact_id: item.artifact_id,
      model: MODEL_KIND[item.model_key] || item.model_key,
      model_key: item.model_key,
      status: item.status,
      score: item.score === null ? null : Number(item.score),
      verdict: item.verdict,
      confidence: item.confidence,
      confidence_value: item.confidence_value === null ? null : Number(item.confidence_value),
      indicators: item.indicators,
      reason_codes: item.reason_codes,
      model_version: item.model_version,
      calibration_version: item.calibration_version,
    })),
    review: (report.review_cases || []).map((review) => ({
      id: review.id,
      decision_id: review.decision_id,
      status: review.status,
      priority: review.priority,
      reason_codes: review.reason_codes,
      created_at: review.created_at,
    })),
    status_url: `/api/v1/gateway/scans/${report.scan.id}`,
    report_url: `/api/v1/gateway/reports/${report.scan.id}`,
  });
}

async function executeRoute(route, policy, prepared) {
  if (!hasDetectionModule(route.kind)) {
    return {
      attempts: [],
      evidence: {
        artifactId: route.artifact.id,
        kind: route.kind,
        modelKey: route.modelKey,
        status: 'not_applicable',
        score: null,
        verdict: 'unknown',
        confidence: 'unknown',
        confidenceValue: null,
        indicators: [],
        reasonCodes: ['MODEL_NOT_APPLICABLE'],
        degraded: false,
        required: route.required,
        rawResponseRedacted: {},
      },
    };
  }
  const invocation = await invokeDetectionModule(route.kind, route.artifact, {
    modelKey: route.modelKey,
    required: route.required,
    timeoutMs: modelTimeoutMs(policy, prepared, serverConfig.gatewaySynchronousBudgetMs),
    allowProviderFallback: false,
    modelContract: prepared.configuration,
    correlationId: `${route.artifact.scan_id || 'gateway'}:${route.artifact.id}:${route.modelKey}`,
  });
  return invocation.result;
}

async function orchestrateSubmission(input) {
  const { auth, submission, idempotencyKey, requestId, traceId } = input;
  const hmacKey = serverConfig.gatewayContentHmacKey;
  if (!hmacKey || Buffer.byteLength(String(hmacKey), 'utf8') < 32) {
    throw new HttpError(500, 'Gateway content-matching key is not configured.', { code: 'SERVER_CONFIG_ERROR' });
  }
  const integration = await resolveIntegration(auth, submission.source.integration_id, 'gateway:scan');
  const mediaUploads = await uploadsForSubmission(auth.organization.id, submission.content.media.map((item) => item.upload_id));
  const policyVersionId = await activePolicyVersionId(auth.organization.id, submission.policy_id);
  const requestHash = canonicalRequestHash(submission);
  const deadlineAt = new Date(Date.now() + 120000).toISOString();
  const submitted = await submitScan({
    orgId: auth.organization.id,
    integrationId: integration.id,
    idempotencyKey,
    requestHash,
    apiKeyId: auth.apiKeyId,
    submittedBy: auth.user?.id || null,
    processingMode: submission.processing_mode,
    source: submission.source.kind,
    externalEventId: submission.source.external_event_id,
    requestId,
    traceId,
    policyVersionId,
    deadlineAt,
    metadata: {
      ...submission.metadata,
      callback_webhook_endpoint_id: submission.callback?.webhook_endpoint_id || null,
      schema_version: submission.schema_version,
    },
  });

  if (submitted.replayed && submitted.response_body) {
    return { status: Number(submitted.response_status || 200), body: submitted.response_body, replayed: true };
  }

  const scanId = submitted.scan_id;
  const claimed = await claimScan(auth.organization.id, scanId);
  if (!claimed) {
    const current = publicReport(await scanReport(auth.organization.id, scanId));
    const status = current.status === 'completed' ? 200 : 202;
    return { status, body: { ok: true, replayed: true, ...current }, replayed: true };
  }

  logger.info('gateway.scan.claimed', {
    request_id: requestId,
    trace_id: traceId,
    scan_id: scanId,
    organization_id: auth.organization.id,
  });

  try {
    const policyRow = await getPolicyVersion(claimed.policy_version_id, auth.organization.id);
    const policy = compilePolicy(policyRow.compiled_policy);
    const ephemeralArtifacts = buildArtifacts(submission, hmacKey, auth.organization.id);
    const uploadById = new Map(mediaUploads.map((upload) => [upload.id, upload]));
    const retentionHours = Math.max(1, Math.min(24, Number(policy.retention.maximum_hours || 1)));
    for (const artifact of ephemeralArtifacts.filter((item) => item.upload_id)) {
      const upload = uploadById.get(artifact.upload_id);
      if (!upload || upload.artifact_type !== artifact.type) throw new HttpError(400, 'Media upload kind does not match the submitted artifact.', { code: 'UPLOAD_KIND_MISMATCH' });
      artifact.mime_type = upload.detected_mime_type || upload.declared_mime_type;
      artifact.size_bytes = Number(upload.actual_size_bytes || upload.declared_size_bytes);
      artifact.storage_bucket = upload.storage_bucket;
      artifact.storage_path = `${auth.organization.id}/${scanId}/media/${upload.id}`;
      artifact.retention = 'temporary_file';
      artifact.retention_until = new Date(Date.now() + retentionHours * 3600000).toISOString();
      artifact.metadata = { upload_id: upload.id, media_kind: upload.artifact_type };
    }
    const artifacts = await createArtifacts(auth.organization.id, scanId, ephemeralArtifacts);
    const routes = routeArtifacts(artifacts, policy);
    for (const artifact of artifacts.filter((item) => item.upload_id)) {
      const upload = uploadById.get(artifact.upload_id);
      await prepareUploadAttachment(upload.id, scanId, artifact.id, artifact.storage_path);
      await moveObject(upload.storage_bucket, upload.staging_path, artifact.storage_path);
      await attachUpload(upload.id, scanId, artifact.id, artifact.storage_path);
      await enqueueJob({
        orgId: auth.organization.id,
        scanId,
        artifactId: artifact.id,
        jobType: 'retention',
        dedupeKey: `retention:${artifact.id}`,
        payload: { artifact_id: artifact.id },
        availableAt: artifact.retention_until,
        maxAttempts: 8,
      });
    }
    const routesByArtifact = new Map(routes.map((route) => [route.artifact.id, route]));

    const existing = await scanReport(auth.organization.id, scanId);
    const existingArtifacts = new Set((existing.evidence || []).map((item) => item.artifact_id));
    const routesToRun = routes.filter((route) => route.mode === 'fast' && !existingArtifacts.has(route.artifact.id));
    const preparedRoutes = await mapWithConcurrency(routesToRun, 8, async (route) => ({
      route,
      prepared: await prepareModelRun(auth.organization.id, scanId, route.artifact, route.modelKey),
    }));
    const batchedLinks = preparedRoutes.filter(({ route }) => route.kind === 'link' && route.modelKey === 'swift');
    const executionGroups = [
      ...preparedRoutes.filter(({ route }) => route.kind !== 'link' || route.modelKey !== 'swift').map((item) => ({ type: 'single', items: [item] })),
      ...(batchedLinks.length ? [{ type: 'link_batch', items: batchedLinks }] : []),
    ];
    const evidenceGroups = await mapWithConcurrency(
      executionGroups,
      serverConfig.gatewayModelConcurrency,
      async (group) => {
        if (group.type === 'link_batch') {
          const timeoutMs = Math.min(...group.items.map(({ prepared }) => modelTimeoutMs(
            policy,
            prepared,
            serverConfig.gatewaySynchronousBudgetMs,
          )));
          const invocations = await invokeDetectionModuleQueue('link', group.items.map(({ route }) => route.artifact), {
            modelKey: 'swift',
            required: group.items.some(({ route }) => route.required),
            timeoutMs,
            concurrency: serverConfig.gatewayModelConcurrency,
            allowProviderFallback: false,
            modelContract: group.items[0].prepared.configuration,
            correlationId: `${scanId}:gateway:swift`,
          });
          const results = invocations.map((invocation) => invocation.result);
          return mapWithConcurrency(results, 8, (result, index) => {
            const { route, prepared } = group.items[index];
            result.evidence.required = route.required;
            return recordEvidence(auth.organization.id, scanId, route.artifact, result.evidence, prepared);
          });
        }
        const { route, prepared } = group.items[0];
        const result = await executeRoute(route, policy, prepared);
        return [await recordEvidence(auth.organization.id, scanId, route.artifact, result.evidence, prepared)];
      },
    );
    const newEvidence = evidenceGroups.flat();
    const persistedEvidence = [
      ...(existing.evidence || []).map((row) => asCorrelationEvidence(row, routesByArtifact)),
      ...newEvidence,
    ];
    const decision = correlate(persistedEvidence, policy, {
      contextCategories: Array.isArray(submission.metadata.context_categories) ? submission.metadata.context_categories : [],
    });
    const mediaRoutes = routes.filter((route) => route.mode === 'heavy' || route.mode === 'unsupported');
    if (mediaRoutes.length) {
      decision.decision_state = 'preliminary';
      decision.recommendation = persistedEvidence.length ? decision.recommendation : 'hold';
      decision.reason_codes = [...new Set([...decision.reason_codes, 'MEDIA_ANALYSIS_PENDING'])].sort();
      for (const route of mediaRoutes) {
        await enqueueJob({
          orgId: auth.organization.id,
          scanId,
          artifactId: route.artifact.id,
          jobType: 'media',
          dedupeKey: `media:${route.artifact.id}:${route.modelKey || route.kind}`,
          payload: { artifact_id: route.artifact.id, kind: route.kind, model_key: route.modelKey },
          maxAttempts: 5,
        });
      }
    }
    await publishDecision(scanId, decision, auth.user?.id || null);
    await completeArtifacts(auth.organization.id, scanId);
    const report = publicReport(await scanReport(auth.organization.id, scanId));
    const body = { ok: true, replayed: Boolean(submitted.replayed), request_id: requestId, ...report };
    const status = decision.decision_state === 'final' ? 200 : 202;
    await storeIdempotentResponse(scanId, status, body);
    logger.info('gateway.scan.completed', {
      request_id: requestId,
      trace_id: traceId,
      scan_id: scanId,
      organization_id: auth.organization.id,
      status: report.status,
      degraded: report.degraded,
      latency_ms: Date.now() - Date.parse(claimed.started_at || claimed.created_at),
    });
    return { status, body, replayed: Boolean(submitted.replayed) };
  } catch (error) {
    await failScan(auth.organization.id, scanId, error).catch(() => null);
    logger.error('gateway.scan.failed', {
      request_id: requestId,
      trace_id: traceId,
      scan_id: scanId,
      organization_id: auth.organization.id,
      error_code: error.code || 'GATEWAY_ORCHESTRATION_FAILED',
    });
    throw error;
  }
}

module.exports = {
  orchestrateSubmission,
  publicReport,
};
