const crypto = require('crypto');
const { correlate } = require('../../lib/gateway/correlation');
const { validateImageBytes } = require('../../lib/gateway/media');
const { compilePolicy } = require('../../lib/gateway/policy');
const { completeArtifact, getPolicyVersion, publishDecision, recordEvidence, scanReport } = require('../../lib/gateway/persistence');
const { routeArtifacts } = require('../../lib/gateway/router');
const { downloadObject } = require('../../lib/gateway/storage');
const { actionableMediaJobs, loadArtifact } = require('../../lib/gateway/worker-store');
const { supabaseFetch } = require('../../lib/supabase-server');
const deepfakeAdapter = require('../../lib/models/deepfake-image');

function evidenceRow(row, route) {
  return { id: row.id, artifactId: row.artifact_id, kind: route?.kind || row.model_key, modelKey: row.model_key,
    status: row.status, score: row.score === null ? null : Number(row.score), verdict: row.verdict,
    confidence: row.confidence, reasonCodes: row.reason_codes || [], required: route?.required !== false };
}

async function handleMedia(job) {
  const artifact = await loadArtifact(job.org_id, job.scan_id, job.artifact_id);
  if (!artifact) { const error = new Error('Media artifact was not found.'); error.code = 'ARTIFACT_NOT_FOUND'; throw error; }
  const reportBefore = await scanReport(job.org_id, job.scan_id);
  if (['cancel_requested', 'cancelled', 'completed', 'failed'].includes(reportBefore.scan.status)) return;
  const policy = compilePolicy((await getPolicyVersion(reportBefore.scan.policy_version_id, job.org_id)).compiled_policy);
  const artifactView = { ...artifact, type: artifact.artifact_type };
  const route = routeArtifacts([artifactView], policy)[0];

  if (!route) {
    await completeArtifact(job.org_id, job.scan_id, artifact.id);
    return;
  }

  if (artifact.artifact_type === 'image' && !(reportBefore.evidence || []).some((row) => row.artifact_id === artifact.id)) {
    const object = await downloadObject(artifact.storage_bucket, artifact.storage_path);
    const mimeType = validateImageBytes(object.buffer, artifact.mime_type);
    const digest = crypto.createHash('sha256').update(object.buffer).digest('hex');
    await supabaseFetch(`/rest/v1/gateway_uploads?artifact_id=eq.${artifact.id}`, { method: 'PATCH', service: true, body: { content_sha256: digest, detected_mime_type: mimeType, actual_size_bytes: object.buffer.length } });
    const result = await deepfakeAdapter.execute({ id: artifact.id, type: 'image', upload: { buffer: object.buffer, mimeType, size: object.buffer.length, filename: 'gateway-image' } }, { modelKey: route.modelKey, required: route.required });
    await recordEvidence(job.org_id, job.scan_id, artifactView, result.evidence);
  }

  await completeArtifact(job.org_id, job.scan_id, artifact.id);
}

async function finalizeMediaScan(job) {
  const remaining = await actionableMediaJobs(job.scan_id);
  if (remaining.length) return;

  const report = await scanReport(job.org_id, job.scan_id);
  if (['cancel_requested', 'cancelled', 'completed', 'failed'].includes(report.scan.status)) return;
  const policy = compilePolicy((await getPolicyVersion(report.scan.policy_version_id, job.org_id)).compiled_policy);
  const routes = routeArtifacts(report.artifacts.map((row) => ({ ...row, id: row.id, type: row.artifact_type })), policy);
  const routeMap = new Map(routes.map((item) => [item.artifact.id, item]));
  const evidence = report.evidence.map((row) => evidenceRow(row, routeMap.get(row.artifact_id)));
  const decision = correlate(evidence, policy, { contextCategories: report.scan.metadata?.context_categories || [] });
  decision.decision_state = 'final';
  const unsupported = report.artifacts.some((row) => ['audio', 'video'].includes(row.artifact_type));
  if (unsupported) {
    decision.recommendation = 'hold';
    decision.degraded = true;
    decision.reason_codes = [...new Set([...decision.reason_codes, 'UNSUPPORTED_MEDIA_MODEL'])].sort();
  }
  await publishDecision(job.scan_id, decision, null);
}

handleMedia.finalize = finalizeMediaScan;
module.exports = handleMedia;
