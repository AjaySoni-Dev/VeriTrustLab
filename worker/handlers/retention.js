const { deleteObject } = require('../../lib/gateway/storage');
const { loadArtifact, recordRetentionReceipt } = require('../../lib/gateway/worker-store');

module.exports = async function handleRetention(job, workerId) {
  const artifact = await loadArtifact(job.org_id, job.scan_id, job.artifact_id);
  if (!artifact || artifact.status === 'deleted') return;
  if (artifact.retention_until && Date.parse(artifact.retention_until) > Date.now()) {
    const error = new Error('Retention deadline has not arrived.');
    error.code = 'RETENTION_NOT_DUE';
    error.retrySeconds = Math.ceil((Date.parse(artifact.retention_until) - Date.now()) / 1000);
    throw error;
  }
  if (artifact.storage_bucket && artifact.storage_path) await deleteObject(artifact.storage_bucket, artifact.storage_path);
  await recordRetentionReceipt(artifact.id, workerId, { storage_absent_after_delete: true, metadata_scrubbed: true });
};
