const { serverConfig } = require('../lib/config');
const logger = require('../lib/gateway/logging');
const { actionableMediaJobs, claimExpiredUploads, claimJobs, completeJob, ensureRetentionJob, failJob, heartbeatJob, markUploadDeleted, mediaScansAwaitingFinalization, retentionArtifactsAwaitingCleanup } = require('../lib/gateway/worker-store');
const { deleteObjects } = require('../lib/gateway/storage');
const handleMedia = require('./handlers/media');
const handleWebhook = require('./handlers/webhook');
const handleRetention = require('./handlers/retention');
const { processBillingOutbox, processPlatformQueue } = require('../lib/platform-worker');

const QUEUES = Object.freeze({ gateway_media: handleMedia, gateway_webhooks: handleWebhook, gateway_retention: handleRetention });
let nextUploadCleanupAt = 0;
let nextMediaReconcileAt = 0;
let nextRetentionReconcileAt = 0;

async function cleanupExpiredUploads() {
  if (Date.now() < nextUploadCleanupAt) return 0;
  nextUploadCleanupAt = Date.now() + 60000;
  const uploads = await claimExpiredUploads(25);
  for (const upload of uploads) {
    try {
      await deleteObjects(upload.storage_bucket, [upload.staging_path, upload.final_path]);
      await markUploadDeleted(upload.upload_id);
    } catch (error) {
      logger.error('gateway.upload.cleanup_failed', { upload_id: upload.upload_id, error_code: error.code || 'UPLOAD_CLEANUP_FAILED' });
    }
  }
  return uploads.length;
}

async function reconcileMediaFinalizations() {
  if (Date.now() < nextMediaReconcileAt) return 0;
  nextMediaReconcileAt = Date.now() + 15000;
  const scans = await mediaScansAwaitingFinalization(25);
  let finalized = 0;
  for (const scan of scans || []) {
    if ((await actionableMediaJobs(scan.id)).length) continue;
    try {
      await handleMedia.finalize({ scan_id: scan.id, org_id: scan.org_id });
      finalized += 1;
    } catch (error) {
      logger.error('gateway.media.finalize_reconcile_failed', { scan_id: scan.id, error_code: error.code || 'MEDIA_FINALIZE_FAILED' });
    }
  }
  return finalized;
}

async function reconcileRetentionJobs() {
  if (Date.now() < nextRetentionReconcileAt) return 0;
  nextRetentionReconcileAt = Date.now() + 60000;
  const artifacts = await retentionArtifactsAwaitingCleanup(25);
  for (const artifact of artifacts || []) {
    await ensureRetentionJob(artifact).catch((error) => {
      logger.error('gateway.retention.reconcile_failed', { artifact_id: artifact.id, scan_id: artifact.scan_id, error_code: error.code || 'RETENTION_RECONCILE_FAILED' });
    });
  }
  return (artifacts || []).length;
}

function requestedQueues(queues) {
  if (queues === undefined || queues === null) return Object.keys(QUEUES);
  const values = Array.isArray(queues) ? queues : [queues];
  const normalized = [...new Set(values.map((queue) => String(queue || '').trim()).filter(Boolean))];
  if (!normalized.length || normalized.some((queue) => !QUEUES[queue])) {
    const error = new Error('An unsupported gateway queue was requested.');
    error.code = 'UNSUPPORTED_GATEWAY_QUEUE';
    throw error;
  }
  return normalized;
}

async function processQueue(queue, workerId, options = {}) {
  if (!QUEUES[queue]) {
    const error = new Error('An unsupported gateway queue was requested.');
    error.code = 'UNSUPPORTED_GATEWAY_QUEUE';
    throw error;
  }
  const limit = Math.max(1, Math.min(5, Number(options.limit) || 5));
  const visibilitySeconds = Math.max(30, Math.min(600, Number(options.visibilitySeconds) || 180));
  const jobs = await claimJobs(queue, workerId, limit, visibilitySeconds);
  for (const job of jobs) {
    let leaseLost = false;
    const heartbeat = setInterval(() => {
      heartbeatJob(job, visibilitySeconds).then((ok) => { leaseLost = !ok; }).catch((error) => {
        leaseLost = true;
        logger.error('gateway.job.heartbeat_failed', { job_id: job.job_id, scan_id: job.scan_id, queue, worker_id: workerId, error_code: error.code || 'HEARTBEAT_FAILED' });
      });
    }, 45000);
    heartbeat.unref();
    try {
      await QUEUES[queue](job, workerId);
      if (leaseLost) { const error = new Error('The job lease was lost during processing.'); error.code = 'JOB_LEASE_LOST'; throw error; }
      await completeJob(job);
      if (typeof QUEUES[queue].finalize === 'function') {
        await QUEUES[queue].finalize(job, workerId).catch((error) => {
          logger.error('gateway.media.finalize_deferred', { job_id: job.job_id, scan_id: job.scan_id, error_code: error.code || 'MEDIA_FINALIZE_FAILED' });
        });
      }
      logger.info('gateway.job.completed', { job_id: job.job_id, scan_id: job.scan_id, queue, worker_id: workerId });
    } catch (error) {
      const status = await failJob(job, error).catch(() => 'lease_lost');
      logger.error('gateway.job.failed', { job_id: job.job_id, scan_id: job.scan_id, queue, worker_id: workerId, error_code: error.code || 'WORKER_ERROR', status });
    } finally {
      clearInterval(heartbeat);
    }
  }
  return jobs.length;
}

async function tick(options = {}) {
  const workerId = String(options.workerId || serverConfig.gatewayWorkerId).slice(0, 160);
  const queues = requestedQueues(options.queues);
  const runMaintenance = options.maintenance !== false;
  const report = {
    worker_id: workerId,
    queues: {},
    upload_cleanup: 0,
    media_finalizations: 0,
    retention_reconciliations: 0,
    platform_jobs: 0,
    billing_outbox: 0,
    processed: 0,
  };

  if (runMaintenance) report.upload_cleanup = await cleanupExpiredUploads();
  for (const queue of queues) {
    report.queues[queue] = await processQueue(queue, workerId, {
      limit: options.limit,
      visibilitySeconds: options.visibilitySeconds,
    });
    report.processed += report.queues[queue];
  }
  if (runMaintenance) {
    report.media_finalizations = await reconcileMediaFinalizations();
    report.retention_reconciliations = await reconcileRetentionJobs();
    report.platform_jobs = await processPlatformQueue(workerId, {
      limit: options.limit,
      visibilitySeconds: options.visibilitySeconds,
    });
    report.billing_outbox = await processBillingOutbox(workerId, 25);
  }
  report.processed += report.upload_cleanup + report.media_finalizations + report.retention_reconciliations
    + report.platform_jobs + report.billing_outbox;
  return options.report ? report : report.processed;
}

async function main() {
  const once = ['1', 'true', 'yes'].includes(String(process.env.VERITRUST_WORKER_ONCE || '').toLowerCase());
  do {
    const count = await tick().catch((error) => {
      logger.error('gateway.worker.tick_failed', { error_code: error.code || 'WORKER_TICK_FAILED' });
      return 0;
    });
    if (once) break;
    await new Promise((resolve) => setTimeout(resolve, count ? 250 : 2000));
  } while (true);
}

if (require.main === module) main();
module.exports = { cleanupExpiredUploads, processQueue, reconcileMediaFinalizations, reconcileRetentionJobs, requestedQueues, tick };
