const crypto = require('node:crypto');
const { HttpError } = require('./veritrust-api');
const { mapWithConcurrency } = require('./gateway/execution');
const phishingModule = require('./models/phishing-text');
const linkModule = require('./models/malicious-url');

const MODULE_CONTRACT_VERSION = 'veritrust-module-command-1';
const MODULES = Object.freeze({
  phishing: Object.freeze({
    handler: phishingModule,
    acceptedArtifacts: new Set(['email', 'text']),
  }),
  link: Object.freeze({
    handler: linkModule,
    acceptedArtifacts: new Set(['url']),
  }),
});

function hasDetectionModule(moduleKey) {
  return Boolean(MODULES[String(moduleKey || '').trim().toLowerCase()]);
}

function moduleCorrelationId(moduleKey, artifact, supplied) {
  if (supplied) return String(supplied).slice(0, 200);
  return crypto.createHash('sha256')
    .update(`${MODULE_CONTRACT_VERSION}:${moduleKey}:${artifact.id}`)
    .digest('hex');
}

async function invokeDetectionModule(moduleKey, artifact, options = {}) {
  const normalizedKey = String(moduleKey || '').trim().toLowerCase();
  const module = MODULES[normalizedKey];
  if (!module) throw new HttpError(503, 'Detection module is unavailable.', { code: 'MODULE_UNAVAILABLE' });
  if (!artifact?.id || !module.acceptedArtifacts.has(String(artifact.type || ''))) {
    throw new HttpError(400, 'Artifact is incompatible with the detection module.', { code: 'MODULE_ARTIFACT_UNSUPPORTED' });
  }

  const correlationId = moduleCorrelationId(normalizedKey, artifact, options.correlationId);
  const started = Date.now();
  const result = await module.handler.execute(artifact, {
    ...options,
    moduleContractVersion: MODULE_CONTRACT_VERSION,
    moduleCorrelationId: correlationId,
  });
  return {
    contract_version: MODULE_CONTRACT_VERSION,
    correlation_id: correlationId,
    module: normalizedKey,
    artifact_id: artifact.id,
    latency_ms: Date.now() - started,
    result,
  };
}

async function invokeDetectionModuleQueue(moduleKey, artifacts, options = {}) {
  if (!Array.isArray(artifacts)) throw new TypeError('artifacts must be an array');
  const concurrency = moduleKey === 'link' ? 1 : (options.concurrency || 1);
  return mapWithConcurrency(artifacts, concurrency, (artifact, index) => invokeDetectionModule(
    moduleKey,
    artifact,
    {
      ...options,
      correlationId: options.correlationId
        ? `${options.correlationId}:${index}`
        : undefined,
    },
  ));
}

module.exports = {
  MODULE_CONTRACT_VERSION,
  hasDetectionModule,
  invokeDetectionModule,
  invokeDetectionModuleQueue,
};
