const { ConfigError, getOptionalEnv, getModelPath } = require('./config');
const BUNDLED_CANARY_CONTRACTS = require('../config/hf-model-contracts.canary.json');

const REGISTRY_SCHEMA = 'gateway-model-registry-2';
const QUALIFIED_STATES = new Set(['production', 'canary']);
const PINNED_RUNTIME_MODELS = new Set(['mailguard', 'swift']);
const MODEL_DEFINITIONS = Object.freeze({
  mailguard: Object.freeze({
    pathKey: 'phishing_mailguard',
    provider: 'hf-inference',
    task: 'text-classification',
    requiresLabels: true,
  }),
  cortex: Object.freeze({
    pathKey: 'phishing_cortex',
    provider: 'featherless-ai',
    task: 'conversational',
  }),
  swift: Object.freeze({
    pathKey: 'link_swift',
    provider: 'hf-inference',
    task: 'text-classification',
  }),
  pixel: Object.freeze({
    pathKey: 'deepfake_pixel',
    provider: 'hf-inference',
    task: 'image-classification',
  }),
  prism: Object.freeze({
    pathKey: 'deepfake_prism',
    provider: 'hf-inference',
    task: 'image-classification',
  }),
});

class ModelContractError extends Error {
  constructor(code, message, options = {}) {
    super(message);
    this.name = 'ModelContractError';
    this.status = 503;
    this.code = code;
    this.modelKey = options.modelKey || null;
    this.source = options.source || null;
  }
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function parseContractMap() {
  const raw = getOptionalEnv('HF_MODEL_CONTRACTS', '');
  if (!raw) return {};
  try {
    let encoded = raw.replace(/^HF_MODEL_CONTRACTS\s*=\s*/u, '').trim();
    let parsed = JSON.parse(encoded);
    // Accept the JSON-string form emitted by configuration/export tools and
    // a wrapper object copied from `npm run config:canary`.
    if (typeof parsed === 'string') parsed = JSON.parse(parsed);
    if (isPlainObject(parsed) && typeof parsed.HF_MODEL_CONTRACTS === 'string') {
      encoded = parsed.HF_MODEL_CONTRACTS.trim();
      parsed = JSON.parse(encoded);
    }
    if (!isPlainObject(parsed)) throw new Error('object required');
    return parsed;
  } catch {
    throw new ConfigError('HF_MODEL_CONTRACTS', { invalid: true });
  }
}

function normalizedRepositoryId(value) {
  const repositoryId = String(value || '').trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,95}\/[A-Za-z0-9][A-Za-z0-9._-]{0,95}$/u.test(repositoryId)) return null;
  return repositoryId;
}

function validateThresholds(contract, modelKey, source) {
  if (contract.thresholds === undefined) return;
  if (!isPlainObject(contract.thresholds)) {
    throw new ModelContractError('MODEL_THRESHOLD_CONTRACT_INVALID', `${modelKey} thresholds must be an object.`, { modelKey, source });
  }
  const benign = Number(contract.thresholds.likely_benign_max);
  const phishing = Number(contract.thresholds.likely_phishing_min);
  if (!Number.isFinite(benign) || !Number.isFinite(phishing) || benign < 0 || phishing > 1 || benign >= phishing) {
    throw new ModelContractError('MODEL_THRESHOLD_CONTRACT_INVALID', `${modelKey} thresholds are invalid.`, { modelKey, source });
  }
}

function validateLabelContract(contract, modelKey, source) {
  if (!isPlainObject(contract.label_map) || !Array.isArray(contract.ordered_labels) || contract.ordered_labels.length < 2) {
    throw new ModelContractError('MODEL_LABEL_CONTRACT_UNRESOLVED', `${modelKey} label semantics are unresolved.`, { modelKey, source });
  }
  const labels = contract.ordered_labels.map((label) => String(label || '').trim());
  if (labels.some((label) => !label) || new Set(labels).size !== labels.length) {
    throw new ModelContractError('MODEL_LABEL_CONTRACT_INVALID', `${modelKey} ordered labels are invalid.`, { modelKey, source });
  }
  const mapped = Object.keys(contract.label_map).sort();
  if (mapped.length !== labels.length || mapped.some((label, index) => label !== [...labels].sort()[index])) {
    throw new ModelContractError('MODEL_LABEL_CONTRACT_INVALID', `${modelKey} label map does not match ordered labels.`, { modelKey, source });
  }
  const semantics = new Set(Object.values(contract.label_map).map((value) => String(value || '').toUpperCase()));
  if (![...semantics].every((value) => ['BENIGN', 'LIKELY_BENIGN', 'PHISHING', 'LIKELY_PHISHING'].includes(value))
    || ![...semantics].some((value) => ['BENIGN', 'LIKELY_BENIGN'].includes(value))
    || ![...semantics].some((value) => ['PHISHING', 'LIKELY_PHISHING'].includes(value))) {
    throw new ModelContractError('MODEL_LABEL_CONTRACT_INVALID', `${modelKey} label semantics must cover benign and phishing classes.`, { modelKey, source });
  }
  const tolerance = Number(contract.score_sum_tolerance ?? 0.02);
  if (!Number.isFinite(tolerance) || tolerance < 0 || tolerance > 0.25) {
    throw new ModelContractError('MODEL_LABEL_CONTRACT_INVALID', `${modelKey} score tolerance is invalid.`, { modelKey, source });
  }
  validateThresholds(contract, modelKey, source);
}

function validateModelContract(modelKey, value, options = {}) {
  const normalizedKey = String(modelKey || '').trim().toLowerCase();
  const definition = MODEL_DEFINITIONS[normalizedKey];
  const source = options.source || 'unknown';
  if (!definition || !isPlainObject(value)) {
    throw new ModelContractError('MODEL_CONTRACT_UNRESOLVED', `${normalizedKey || 'Model'} contract is unresolved.`, { modelKey: normalizedKey, source });
  }
  if (value.registry_schema !== REGISTRY_SCHEMA) {
    throw new ModelContractError('MODEL_CONTRACT_UNRESOLVED', `${normalizedKey} registry schema is unresolved.`, { modelKey: normalizedKey, source });
  }
  const repositoryId = normalizedRepositoryId(value.repository_id);
  if (!repositoryId || !/^[0-9a-f]{40,64}$/iu.test(String(value.revision_sha || ''))) {
    throw new ModelContractError('MODEL_IDENTITY_UNRESOLVED', `${normalizedKey} immutable model identity is unresolved.`, { modelKey: normalizedKey, source });
  }
  const qualificationState = String(value.qualification_state || '').toLowerCase();
  if (!QUALIFIED_STATES.has(qualificationState)) {
    throw new ModelContractError('MODEL_NOT_QUALIFIED', `${normalizedKey} is not qualified for policy influence.`, { modelKey: normalizedKey, source });
  }
  const provider = String(value.provider || definition.provider).toLowerCase();
  const task = String(value.task || definition.task).toLowerCase();
  if (provider !== definition.provider || task !== definition.task) {
    throw new ModelContractError('MODEL_TRANSPORT_CONTRACT_INVALID', `${normalizedKey} provider or task does not match its adapter.`, { modelKey: normalizedKey, source });
  }
  if (definition.requiresLabels) validateLabelContract(value, normalizedKey, source);
  return Object.freeze({
    ...value,
    repository_id: repositoryId,
    revision_sha: String(value.revision_sha).toLowerCase(),
    qualification_state: qualificationState,
    provider,
    task,
    ...(Array.isArray(value.ordered_labels) ? { ordered_labels: Object.freeze(value.ordered_labels.map(String)) } : {}),
  });
}

function configuredLegacyPath(modelKey) {
  const definition = MODEL_DEFINITIONS[modelKey];
  if (!definition) return null;
  try {
    return getModelPath(definition.pathKey);
  } catch (error) {
    if (error instanceof ConfigError && error.code === 'CONFIG_MISSING') return null;
    throw error;
  }
}

function runtimeModelContract(modelKey, options = {}) {
  const normalizedKey = String(modelKey || '').trim().toLowerCase();
  const bundledCandidate = BUNDLED_CANARY_CONTRACTS[normalizedKey];

  // MailGuard and Swift are first-party VeriTrust runtime dependencies. Their
  // non-secret repository, revision, task, and label contracts are pinned in
  // source so Vercel variables cannot drift the integrated and standalone
  // modules apart. Supabase registry rows must still match these contracts.
  if (PINNED_RUNTIME_MODELS.has(normalizedKey) && bundledCandidate) {
    return {
      contract: validateModelContract(normalizedKey, bundledCandidate, { source: 'bundled-pinned' }),
      source: 'bundled-pinned',
    };
  }

  const candidate = parseContractMap()[normalizedKey];
  const legacyPath = configuredLegacyPath(normalizedKey);

  if (candidate) {
    const contract = validateModelContract(normalizedKey, candidate, { source: 'environment' });
    if (legacyPath && legacyPath !== contract.repository_id) {
      throw new ModelContractError('MODEL_IDENTITY_MISMATCH', `${normalizedKey} contract and legacy model path disagree.`, { modelKey: normalizedKey, source: 'environment' });
    }
    return { contract, source: 'environment' };
  }

  // Exact repository IDs opt into the immutable canary contracts shipped with
  // this deployment. Arbitrary repositories still require an explicit,
  // qualified HF_MODEL_CONTRACTS entry and therefore continue to fail closed.
  if (bundledCandidate && legacyPath === bundledCandidate.repository_id) {
    return {
      contract: validateModelContract(normalizedKey, bundledCandidate, { source: 'bundled-canary' }),
      source: 'bundled-canary',
    };
  }

  if (options.required === false) return null;
  throw new ModelContractError(
    legacyPath ? 'MODEL_CONTRACT_MISSING_FOR_CONFIGURED_PATH' : 'MODEL_CONTRACT_UNRESOLVED',
    legacyPath
      ? `${normalizedKey} has a configured model repository but no qualified HF_MODEL_CONTRACTS entry.`
      : `${normalizedKey} is missing from HF_MODEL_CONTRACTS.`,
    { modelKey: normalizedKey, source: 'environment' },
  );
}

function environmentModelContract(modelKey, options = {}) {
  return runtimeModelContract(modelKey, options)?.contract || null;
}

function canonicalContractValue(value) {
  if (Array.isArray(value)) return value.map(canonicalContractValue);
  if (!isPlainObject(value)) return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalContractValue(value[key])]));
}

function contractIdentity(contract) {
  return JSON.stringify(canonicalContractValue({
    registry_schema: contract.registry_schema,
    repository_id: contract.repository_id,
    revision_sha: contract.revision_sha,
    provider: contract.provider,
    task: contract.task,
    ordered_labels: contract.ordered_labels || null,
    label_map: contract.label_map || null,
    thresholds: contract.thresholds || null,
    score_sum_tolerance: contract.score_sum_tolerance ?? null,
  }));
}

function resolveModelContract(modelKey, candidate, options = {}) {
  let runtime = null;
  if (options.allowEnvironmentFallback || options.requireRuntimeMatch) {
    runtime = runtimeModelContract(modelKey, { required: Boolean(options.requireRuntimeMatch) });
  }

  if (candidate) {
    try {
      const contract = validateModelContract(modelKey, candidate, { source: options.source || 'database' });
      if (runtime && contractIdentity(contract) !== contractIdentity(runtime.contract)) {
        throw new ModelContractError(
          'MODEL_RUNTIME_REGISTRY_MISMATCH',
          `${modelKey} database and runtime model contracts disagree.`,
          { modelKey, source: options.source || 'database' },
        );
      }
      return { contract, source: options.source || 'database' };
    } catch (error) {
      // Runtime fallback is available only to callers that do not require a
      // persisted identity match. Gateway evidence must bind the exact database
      // contract it executed, so incomplete or divergent registry rows fail
      // closed instead of being mislabeled as a different persisted version.
      if (options.requireRuntimeMatch || error.code === 'MODEL_RUNTIME_REGISTRY_MISMATCH' || !runtime) throw error;
      return runtime;
    }
  }
  return runtime || runtimeModelContract(modelKey, { required: true });
}

function modelContractReadiness(modelKey) {
  try {
    const resolved = runtimeModelContract(modelKey, { required: false });
    if (!resolved) {
      const legacyModelConfigured = Boolean(configuredLegacyPath(String(modelKey || '').trim().toLowerCase()));
      return {
        ready: false,
        code: legacyModelConfigured
          ? 'MODEL_CONTRACT_MISSING_FOR_CONFIGURED_PATH'
          : 'MODEL_CONTRACT_UNRESOLVED',
        legacy_model_configured: legacyModelConfigured,
      };
    }
    return {
      ready: true,
      source: resolved.source,
      qualification_state: resolved.contract.qualification_state,
      provider: resolved.contract.provider,
      task: resolved.contract.task,
      legacy_model_configured: Boolean(configuredLegacyPath(String(modelKey || '').trim().toLowerCase())),
    };
  } catch (error) {
    return { ready: false, code: error.code || 'MODEL_CONTRACT_INVALID' };
  }
}

module.exports = {
  MODEL_DEFINITIONS,
  ModelContractError,
  REGISTRY_SCHEMA,
  environmentModelContract,
  contractIdentity,
  modelContractReadiness,
  parseContractMap,
  resolveModelContract,
  runtimeModelContract,
  validateModelContract,
};
