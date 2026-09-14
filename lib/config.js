class ConfigError extends Error {
  constructor(name, options = {}) {
    super(options.invalid
      ? `Server configuration variable ${name} contains an invalid value.`
      : `Server configuration is missing required environment variable: ${name}.`);
    this.name = 'ConfigError';
    this.status = 500;
    this.code = options.invalid ? 'CONFIG_INVALID' : 'CONFIG_MISSING';
    this.envName = name;
  }
}

function cleanEnvValue(value) {
  let cleaned = String(value || '').trim();
  const lines = cleaned.split(/\r?\n/u).map((line) => line.trim()).filter(Boolean);
  // Vercel values are occasionally pasted multiple times on separate lines.
  // Collapsing only byte-for-byte identical lines is deterministic and avoids
  // silently choosing between different credentials.
  if (lines.length > 1 && new Set(lines).size === 1) cleaned = lines[0];
  return cleaned || null;
}

function assertHeaderSafe(value, name) {
  if (/[\u0000-\u001f\u007f]/u.test(value)) throw new ConfigError(name, { invalid: true });
  return value;
}

function getRequiredHeaderEnv(name) {
  return assertHeaderSafe(getRequiredEnv(name), name);
}

function getRequiredEnv(name) {
  const value = cleanEnvValue(process.env[name]);
  if (!value) {
    throw new ConfigError(name);
  }
  return value;
}

function getOptionalEnv(name, fallback = '') {
  const value = cleanEnvValue(process.env[name]);
  return value === null ? fallback : value;
}

function getOptionalEnvAliases(names, fallback = '') {
  for (const name of names) {
    const value = cleanEnvValue(process.env[name]);
    if (value !== null) return value;
  }
  return fallback;
}

function getRequiredEnvAliases(names) {
  const value = getOptionalEnvAliases(names, '');
  if (!value) throw new ConfigError(names.join(' or '));
  return value;
}

function getOptionalInteger(name, fallback, options = {}) {
  const raw = getOptionalEnv(name, '');
  if (!raw) return fallback;
  const value = Number(raw);
  const minimum = options.minimum ?? Number.MIN_SAFE_INTEGER;
  const maximum = options.maximum ?? Number.MAX_SAFE_INTEGER;
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    const error = new Error(`Server configuration variable ${name} must be an integer between ${minimum} and ${maximum}.`);
    error.name = 'ConfigError';
    error.status = 500;
    error.code = 'CONFIG_INVALID';
    throw error;
  }
  return value;
}

const MODEL_ENV_NAMES = Object.freeze({
  deepfake_pixel: 'HF_DEEPFAKE_PIXEL_MODEL',
  deepfake_prism: 'HF_DEEPFAKE_PRISM_MODEL',
  phishing_mailguard: 'HF_PHISHING_MAILGUARD_MODEL',
  phishing_cortex: 'HF_PHISHING_CORTEX_MODEL',
  link_swift: 'HF_LINK_SWIFT_MODEL',
});

const VERITRUST_RUNTIME_DEFAULTS = Object.freeze({
  siteUrl: 'https://www.veritrustlab.in',
  allowedOrigins: Object.freeze(['https://www.veritrustlab.in', 'https://veritrustlab.in']),
  gatewaySynchronousBudgetMs: 55000,
  gatewayServerlessBatch: 1,
  gatewayModelConcurrency: 1,
});

function modelPathMap() {
  const raw = getOptionalEnv('HF_MODEL_PATHS', '');
  if (!raw) return {};
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('not an object');
    return parsed;
  } catch {
    throw new ConfigError('HF_MODEL_PATHS', { invalid: true });
  }
}

function validateModelPath(value, envName) {
  const path = assertHeaderSafe(String(value || '').trim(), envName);
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,95}\/[A-Za-z0-9][A-Za-z0-9._-]{0,95}$/u.test(path)) {
    throw new ConfigError(envName, { invalid: true });
  }
  return path;
}

function getModelPath(modelKey) {
  const normalizedKey = String(modelKey || '').trim().toLowerCase();
  const envName = MODEL_ENV_NAMES[normalizedKey];
  if (!envName) throw new ConfigError('HF model key', { invalid: true });
  const mapped = modelPathMap()[normalizedKey];
  const direct = getOptionalEnv(envName, '');
  const legacyDefault = normalizedKey === 'deepfake_pixel' ? getOptionalEnv('HF_MODEL_PATH', '') : '';
  const value = direct || mapped || legacyDefault;
  if (!value) throw new ConfigError(`${envName} or HF_MODEL_PATHS`);
  return validateModelPath(value, direct ? envName : (mapped ? 'HF_MODEL_PATHS' : 'HF_MODEL_PATH'));
}

function parseAllowedOrigins(value = VERITRUST_RUNTIME_DEFAULTS.allowedOrigins.join(',')) {
  const origins = String(value || '')
    .split(',')
    .map((origin) => origin.trim().replace(/\/$/, ''))
    .filter(Boolean)
    .map((origin) => {
      let parsed;
      try {
        parsed = new URL(origin);
      } catch {
        throw new ConfigError('VERITRUST_ALLOWED_ORIGINS', { invalid: true });
      }
      if (!['https:', 'http:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash) {
        throw new ConfigError('VERITRUST_ALLOWED_ORIGINS', { invalid: true });
      }
      return parsed.origin;
    });
  return [...new Set(origins.length ? origins : VERITRUST_RUNTIME_DEFAULTS.allowedOrigins)];
}

function configuredSiteUrl() {
  const value = getOptionalEnv('VERITRUST_SITE_URL', VERITRUST_RUNTIME_DEFAULTS.siteUrl).replace(/\/$/, '');
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new ConfigError('VERITRUST_SITE_URL', { invalid: true });
  }
  if (!['https:', 'http:'].includes(parsed.protocol) || parsed.username || parsed.password) {
    throw new ConfigError('VERITRUST_SITE_URL', { invalid: true });
  }
  return parsed.origin;
}

const serverConfig = {
  get supabaseUrl() {
    return getRequiredEnv('SUPABASE_URL').replace(/\/$/, '');
  },
  get supabaseAnonKey() {
    return getRequiredHeaderEnv('SUPABASE_ANON_KEY');
  },
  get supabaseServiceRoleKey() {
    return getRequiredHeaderEnv('SUPABASE_SERVICE_ROLE_KEY');
  },
  get hfToken() {
    const name = getOptionalEnv('HF_TOKEN') ? 'HF_TOKEN' : 'HF_ACCESS_TOKEN';
    return getRequiredHeaderEnv(name);
  },
  modelPath(modelKey) {
    return getModelPath(modelKey);
  },
  get adminSecret() {
    return getOptionalEnvAliases(['VERITRUST_ADMIN_SECRET', 'ADMIN'], '');
  },
  get gatewayContentHmacKey() {
    return getRequiredEnvAliases(['VERITRUST_CONTENT_HMAC_KEY', 'CONTENT_HMAC']);
  },
  get gatewaySynchronousBudgetMs() {
    return VERITRUST_RUNTIME_DEFAULTS.gatewaySynchronousBudgetMs;
  },
  get gatewayWorkerId() {
    return getOptionalEnv('VERITRUST_GATEWAY_WORKER_ID', 'veritrust-worker-1');
  },
  get gatewayDispatchSecret() {
    return getRequiredEnvAliases(['VERITRUST_GATEWAY_DISPATCH_SECRET', 'DISPATCH']);
  },
  get gatewayServerlessBatch() {
    return VERITRUST_RUNTIME_DEFAULTS.gatewayServerlessBatch;
  },
  get gatewayModelConcurrency() {
    return VERITRUST_RUNTIME_DEFAULTS.gatewayModelConcurrency;
  },
  get gatewayWebhookEncryptionKey() {
    return getRequiredEnvAliases(['VERITRUST_WEBHOOK_ENCRYPTION_KEY', 'WEBHOOK_ENCRYPTION']);
  },
  get emailReceiverSecret() {
    return getRequiredEnv('VERITRUST_EMAIL_RECEIVER_SECRET');
  },
  get allowedOrigins() {
    return parseAllowedOrigins(getOptionalEnv('VERITRUST_ALLOWED_ORIGINS', VERITRUST_RUNTIME_DEFAULTS.allowedOrigins.join(',')));
  },
  get siteUrl() {
    return configuredSiteUrl();
  },
};

const allowedOrigins = parseAllowedOrigins(getOptionalEnv('VERITRUST_ALLOWED_ORIGINS', VERITRUST_RUNTIME_DEFAULTS.allowedOrigins.join(',')));

module.exports = {
  ConfigError,
  MODEL_ENV_NAMES,
  VERITRUST_RUNTIME_DEFAULTS,
  allowedOrigins,
  cleanEnvValue,
  getModelPath,
  getOptionalEnv,
  getOptionalEnvAliases,
  getOptionalInteger,
  getRequiredEnv,
  getRequiredHeaderEnv,
  getRequiredEnvAliases,
  parseAllowedOrigins,
  serverConfig,
};
