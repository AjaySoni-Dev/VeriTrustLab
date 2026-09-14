// Private route implementation; api/system.js is the Vercel entrypoint.
const {
  DEEPFAKE_MODELS,
  PHISHING_MODELS,
  constantTimeEqual,
  handleApiError,
  handleOptions,
  requireMethod,
  sendJson,
} = require('../../veritrust-api');
const { getOptionalEnv, serverConfig } = require('../../config');
const {
  isServiceRoleConfigured,
  isSupabaseConfigured,
} = require('../../supabase-server');
const { platformHealth } = require('../../platform');
const { isModuleEnabled, sanitizeModuleData } = require('../../modules');
const { modelContractReadiness } = require('../../model-contracts');
const { modelRegistryHealth } = require('../../gateway/persistence');

module.exports = async function handler(req, res) {
  if (handleOptions(req, res)) return;

  try {
    requireMethod(req, 'GET');

    const payload = {
      ok: true,
      service: 'VeriTrust API',
      status: 'operational',
      release: 'mailgraph-model-run-timestamp-guard-2026-08-23',
      timestamp: new Date().toISOString(),
    };

    const adminSecret = serverConfig.adminSecret;
    const providedSecret = String(req.headers['x-veritrust-admin-secret'] || '').trim();
    if (constantTimeEqual(providedSecret, adminSecret)) {
      let databaseHealth = null;
      let databaseHealthError = null;
      let databaseModelRegistry = null;
      let databaseModelRegistryError = null;
      if (isServiceRoleConfigured()) {
        try {
          databaseHealth = await platformHealth();
        } catch (error) {
          databaseHealthError = error.code || 'PLATFORM_HEALTH_UNAVAILABLE';
        }
        try {
          databaseModelRegistry = await modelRegistryHealth();
        } catch (error) {
          databaseModelRegistryError = error.code || 'MODEL_REGISTRY_HEALTH_UNAVAILABLE';
        }
      }
      payload.diagnostics = {
        runtime: 'vercel-node',
        supabase_configured: isSupabaseConfigured(),
        supabase_service_role_configured: isServiceRoleConfigured(),
        hf_configured: Boolean(getOptionalEnv('HF_TOKEN') || getOptionalEnv('HF_ACCESS_TOKEN')),
        hf_token_configured: Boolean(getOptionalEnv('HF_TOKEN') || getOptionalEnv('HF_ACCESS_TOKEN')),
        model_contracts: {
          ...(isModuleEnabled('phishing') ? {
            mailguard: modelContractReadiness('mailguard'),
            cortex: modelContractReadiness('cortex'),
          } : {}),
          ...(isModuleEnabled('link') ? { swift: modelContractReadiness('swift') } : {}),
          ...(isModuleEnabled('deepfake') ? {
            pixel: modelContractReadiness('pixel'),
            prism: modelContractReadiness('prism'),
          } : {}),
        },
        allowed_origin_count: serverConfig.allowedOrigins.length,
        ...(isModuleEnabled('deepfake') ? { deepfake_models: Object.values(DEEPFAKE_MODELS).map((item) => item.display_name) } : {}),
        ...(isModuleEnabled('phishing') ? { phishing_models: Object.values(PHISHING_MODELS).map((item) => item.display_name) } : {}),
        database: databaseHealth,
        database_health_error: databaseHealthError,
        database_model_registry: databaseModelRegistry,
        database_model_registry_error: databaseModelRegistryError,
      };
    }

    sendJson(res, 200, sanitizeModuleData(payload));
  } catch (error) {
    handleApiError(res, error, 'Health check failed.');
  }
};
