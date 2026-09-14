// Private route implementation; api/system.js is the Vercel entrypoint.
const {
  handleApiError,
  handleOptions,
  requireMethod,
  sendJson,
} = require('../../veritrust-api');
const { serverConfig } = require('../../config');
const { MODULE_CONFIG } = require('../../modules');
const { MAX_IMAGE_BYTES } = require('../../validators');

module.exports = async function handler(req, res) {
  if (handleOptions(req, res)) return;

  try {
    requireMethod(req, 'GET');
    sendJson(res, 200, {
      ok: true,
      config: {
        ...(MODULE_CONFIG.deepfake ? {
          cropApiUrl: 'https://ajaysoni-dev-deepfakefusion.hf.space/api/crop-image',
          cropOutputBaseUrl: 'https://ajaysoni-dev-deepfakefusion.hf.space',
          maxImageBytes: MAX_IMAGE_BYTES,
        } : {}),
        modules: MODULE_CONFIG,
        supabase: {
          url: serverConfig.supabaseUrl,
          anonKey: serverConfig.supabaseAnonKey,
        },
        api: {
          health: '/api/health',
          ...(MODULE_CONFIG.deepfake ? { deepfake: '/api/deepfake' } : {}),
          ...(MODULE_CONFIG.link ? { linkCheck: '/api/link-check' } : {}),
          ...(MODULE_CONFIG.phishing ? {
            phishing: '/api/phishing',
            emailAnalyzeText: '/api/v1/gateway/email/analyze-text',
            emailAnalyzeEml: '/api/v1/gateway/email/analyze-eml',
            emailEvidence: '/api/v2/phishing/evidence',
          } : {}),
          session: '/api/session',
          scans: '/api/scans',
          cases: '/api/cases',
          apiKeys: '/api/api-keys',
          dashboard: '/api/dashboard',
          authSession: '/api/auth-session',
          profile: '/api/profile',
          privacy: '/api/privacy',
          jobs: '/api/jobs',
          modelCards: '/api/model-cards',
        },
      },
    });
  } catch (error) {
    handleApiError(res, error, 'Client configuration is unavailable.');
  }
};
