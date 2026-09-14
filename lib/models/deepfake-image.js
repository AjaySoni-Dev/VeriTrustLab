const { runDeepfakeDetection } = require('../detection-service');

async function execute(artifact, options = {}) {
  if (!artifact?.upload?.buffer) {
    return {
      attempts: [],
      evidence: {
        artifactId: artifact?.id,
        kind: 'deepfake_image',
        modelKey: options.modelKey || 'pixel',
        status: 'pending',
        score: null,
        verdict: 'unknown',
        confidence: 'unknown',
        confidenceValue: null,
        indicators: [],
        reasonCodes: ['MEDIA_WORKER_REQUIRED'],
        degraded: false,
        required: options.required !== false,
      },
    };
  }
  const started = Date.now();
  try {
    const result = await runDeepfakeDetection({ upload: artifact.upload, modelKey: options.modelKey || 'pixel' });
    const payload = result.payload;
    const score = Number(payload.result.fake_score);
    return {
      attempts: result.modelRuns || [],
      evidence: {
        artifactId: artifact.id,
        kind: 'deepfake_image',
        modelKey: payload.model.key,
        status: 'completed',
        score,
        verdict: score >= 0.75 ? 'manipulated' : score >= 0.45 ? 'suspicious' : 'safe',
        confidence: Number(payload.result.confidence) >= 0.85 ? 'high' : Number(payload.result.confidence) >= 0.65 ? 'medium' : 'low',
        confidenceValue: Number(payload.result.confidence),
        indicators: payload.result.indicators || [],
        reasonCodes: score >= 0.75 ? ['MANIPULATED_MEDIA'] : [],
        degraded: Boolean(payload.model.fallback_used),
        required: options.required !== false,
        latencyMs: Date.now() - started,
        rawResponseRedacted: { label: payload.result.label },
      },
    };
  } catch (error) {
    return {
      attempts: error.modelRuns || [],
      evidence: {
        artifactId: artifact.id,
        kind: 'deepfake_image',
        modelKey: options.modelKey || 'pixel',
        status: 'failed',
        score: null,
        verdict: 'unknown',
        confidence: 'unknown',
        confidenceValue: null,
        indicators: [],
        reasonCodes: ['DEEPFAKE_MODEL_UNAVAILABLE'],
        degraded: true,
        required: options.required !== false,
        latencyMs: Date.now() - started,
        errorCode: error.code || 'MODEL_ERROR',
        rawResponseRedacted: { error_code: error.code || 'MODEL_ERROR' },
      },
    };
  }
}

module.exports = {
  execute,
  supports(artifact) { return artifact?.type === 'image'; },
};
