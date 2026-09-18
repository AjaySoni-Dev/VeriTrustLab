const { runPhishingDetection } = require('../detection-service');

function confidenceBand(value) {
  const normalized = String(value || '').toLowerCase();
  if (['strong', 'high'].includes(normalized)) return 'high';
  if (['moderate', 'medium'].includes(normalized)) return 'medium';
  if (['weak', 'low'].includes(normalized)) return 'low';
  return 'unknown';
}

function verdictForState(state) {
  if (state === 'LIKELY_PHISHING') return 'malicious';
  if (state === 'LIKELY_BENIGN') return 'safe';
  return 'unknown';
}

function reasonCodes(indicators) {
  return [...new Set((indicators || []).map((item) => {
    const type = typeof item === 'object' ? item.type : null;
    return type ? `PHISHING_${String(type).toUpperCase()}` : null;
  }).filter(Boolean))];
}

async function execute(artifact, options = {}) {
  const started = Date.now();
  try {
    const result = await runPhishingDetection({
      text: artifact.content,
      modelKey: options.modelKey || 'mailguard',
      allowProviderFallback: Boolean(options.allowProviderFallback),
      allowLocalFallback: false,
      timeoutMs: options.timeoutMs,
      // The Gateway registry binding is validated before this adapter runs.
      // Runtime inference intentionally resolves the same immutable environment
      // contract used by the standalone detector.
    });
    const payload = result.payload;
    const score = payload.result.phishing_score === null ? null : Number(payload.result.phishing_score);
    const indicators = Array.isArray(payload.result.indicators) ? payload.result.indicators : [];
    return {
      attempts: result.modelRuns || [],
      evidence: {
        artifactId: artifact.id,
        kind: 'phishing',
        modelKey: payload.model.key,
        status: Number.isFinite(score) ? 'completed' : 'not_applicable',
        score,
        verdict: verdictForState(payload.result.state),
        confidence: confidenceBand(payload.result.confidence_band),
        confidenceValue: payload.result.confidence === null || payload.result.confidence === undefined ? null : Number(payload.result.confidence),
        indicators,
        reasonCodes: reasonCodes(indicators),
        degraded: Boolean(payload.model.fallback_used),
        required: options.required !== false,
        latencyMs: Date.now() - started,
        rawResponseRedacted: {
          label: payload.result.label,
          model_score: payload.result.model_score,
          rule_score: payload.result.rule_score,
          state: payload.result.state,
          semantic_extraction: payload.result.semantic_extraction || null,
          module_contract_version: options.moduleContractVersion || null,
          module_correlation_id: options.moduleCorrelationId || null,
        },
      },
    };
  } catch (error) {
    const errorCode = String(error.code || 'MODEL_RUNTIME_ERROR');
    return {
      attempts: error.modelRuns || [],
      evidence: {
        artifactId: artifact.id,
        kind: 'phishing',
        modelKey: options.modelKey || 'mailguard',
        status: error.name === 'TimeoutError' || /TIMEOUT/u.test(errorCode) ? 'timed_out' : 'failed',
        score: null,
        verdict: 'unknown',
        confidence: 'unknown',
        confidenceValue: null,
        indicators: [],
        reasonCodes: ['PHISHING_MODEL_UNAVAILABLE', errorCode],
        degraded: true,
        required: options.required !== false,
        latencyMs: Date.now() - started,
        errorCode,
        rawResponseRedacted: {
          error_code: errorCode,
          upstream_status: Number(error?.extra?.status) || null,
          stage: error?.extra?.stage || null,
          runtime_error_name: error?.extra?.runtime_error_name || error?.name || null,
          module_contract_version: options.moduleContractVersion || null,
          module_correlation_id: options.moduleCorrelationId || null,
        },
      },
    };
  }
}

module.exports = {
  execute,
  supports(artifact) { return artifact?.type === 'text'; },
};
