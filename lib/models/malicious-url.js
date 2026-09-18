const { runLinkDetection } = require('../detection-service');
const { mapWithConcurrency } = require('../gateway/execution');

function confidenceBand(value) {
  const normalized = String(value || '').toLowerCase();
  if (['strong', 'high'].includes(normalized)) return 'high';
  if (['moderate', 'medium'].includes(normalized)) return 'medium';
  if (['weak', 'low'].includes(normalized)) return 'low';
  return 'unknown';
}

function verdictForResult(result) {
  const label = String(result.label || '').toLowerCase();
  if (['malicious', 'phishing'].includes(label) || Number(result.link_score) >= 0.75) return 'malicious';
  if (label === 'suspicious' || Number(result.link_score) >= 0.45) return 'suspicious';
  return 'safe';
}

async function execute(artifact, options = {}) {
  const started = Date.now();
  try {
    const result = await runLinkDetection({
      url: artifact.content,
      modelKey: options.modelKey || 'swift',
      allowProviderFallback: Boolean(options.allowProviderFallback),
      allowLocalFallback: false,
      timeoutMs: options.timeoutMs,
      // prepareModelRun has already required the persisted registry identity to
      // match the runtime contract. Execute with the runtime contract exactly
      // as the working standalone route does; do not inject a JSONB-derived
      // object into the detector.
    });
    const payload = result.payload;
    const score = Number(payload.result.link_score);
    const indicators = Array.isArray(payload.result.indicators) ? payload.result.indicators : [];
    return {
      attempts: result.modelRuns || [],
      evidence: {
        artifactId: artifact.id,
        kind: 'link',
        modelKey: payload.model.key,
        status: 'completed',
        score,
        verdict: verdictForResult(payload.result),
        confidence: confidenceBand(payload.result.confidence_band),
        confidenceValue: Number(payload.result.confidence),
        indicators,
        reasonCodes: [...new Set(indicators.map((item) => item?.type ? `URL_${String(item.type).toUpperCase()}` : null).filter(Boolean))],
        degraded: Boolean(payload.model.fallback_used),
        required: options.required !== false,
        latencyMs: Date.now() - started,
        rawResponseRedacted: {
          label: payload.result.label,
          model_score: payload.result.model_score,
          rule_score: payload.result.rule_score,
          hostname: payload.result.extracted?.hostname || null,
          query_present: Boolean(payload.result.extracted?.query_present),
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
        kind: 'link',
        modelKey: options.modelKey || 'swift',
        status: error.name === 'TimeoutError' || /TIMEOUT/u.test(errorCode) ? 'timed_out' : 'failed',
        score: null,
        verdict: 'unknown',
        confidence: 'unknown',
        confidenceValue: null,
        indicators: [],
        reasonCodes: ['LINK_MODEL_UNAVAILABLE', errorCode],
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

async function executeBatch(artifacts, options = {}) {
  if (!Array.isArray(artifacts) || !artifacts.length) return [];
  // HF text classification accepts one string per request. Reuse the exact
  // standalone Swift path for every child and await the bounded group.
  return mapWithConcurrency(
    artifacts,
    options.concurrency || 1,
    (artifact) => execute(artifact, options),
  );
}

module.exports = {
  execute,
  executeBatch,
  supports(artifact) { return artifact?.type === 'url'; },
};
