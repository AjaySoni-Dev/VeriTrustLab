function clamp01(value) {
  return Math.max(0, Math.min(1, Number(value) || 0));
}

function gatewayRiskLevel(score, verdict) {
  const normalizedVerdict = String(verdict || '').toLowerCase();
  if (['low', 'medium', 'high', 'critical'].includes(normalizedVerdict)) return normalizedVerdict;
  const value = clamp01(score);
  if (value >= 0.9) return 'critical';
  if (value >= 0.75) return 'high';
  if (value >= 0.45) return 'medium';
  return 'low';
}

function newestFirst(left, right) {
  return Date.parse(right?.created_at || 0) - Date.parse(left?.created_at || 0);
}

function selectDecision(scan, decisions) {
  const rows = [...(decisions || [])].sort((left, right) => {
    const sequence = Number(right.sequence || 0) - Number(left.sequence || 0);
    return sequence || newestFirst(left, right);
  });
  return rows.find((row) => row.id === scan.final_decision_id)
    || rows.find((row) => row.decision_kind === 'final')
    || rows.find((row) => row.id === scan.preliminary_decision_id)
    || rows.find((row) => row.decision_kind === 'preliminary')
    || rows[0]
    || null;
}

function readableReason(value) {
  return String(value || '').replaceAll('_', ' ').trim();
}

function evidenceConfidence(evidence) {
  const values = (evidence || [])
    .filter((row) => row.status === 'completed')
    .map((row) => Number(row.confidence_value))
    .filter(Number.isFinite)
    .map(clamp01);
  return values.length ? Math.max(...values) : 0;
}

function evidenceIndicators(evidence, reasonCodes) {
  const reasons = (reasonCodes || []).map(readableReason).filter(Boolean);
  const indicators = (evidence || []).flatMap((row) => Array.isArray(row.indicators) ? row.indicators : []);
  return [...reasons, ...indicators];
}

function normalizeGatewayScan(scan, decisions = [], evidence = []) {
  const selectedDecision = selectDecision(scan, decisions);
  const riskScore = clamp01(selectedDecision?.risk_score);
  const riskLevel = selectedDecision
    ? gatewayRiskLevel(riskScore, selectedDecision.verdict)
    : 'unknown';
  const confidence = evidenceConfidence(evidence);
  const reasonCodes = Array.isArray(selectedDecision?.reason_codes) ? selectedDecision.reason_codes : [];
  const indicators = evidenceIndicators(evidence, reasonCodes);
  const recommendation = selectedDecision?.recommendation || null;
  const verdict = selectedDecision?.verdict || scan.status || 'unknown';
  const modelKeys = [...new Set((evidence || []).map((row) => row.model_key).filter(Boolean))];
  const explanation = selectedDecision
    ? `Unified gateway recommendation: ${readableReason(recommendation || 'review')}.`
    : `Unified gateway scan is ${readableReason(scan.status || 'processing')}.`;

  return {
    id: scan.id,
    org_id: scan.org_id,
    user_id: scan.submitted_by || null,
    scan_type: 'gateway',
    status: scan.status,
    selected_model_key: 'gateway',
    fallback_model_key: null,
    final_label: verdict,
    confidence,
    risk_level: riskLevel,
    source: scan.source || 'api',
    error_message: scan.failure_code || null,
    created_at: scan.created_at,
    completed_at: scan.completed_at || null,
    metadata: {
      ...(scan.metadata || {}),
      logical_scan_type: 'gateway',
      record_kind: 'gateway',
      gateway: {
        display_id: scan.display_id,
        processing_mode: scan.processing_mode,
        source: scan.source || 'api',
        degraded: Boolean(scan.degraded || selectedDecision?.degraded),
        decision_id: selectedDecision?.id || null,
        decision_kind: selectedDecision?.decision_kind || null,
        risk_score: riskScore,
        recommendation,
        reason_codes: reasonCodes,
        policy_version_id: selectedDecision?.policy_version_id || scan.policy_version_id || null,
        correlation_version: selectedDecision?.correlation_version || scan.correlation_version || null,
        model_keys: modelKeys,
        evidence_count: evidence.length,
      },
    },
    scan_inputs: [{
      input_kind: 'gateway',
      text_preview: null,
      metadata: {
        display_id: scan.display_id,
        source: scan.source || 'api',
        processing_mode: scan.processing_mode,
      },
    }],
    scan_results: selectedDecision ? [{
      label: verdict,
      confidence,
      risk_level: riskLevel,
      primary_score: riskScore,
      secondary_score: null,
      explanation,
      indicators,
      raw_scores: (evidence || []).map((row) => ({
        model_key: row.model_key,
        model_version: row.model_version,
        status: row.status,
        score: row.score === null || row.score === undefined ? null : Number(row.score),
        verdict: row.verdict,
        confidence: row.confidence,
        confidence_value: row.confidence_value === null || row.confidence_value === undefined
          ? null
          : Number(row.confidence_value),
        indicators: Array.isArray(row.indicators) ? row.indicators : [],
        reason_codes: row.reason_codes || [],
      })),
    }] : [],
    scan_model_runs: [],
  };
}

function mergeScanHistories(regularScans, gatewayScans, limit = 20) {
  const safeLimit = Math.max(1, Math.min(100, Number(limit) || 20));
  const byIdentity = new Map();
  for (const scan of [...(regularScans || []), ...(gatewayScans || [])]) {
    if (!scan?.id) continue;
    const key = `${scan.metadata?.record_kind || 'scan'}:${scan.id}`;
    byIdentity.set(key, scan);
  }
  return [...byIdentity.values()].sort(newestFirst).slice(0, safeLimit);
}

module.exports = {
  gatewayRiskLevel,
  mergeScanHistories,
  normalizeGatewayScan,
  selectDecision,
};
