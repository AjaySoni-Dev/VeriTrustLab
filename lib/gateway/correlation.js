const { CORRELATION_VERSION } = require('./contracts');
const { applyEnforcementGuard, recommendationForScore } = require('./policy');

const SEVERITY_SCORE = Object.freeze({ low: 0.1, medium: 0.45, high: 0.75, critical: 0.9, unknown: 0.5 });
const ACTION_PRIORITY = Object.freeze({ allow: 0, warn: 1, manual_review: 2, hold: 3, quarantine: 4, block: 5 });

function clamp01(value) {
  return Math.max(0, Math.min(1, Number(value) || 0));
}

function scoreSeverity(score) {
  const value = clamp01(score);
  if (value >= 0.9) return 'critical';
  if (value >= 0.75) return 'high';
  if (value >= 0.45) return 'medium';
  return 'low';
}

function maxAction(left, right) {
  return ACTION_PRIORITY[right] > ACTION_PRIORITY[left] ? right : left;
}

function normalizeEvidence(evidence) {
  const status = String(evidence.status || 'failed');
  const score = status === 'completed' && evidence.score !== null && evidence.score !== undefined && Number.isFinite(Number(evidence.score)) ? clamp01(evidence.score) : null;
  return {
    ...evidence,
    id: evidence.id || null,
    kind: String(evidence.kind || evidence.model || 'unknown'),
    status,
    score,
    verdict: String(evidence.verdict || 'unknown').toLowerCase(),
    confidence: String(evidence.confidence || 'unknown').toLowerCase(),
    reasonCodes: Array.isArray(evidence.reasonCodes) ? evidence.reasonCodes.map(String) : [],
    required: Boolean(evidence.required),
  };
}

function containsContext(context, names) {
  const values = new Set((context || []).map((value) => String(value).toLowerCase()));
  return names.some((name) => values.has(name));
}

function deterministicEmailRisk(reasonCodes) {
  const codes = new Set(reasonCodes || []);
  const has = (code) => codes.has(code);
  const identityMismatch = ['REPLY_TO_DOMAIN_DIFFERS', 'RETURN_PATH_DOMAIN_DIFFERS', 'SENDER_DOMAIN_DIFFERS', 'MESSAGE_ID_DOMAIN_DIFFERS', 'LINK_DOMAIN_UNRELATED_TO_AUTHOR']
    .some(has);
  const verifiedAuthFailure = [...codes].some((code) => /^(?:SPF|DKIM|DMARC|ARC)_(?:FAIL|TEMPERROR|PERMERROR)$/u.test(code));
  const contentLure = ['CREDENTIAL_REQUEST', 'PAYMENT_REQUEST', 'URGENCY_OR_COERCION', 'ATTACHMENT_LURE', 'QR_OR_LINK_LURE', 'IMPERSONATION_CLAIM']
    .some(has);
  let score = 0;

  if (has('CREDENTIAL_REQUEST')) score = Math.max(score, 0.4);
  if (has('PAYMENT_REQUEST') || has('ATTACHMENT_LURE') || has('QR_OR_LINK_LURE')) score = Math.max(score, 0.35);
  if (has('VISIBLE_URL_DIFFERS_FROM_HREF')) score = Math.max(score, 0.55);
  if (has('OBFUSCATED_LINK_TEXT') || has('AI_INPUT_OBFUSCATION') || has('HTML_HIDDEN_CONTENT')) score = Math.max(score, 0.5);
  if (has('HTML_META_REFRESH') || has('UNICODE_DIRECTIONAL_CONTROL')) score = Math.max(score, 0.6);
  if (has('IDENTITY_DOMAIN_CONFUSABLE')) score = Math.max(score, 0.75);
  if (has('INFRASTRUCTURE_IP_HIGH_ABUSE_REPUTATION')) score = Math.max(score, 0.62);
  if (has('INFRASTRUCTURE_IP_ELEVATED_ABUSE_REPUTATION')) score = Math.max(score, 0.4);
  if (has('DOMAIN_REGISTERED_WITHIN_30_DAYS') && (contentLure || identityMismatch)) score = Math.max(score, 0.6);
  if (has('DOMAIN_REGISTERED_WITHIN_90_DAYS') && contentLure && identityMismatch) score = Math.max(score, 0.56);
  if (contentLure && identityMismatch) score = Math.max(score, 0.58);
  if (has('VISIBLE_URL_DIFFERS_FROM_HREF') && identityMismatch) score = Math.max(score, 0.65);
  if (has('CREDENTIAL_REQUEST') && has('VISIBLE_URL_DIFFERS_FROM_HREF')) score = Math.max(score, 0.68);
  if (verifiedAuthFailure && (contentLure || identityMismatch)) score = Math.max(score, 0.72);

  return Number(score.toFixed(6));
}

function correlate(rawEvidence, policy, options = {}) {
  const evidence = rawEvidence.map(normalizeEvidence).sort((a, b) => {
    const left = `${a.kind}:${a.artifactId || ''}:${a.modelKey || ''}:${a.id || ''}`;
    const right = `${b.kind}:${b.artifactId || ''}:${b.modelKey || ''}:${b.id || ''}`;
    return left.localeCompare(right);
  });
  const completed = evidence.filter((item) => item.status === 'completed');
  const unresolved = evidence.filter((item) => ['pending', 'queued', 'leased', 'running'].includes(item.status));
  const requiredFailures = evidence.filter((item) => item.required && ['failed', 'timed_out', 'cancelled'].includes(item.status));
  const reasonCodes = new Set(completed.flatMap((item) => item.reasonCodes));
  if (policy.correlation_version && policy.correlation_version !== CORRELATION_VERSION) {
    reasonCodes.add('POLICY_CORRELATION_COMPATIBILITY_UPGRADE');
  }
  const scored = completed.filter((item) => item.score !== null);
  let risk = scored.reduce((maximum, item) => Math.max(maximum, item.score), 0);
  const deterministicRisk = deterministicEmailRisk(reasonCodes);
  if (deterministicRisk > 0) {
    risk = Math.max(risk, deterministicRisk);
    reasonCodes.add('DETERMINISTIC_EMAIL_RISK');
  }
  let verdict = 'unknown';

  const maliciousLinks = completed.filter((item) => item.kind === 'link' && item.score !== null && item.score >= 0.75 && ['malicious', 'suspicious'].includes(item.verdict));
  if (maliciousLinks.length) {
    risk = Math.max(risk, 0.75);
    reasonCodes.add('MALICIOUS_URL');
  }

  const phishing = completed.filter((item) => item.kind === 'phishing' && item.score !== null).reduce((maximum, item) => Math.max(maximum, item.score), 0);
  const link = completed.filter((item) => item.kind === 'link' && item.score !== null).reduce((maximum, item) => Math.max(maximum, item.score), 0);
  if (phishing >= 0.55 && link >= 0.45) {
    reasonCodes.add('PHISHING_LINK_INTERACTION');
  }

  const identityMismatch = reasonCodes.has('REPLY_TO_DOMAIN_DIFFERS') || reasonCodes.has('RETURN_PATH_DOMAIN_DIFFERS') || reasonCodes.has('LINK_DOMAIN_UNRELATED_TO_AUTHOR');
  const authFailure = [...reasonCodes].some((code) => /^(?:SPF|DKIM|DMARC|ARC)_(?:FAIL|TEMPERROR|PERMERROR)$/u.test(code));

  let failModeApplied = null;
  if (!scored.length && deterministicRisk === 0 && requiredFailures.length) {
    risk = Math.max(risk, SEVERITY_SCORE.unknown);
    reasonCodes.add('RISK_UNKNOWN_REQUIRED_EVIDENCE_UNAVAILABLE');
  }

  if (risk >= 0.9) verdict = 'critical';
  else if (risk >= 0.75) verdict = 'high';
  else if (risk >= 0.45) verdict = 'medium';
  else if (completed.length) verdict = 'low';

  let recommendation = recommendationForScore(risk, policy);
  if ((identityMismatch || authFailure) && (phishing >= 0.45 || deterministicRisk >= 0.45)) {
    recommendation = maxAction(recommendation, 'manual_review');
    reasonCodes.add('INDEPENDENT_EVIDENCE_REQUIRES_REVIEW');
  }
  if (requiredFailures.length) {
    failModeApplied = policy.failure_modes.interactive_text_url;
    recommendation = maxAction(recommendation, failModeApplied);
    reasonCodes.add('REQUIRED_MODEL_UNAVAILABLE');
  }

  const guarded = applyEnforcementGuard(recommendation, policy, [...reasonCodes]);
  recommendation = guarded.recommendation;
  const finalReasons = [...new Set(guarded.reasonCodes)].sort();
  const degraded = requiredFailures.length > 0 || evidence.some((item) => item.degraded);
  const decisionState = unresolved.length ? 'preliminary' : 'final';
  const manualReviewRequired = ['manual_review', 'quarantine', 'block', 'hold'].includes(recommendation)
    || finalReasons.includes('INDEPENDENT_EVIDENCE_REQUIRES_REVIEW');

  return {
    risk: Number(clamp01(risk).toFixed(6)),
    severity: scoreSeverity(risk),
    verdict,
    recommendation,
    decision_state: decisionState,
    reason_codes: finalReasons,
    evidence_ids: evidence.map((item) => item.id).filter(Boolean).sort(),
    correlation_version: CORRELATION_VERSION,
    fail_mode_applied: failModeApplied,
    manual_review_required: manualReviewRequired,
    degraded,
  };
}

module.exports = {
  correlate,
  deterministicEmailRisk,
  scoreSeverity,
};
