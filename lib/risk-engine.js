const RISK_LEVELS = new Set(['Low', 'Medium', 'High', 'Critical']);

function clamp01(value) {
  return Math.max(0, Math.min(1, Number(value) || 0));
}

function roundScore(value) {
  return Number(clamp01(value).toFixed(5));
}

function riskFromScore(score) {
  const normalized = clamp01(score);
  if (normalized >= 0.9) return 'Critical';
  if (normalized >= 0.75) return 'High';
  if (normalized >= 0.45) return 'Medium';
  return 'Low';
}

function confidenceBand(confidence) {
  const normalized = clamp01(confidence);
  if (normalized >= 0.85) return 'Strong';
  if (normalized >= 0.65) return 'Moderate';
  return 'Weak';
}

function normalizeRiskLevel(value) {
  const normalized = String(value || '').trim().toLowerCase();
  const mapped = normalized.charAt(0).toUpperCase() + normalized.slice(1);
  return RISK_LEVELS.has(mapped) ? mapped : 'Low';
}

function severityScore(severity) {
  const normalized = normalizeRiskLevel(severity);
  if (normalized === 'Critical') return 0.95;
  if (normalized === 'High') return 0.78;
  if (normalized === 'Medium') return 0.52;
  return 0.25;
}

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function indicator(type, title, description, severity = 'Medium') {
  return {
    type,
    title,
    description,
    severity: normalizeRiskLevel(severity),
  };
}

function buildDeepfakeEvidence(payload = {}) {
  const result = payload.result || payload;
  const model = payload.model || {};
  const metadata = payload.metadata || {};
  const evidence = [];
  const fakeScore = clamp01(result.fake_score);
  const realScore = clamp01(result.real_score);
  const riskLevel = normalizeRiskLevel(result.risk_level || riskFromScore(fakeScore));
  const confidence = clamp01(result.confidence);
  const band = confidenceBand(confidence);

  evidence.push(indicator(
    'model_score',
    'Synthetic-media probability',
    fakeScore >= 0.45
      ? 'The selected model assigned an elevated fake probability.'
      : 'The selected model assigned a lower fake probability.',
    riskLevel
  ));

  if (fakeScore > realScore) {
    evidence.push(indicator(
      'score_comparison',
      'Fake score exceeded real score',
      'The model fake score was higher than the model real score.',
      fakeScore >= 0.75 ? 'High' : 'Medium'
    ));
  } else {
    evidence.push(indicator(
      'score_comparison',
      'Real score exceeded fake score',
      'The model real score was higher than the model fake score.',
      'Low'
    ));
  }

  evidence.push(indicator(
    'confidence_band',
    `${band} model confidence`,
    `The model confidence band is ${band.toLowerCase()} based on the reported score.`,
    band === 'Strong' ? riskLevel : 'Medium'
  ));

  if (metadata.mime_type) {
    evidence.push(indicator(
      'validated_input',
      'Validated image type',
      `The uploaded image type was accepted for analysis: ${metadata.mime_type}.`,
      'Low'
    ));
  }

  if (model.fallback_used || model.fallback_from) {
    evidence.push(indicator(
      'model_fallback',
      'Backup model used',
      'The selected model was unavailable, so VeriTrust used a configured backup model.',
      'Medium'
    ));
  }

  evidence.push(indicator(
    'manual_review',
    'Manual review recommended',
    'AI-assisted image results should be reviewed with source context before high-impact decisions.',
    fakeScore >= 0.75 ? 'High' : 'Medium'
  ));

  return evidence;
}

function extractPhishingEntities(text) {
  const source = String(text || '');
  const urls = unique((source.match(/\bhttps?:\/\/[^\s<>"')]+/gi) || [])
    .map((url) => url.replace(/[.,;:!?]+$/, '')));
  const emails = unique(source.match(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi) || []);
  const phones = unique(source.match(/(?:\+?\d[\s().-]?){8,}\d/g) || [])
    .map((phone) => phone.trim());

  const urlDomains = urls.map((url) => {
    try {
      return new URL(url).hostname.toLowerCase().replace(/^www\./, '');
    } catch {
      return '';
    }
  });
  const bareDomains = source.match(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|in|co|io|ai|app|dev|info|biz|online|site|xyz|top|shop|link|click|zip)\b/gi) || [];
  const emailDomains = emails.map((email) => email.split('@')[1].toLowerCase());
  const domains = unique([...urlDomains, ...bareDomains.map((domain) => domain.toLowerCase().replace(/^www\./, '')), ...emailDomains]);

  return {
    urls,
    domains,
    emails,
    phones,
  };
}

function hasAny(text, patterns) {
  return patterns.some((pattern) => pattern.test(text));
}

function suspiciousDomains(entities) {
  const shorteners = new Set([
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'cutt.ly', 'rebrand.ly', 'shorturl.at', 'rb.gy', 's.id', 'lnkd.in',
  ]);

  return entities.domains.filter((domain) => {
    const labels = domain.split('.');
    const joined = domain.replace(/\./g, '');
    return shorteners.has(domain)
      || labels.length >= 4
      || /(?:login|verify|secure|account|update|support|wallet|bank|kyc)/i.test(domain)
      || /xn--/i.test(domain)
      || /[0-9]{3,}/.test(joined)
      || /[a-z]+-[a-z]+-[a-z]+/i.test(domain);
  });
}

function buildPhishingIndicators(text, modelPayload = {}) {
  const source = String(text || '');
  const lower = source.toLowerCase();
  const entities = extractPhishingEntities(source);
  const indicators = [];

  if (hasAny(lower, [/\burgent\b/, /\bimmediately\b/, /\bact now\b/, /\bwithin\s+\d+\s+(hours?|days?)\b/, /\bfinal notice\b/, /\blast chance\b/])) {
    indicators.push(indicator('urgency', 'Urgent action pressure', 'The message asks the user to act quickly or under time pressure.', 'Medium'));
  }

  if (hasAny(lower, [/\bverify\b/, /\bconfirm\b/, /\bupdate\b/, /\bvalidate\b/, /\bre-?activate\b/, /\brestore\b/, /\blogin\b/, /\bsign in\b/])) {
    indicators.push(indicator('credential_request', 'Credential or account action request', 'The message asks for login or account verification activity.', 'High'));
  }

  if (hasAny(lower, [/\botp\b/, /\bone[-\s]?time\b/, /\bpassword\b/, /\bpasscode\b/, /\b2fa\b/, /\bsecurity code\b/, /\bauthentication code\b/])) {
    indicators.push(indicator('otp_or_password', 'OTP or password language', 'The message references passwords, codes, or authentication details.', 'High'));
  }

  if (hasAny(lower, [/\bpayment\b/, /\brefund\b/, /\binvoice\b/, /\bbank\b/, /\bwallet\b/, /\bmoney\b/, /\bprize\b/, /\bcrypto\b/, /\bgift card\b/, /\btransaction\b/])) {
    indicators.push(indicator('payment_or_refund', 'Payment or money lure', 'The message uses financial, refund, prize, or payment-related wording.', 'Medium'));
  }

  if (hasAny(lower, [/\bkyc\b/, /\bblocked\b/, /\bsuspended\b/, /\blocked\b/, /\brestricted\b/, /\blimited\b/, /\bdeactivated\b/, /\baccount hold\b/])) {
    indicators.push(indicator('account_blocking', 'Account blocking pressure', 'The message suggests account blocking, suspension, or KYC pressure.', 'High'));
  }

  if (hasAny(lower, [/\battachment\b/, /\battached\b/, /\bdownload\b/, /\bopen file\b/, /\bview document\b/, /\bscan qr\b/, /\bqr code\b/])) {
    indicators.push(indicator('attachment_risk', 'Attachment or download request', 'The message asks the user to open, download, or scan external content.', 'Medium'));
  }

  if (entities.urls.length || entities.domains.length) {
    indicators.push(indicator('suspicious_url', 'External link present', 'The message contains one or more URLs or domains that should be verified before opening.', entities.urls.length > 1 ? 'High' : 'Medium'));
  }

  const flaggedDomains = suspiciousDomains(entities);
  if (flaggedDomains.length) {
    const usesShortener = flaggedDomains.some((domain) => ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'cutt.ly', 'rebrand.ly', 'shorturl.at', 'rb.gy', 's.id', 'lnkd.in'].includes(domain));
    indicators.push(indicator(
      usesShortener ? 'url_shortener' : 'suspicious_url',
      usesShortener ? 'URL shortener detected' : 'Suspicious domain pattern',
      usesShortener
        ? 'The message uses a shortened link, which can hide the final destination.'
        : 'One or more domains use patterns that are common in suspicious messages.',
      'High'
    ));
  }

  if (hasAny(lower, [/\bdear customer\b/, /\bdear user\b/, /\bsecurity team\b/, /\bsupport team\b/, /\badmin\b/, /\bofficial\b/])) {
    indicators.push(indicator('sender_identity', 'Generic sender identity', 'The message uses generic sender or support-team language that should be verified.', 'Low'));
  }

  if (entities.emails.length || entities.phones.length || hasAny(lower, [/\bwhatsapp\b/, /\btelegram\b/, /\bcall now\b/, /\breply yes\b/])) {
    indicators.push(indicator('contact_method', 'External contact method', 'The message includes contact details or asks the user to move to another channel.', 'Medium'));
  }

  const modelIndicators = Array.isArray(modelPayload.indicators) ? modelPayload.indicators : [];
  for (const item of modelIndicators) {
    if (item && typeof item === 'object' && item.title) {
      indicators.push(indicator(
        item.type || 'model_indicator',
        item.title,
        item.description || 'The selected model returned this risk indicator.',
        item.severity || 'Medium'
      ));
    } else if (typeof item === 'string' && item.trim()) {
      indicators.push(indicator('model_indicator', 'Model-reported indicator', item.trim(), 'Medium'));
    }
  }

  const seen = new Set();
  return indicators.filter((item) => {
    const key = `${item.type}:${item.title}:${item.description}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function scorePhishingIndicators(indicators) {
  const list = Array.isArray(indicators) ? indicators : [];
  if (!list.length) return 0;
  const scores = list.map((item) => severityScore(item.severity));
  const total = scores.reduce((sum, score) => sum + score, 0);
  const maxSeverity = Math.max(...scores);
  const densityBonus = Math.min(0.18, Math.max(0, list.length - 2) * 0.03);
  const cumulative = Math.min(0.4, total * 0.12);
  return roundScore(Math.min(0.98, (maxSeverity * 0.55) + cumulative + densityBonus));
}

function combinePhishingScores(modelScore, ruleScore) {
  const model = clamp01(modelScore);
  const rules = clamp01(ruleScore);
  let combined = model * 0.7 + rules * 0.3;

  if (model >= 0.65 && rules >= 0.6) combined = Math.max(combined, 0.75);
  if (model < 0.45 && rules >= 0.72) combined = Math.max(combined, 0.45);
  if (model < 0.3 && rules < 0.2) combined = Math.min(combined, 0.32);

  return roundScore(combined);
}

function phishingDecisionState(modelState, modelScore, ruleScore, decisionScore) {
  const normalizedState = ['LIKELY_BENIGN', 'LIKELY_PHISHING', 'UNCERTAIN', 'UNSUPPORTED', 'FAILED'].includes(modelState)
    ? modelState
    : 'FAILED';
  if (['UNSUPPORTED', 'FAILED'].includes(normalizedState)) return normalizedState;
  if (modelScore === null || modelScore === undefined || !Number.isFinite(Number(modelScore))) return 'UNCERTAIN';

  const model = clamp01(modelScore);
  const rules = clamp01(ruleScore);
  const decision = clamp01(decisionScore);

  if (normalizedState === 'LIKELY_PHISHING' && model >= 0.55) return 'LIKELY_PHISHING';
  if (decision >= 0.75 && rules >= 0.6) return 'LIKELY_PHISHING';

  // A benign verdict requires agreement from the deterministic evidence layer.
  if (normalizedState === 'LIKELY_BENIGN' && model <= 0.35 && rules < 0.45 && decision < 0.45) return 'LIKELY_BENIGN';
  if (model <= 0.3 && rules < 0.3 && decision < 0.4) return 'LIKELY_BENIGN';

  return 'UNCERTAIN';
}

function buildSafeSummary(resultType, data = {}) {
  const result = data.result || data;
  const riskLevel = normalizeRiskLevel(result.risk_level || riskFromScore(result.fake_score || result.phishing_score));
  const band = result.confidence_band || confidenceBand(result.confidence);

  if (resultType === 'deepfake') {
    if (String(result.label).toLowerCase() === 'fake') {
      return `The image is likely synthetic based on the selected model score. Confidence is ${band.toLowerCase()}, and manual review is recommended.`;
    }
    return `The image is lower-risk based on the selected model score. This does not prove the image is authentic.`;
  }

  if (resultType === 'phishing') {
    const indicators = Array.isArray(result.indicators) ? result.indicators : [];
    if (String(result.label).toLowerCase() === 'phishing') {
      const categories = unique(indicators.map((item) => String(item.type || '').replace(/_/g, ' '))).slice(0, 2);
      const reason = categories.length ? ` because it contains ${categories.join(' and ')} risk indicators` : ' based on the combined model and rule score';
      return `The message is likely phishing${reason}. Verify through official channels before taking action.`;
    }
    if (riskLevel === 'Medium') {
      return 'The message has some suspicious signals. Manual verification is recommended before engaging with links, payments, or account requests.';
    }
    return 'No strong phishing indicators were found from the available signals. This does not prove that the message is safe.';
  }

  return 'AI-assisted assessment completed. Review the evidence and verify important decisions manually.';
}

module.exports = {
  buildDeepfakeEvidence,
  buildPhishingIndicators,
  buildSafeSummary,
  combinePhishingScores,
  confidenceBand,
  phishingDecisionState,
  extractPhishingEntities,
  normalizeRiskLevel,
  riskFromScore,
  scorePhishingIndicators,
};
