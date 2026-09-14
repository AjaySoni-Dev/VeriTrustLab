const crypto = require('crypto');
const { canonicalizeUrl } = require('../gateway/contracts');

const URL_PATTERN = /https?:\/\/[^\s<>"'`]+/giu;
const ATTRIBUTE_URL_PATTERN = /\b(?:href|src|action)\s*=\s*(["'])(https?:\/\/.*?)\1/giu;
const MAX_EXTRACTED_URLS = 50;

function sha256(value) {
  if (value === null || value === undefined || value === '') return null;
  return crypto.createHash('sha256').update(value).digest('hex');
}

function decodeBasicEntities(value) {
  return String(value || '')
    .replace(/&nbsp;/giu, ' ')
    .replace(/&amp;/giu, '&')
    .replace(/&lt;/giu, '<')
    .replace(/&gt;/giu, '>')
    .replace(/&quot;/giu, '"')
    .replace(/&#39;/giu, "'")
    .replace(/&#(\d+);/gu, (_, code) => String.fromCodePoint(Math.min(0x10ffff, Number(code) || 32)));
}

function safeTextFromHtml(html) {
  return decodeBasicEntities(String(html || '')
    .replace(/<!--[\s\S]*?-->/gu, ' ')
    .replace(/<(script|style|form|iframe|object|embed|svg|canvas)\b[\s\S]*?<\/\1\s*>/giu, ' ')
    .replace(/<(?:img|link|meta|input)\b[^>]*>/giu, ' ')
    .replace(/<br\s*\/?\s*>/giu, '\n')
    .replace(/<\/p\s*>/giu, '\n')
    .replace(/<[^>]+>/gu, ' '))
    .replace(/[\t\f\v ]+/gu, ' ')
    .replace(/\n{3,}/gu, '\n\n')
    .trim();
}

function canonicalUrl(raw) {
  try {
    return canonicalizeUrl(String(raw || '').replace(/[),.;!?\]}]+$/u, ''));
  } catch {
    return null;
  }
}

function extractUrls(text, html = '', maxUrls = MAX_EXTRACTED_URLS) {
  const observations = [];
  const seen = new Map();
  const add = (raw, source, metadata = {}) => {
    const url = canonicalUrl(raw);
    if (!url) return;
    if (!seen.has(url) && seen.size >= maxUrls) {
      if (!observations.some((item) => item.code === 'URL_EXTRACTION_LIMIT_REACHED')) observations.push({
        code: 'URL_EXTRACTION_LIMIT_REACHED',
        source: 'deterministic_content',
        producer_version: 'email-content-rules-1',
        observed_at: new Date().toISOString(),
        quality: 'partial',
        limit: maxUrls,
      });
      return;
    }
    const current = seen.get(url) || { url, sources: [], metadata: [] };
    if (!current.sources.includes(source)) current.sources.push(source);
    current.metadata.push(metadata);
    seen.set(url, current);
  };
  for (const raw of String(text || '').match(URL_PATTERN) || []) add(raw, 'text');
  for (const match of String(html || '').matchAll(ATTRIBUTE_URL_PATTERN)) add(match[2], 'html_attribute', { attribute_match: match[0].slice(0, 32) });

  const anchorPattern = /<a\b[^>]*href\s*=\s*(["'])(https?:\/\/.*?)\1[^>]*>([\s\S]*?)<\/a\s*>/giu;
  for (const match of String(html || '').matchAll(anchorPattern)) {
    const href = canonicalUrl(match[2]);
    const visible = canonicalUrl(safeTextFromHtml(match[3]).match(URL_PATTERN)?.[0]);
    if (href) add(href, 'html_href');
    if (href && visible && new URL(href).hostname !== new URL(visible).hostname) {
      observations.push({
        code: 'VISIBLE_URL_DIFFERS_FROM_HREF',
        source: 'deterministic_content',
        producer_version: 'email-content-rules-1',
        observed_at: new Date().toISOString(),
        quality: 'observed',
        visible_hostname: new URL(visible).hostname,
        href_hostname: new URL(href).hostname,
      });
    }
  }
  return { urls: [...seen.values()], observations };
}

const RULES = Object.freeze([
  ['CREDENTIAL_REQUEST', /\b(?:password|passcode|otp|2fa|security code|sign[ -]?in|login|verify (?:your )?account)\b/iu, 'credential_request'],
  ['PAYMENT_REQUEST', /\b(?:invoice|payment|bank transfer|wire transfer|gift card|crypto|refund)\b/iu, 'payment_request'],
  ['URGENCY_OR_COERCION', /\b(?:urgent|immediately|act now|final notice|suspend(?:ed|sion)?|within \d+ (?:hours?|days?))\b/iu, 'urgency'],
  ['OUT_OF_BAND_CONTACT', /\b(?:whatsapp|telegram|signal app|call (?:me|us)|text (?:me|us))\b/iu, 'out_of_band_contact'],
  ['ATTACHMENT_LURE', /\b(?:open|download|review|enable macros?).{0,40}\b(?:attachment|document|invoice|archive)\b/iu, 'attachment_lure'],
  ['QR_OR_LINK_LURE', /\b(?:scan (?:the )?qr|click here|follow (?:this|the) link|secure link)\b/iu, 'qr_link_lure'],
  ['IMPERSONATION_CLAIM', /\b(?:i am|this is|on behalf of|from) (?:the )?(?:support|security|billing|finance|ceo|cfo|hr|it|administrator|bank)\b/iu, 'identity_impersonation'],
]);

function integrityText(value) {
  return String(value || '').normalize('NFKC').replace(/[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/gu, '');
}

function deterministicObservations(text, html = '') {
  const value = String(text || '');
  const normalized = integrityText(value);
  const observations = [];
  for (const [code, pattern, category] of RULES) {
    const match = pattern.exec(value);
    if (!match) continue;
    observations.push({
      code,
      category,
      source: 'deterministic_content',
      producer_version: 'email-content-rules-1',
      observed_at: new Date().toISOString(),
      quality: 'observed',
      span: { start: match.index, end: match.index + match[0].length },
    });
  }
  if (/\b(?:ignore|disregard) (?:all|any|the) (?:previous|prior|system) instructions?\b/iu.test(normalized)
    || /\b(?:system|assistant|developer)\s*:/iu.test(normalized)) {
    observations.push({
      code: 'AI_INPUT_INSTRUCTION_OVERRIDE',
      category: 'ai_input_integrity',
      source: 'ai_input_integrity_guard',
      producer_version: 'ai-input-integrity-1',
      observed_at: new Date().toISOString(),
      quality: 'observed',
    });
  }
  if (normalized !== value) observations.push({
    code: 'AI_INPUT_OBFUSCATION',
    category: 'ai_input_integrity',
    source: 'ai_input_integrity_guard',
    producer_version: 'ai-input-integrity-1',
    observed_at: new Date().toISOString(),
    quality: 'observed',
  });
  if (/[\u202a-\u202e\u2066-\u2069]/u.test(value)) observations.push({
    code: 'UNICODE_DIRECTIONAL_CONTROL',
    category: 'encoding_anomaly',
    source: 'ai_input_integrity_guard',
    producer_version: 'ai-input-integrity-1',
    observed_at: new Date().toISOString(),
    quality: 'observed',
  });
  if (/hxxps?:|\[(?:dot|\.)\]/iu.test(normalized)) observations.push({
    code: 'OBFUSCATED_LINK_TEXT',
    category: 'encoding_anomaly',
    source: 'deterministic_content',
    producer_version: 'email-content-rules-1',
    observed_at: new Date().toISOString(),
    quality: 'observed',
  });
  const htmlValue = String(html || '');
  if (/\b(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:[;"']|\s)|font-size\s*:\s*0|hidden(?:\s|=|>))/iu.test(htmlValue)) observations.push({
    code: 'HTML_HIDDEN_CONTENT',
    category: 'html_visual_trick',
    source: 'deterministic_html',
    producer_version: 'email-content-rules-1',
    observed_at: new Date().toISOString(),
    quality: 'observed',
  });
  if (/<meta\b[^>]*http-equiv\s*=\s*["']?refresh/iu.test(htmlValue)) observations.push({
    code: 'HTML_META_REFRESH',
    category: 'html_active_content',
    source: 'deterministic_html',
    producer_version: 'email-content-rules-1',
    observed_at: new Date().toISOString(),
    quality: 'observed',
  });
  return observations;
}

module.exports = {
  deterministicObservations,
  extractUrls,
  integrityText,
  MAX_EXTRACTED_URLS,
  safeTextFromHtml,
  sha256,
};
