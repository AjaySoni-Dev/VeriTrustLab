const net = require('node:net');
const { HttpError } = require('../veritrust-api');

const EMAIL_EVIDENCE_SCHEMA = 'phishing-evidence-7';
const EMAIL_PIPELINE_VERSION = 'mailgraph-pipeline-6';
const EMAIL_PARSER_VERSION = 'mailparser-3.9.15+veritrust-1';
const EMAIL_AUTH_VERSION = 'mailauth-5.0.2+veritrust-1';
const EMAIL_IDENTITY_VERSION = 'mailgraph-identity-1';
const EMAIL_INFRASTRUCTURE_VERSION = 'mailgraph-infrastructure-2';
const EMAIL_THREAT_INTEL_VERSION = 'mailgraph-threat-intel-1';
const EMAIL_CAMPAIGN_VERSION = 'mailgraph-campaign-memory-1';
const EMAIL_PASSPORT_VERSION = 'veritrust-evidence-passport-1';

const INPUT_MODES = Object.freeze(['plain_text', 'raw_eml', 'trusted_receiver_event']);
const SPECIALIST_STATES = Object.freeze(['LIKELY_BENIGN', 'LIKELY_PHISHING', 'UNCERTAIN', 'UNSUPPORTED', 'FAILED']);
const MAX_RAW_EML_BYTES = 10 * 1024 * 1024;
const MAX_HEADER_BYTES = 256 * 1024;
const MAX_MIME_DEPTH = 10;
const MAX_MIME_PARTS = 100;
const MAX_DECODED_BYTES = 25 * 1024 * 1024;
const MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024;
const MAX_NORMALIZED_HTML_BYTES = 1024 * 1024;
const PARSER_TIMEOUT_MS = 5000;

const CAPABILITIES = Object.freeze({
  plain_text: Object.freeze({
    mime: false,
    headers: false,
    spf: false,
    dkim: false,
    dmarc: false,
    arc: false,
    links: true,
    attachments: false,
    infrastructure_geo: false,
    media_authenticity: false,
    threat_intelligence: false,
    campaign_memory: true,
    evidence_passport: true,
  }),
  raw_eml: Object.freeze({
    mime: true,
    headers: true,
    spf: false,
    dkim: true,
    dmarc: true,
    arc: true,
    links: true,
    attachments: true,
    infrastructure_geo: true,
    media_authenticity: false,
    threat_intelligence: true,
    campaign_memory: true,
    evidence_passport: true,
  }),
  trusted_receiver_event: Object.freeze({
    mime: true,
    headers: true,
    spf: true,
    dkim: true,
    dmarc: true,
    arc: true,
    links: true,
    attachments: true,
    infrastructure_geo: true,
    media_authenticity: false,
    threat_intelligence: true,
    campaign_memory: true,
    evidence_passport: true,
  }),
});

function contractError(status, code, message) {
  throw new HttpError(status, message, { code });
}

function validatePlainTextInput(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) contractError(400, 'EMAIL_TEXT_SCHEMA_INVALID', 'The request body must be a JSON object.');
  const unknown = Object.keys(value).filter((key) => !['subject', 'body', 'channel', 'locale_hint', 'retention_policy', 'org_id', 'integration_id', 'parent_scan_id'].includes(key));
  if (unknown.length) contractError(400, 'EMAIL_TEXT_SCHEMA_UNKNOWN_FIELD', `Unsupported fields: ${unknown.sort().join(', ')}.`);
  const subject = typeof value.subject === 'string' ? value.subject.trim() : '';
  const body = typeof value.body === 'string' ? value.body.trim() : '';
  if (!subject && !body) contractError(400, 'EMAIL_TEXT_REQUIRED', 'Provide a subject or message body.');
  if (subject.length > 998) contractError(413, 'EMAIL_SUBJECT_TOO_LARGE', 'subject must be 998 characters or shorter.');
  if (body.length > 12000) contractError(413, 'EMAIL_TEXT_TOO_LARGE', 'body must be 12,000 characters or shorter.');
  const channel = String(value.channel || 'email').toLowerCase();
  if (!['email', 'sms'].includes(channel)) contractError(400, 'EMAIL_CHANNEL_INVALID', 'channel must be email or sms.');
  return {
    subject,
    body,
    channel,
    locale_hint: typeof value.locale_hint === 'string' ? value.locale_hint.trim().slice(0, 32) : null,
    retention_policy: normalizeRetention(value.retention_policy),
    org_id: value.org_id || null,
    integration_id: value.integration_id || null,
    parent_scan_id: validateOptionalUuid(value.parent_scan_id, 'parent_scan_id'),
  };
}


function validateOptionalUuid(value, fieldName = 'id') {
  if (value === undefined || value === null || value === '') return null;
  const text = String(value).trim();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(text)) {
    contractError(400, 'EMAIL_LINEAGE_ID_INVALID', `${fieldName} must be a UUID when provided.`);
  }
  return text;
}

function normalizeRetention(value) {
  const retention = String(value || 'temporary_file').toLowerCase();
  if (!['none', 'metadata_only', 'temporary_file', 'retained_file'].includes(retention)) {
    contractError(400, 'EMAIL_RETENTION_INVALID', 'retention_policy is not supported.');
  }
  return retention;
}


function validateTrustedReceiverMetadata(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) contractError(400, 'RECEIVER_METADATA_INVALID', 'Trusted receiver metadata must be an object.');
  const required = ['client_ip', 'mail_from', 'helo', 'receiver_id', 'authserv_id', 'received_at', 'event_id'];
  const optional = ['integration_id'];
  const allowed = [...required, ...optional];
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
  if (unknown.length) contractError(400, 'RECEIVER_METADATA_UNKNOWN_FIELD', `Unsupported fields: ${unknown.sort().join(', ')}.`);
  for (const field of required) {
    if (typeof value[field] !== 'string' || !String(value[field]).trim()) contractError(400, 'RECEIVER_METADATA_FIELD_REQUIRED', `${field} is required.`);
  }
  const clientIp = String(value.client_ip).trim().replace(/^::ffff:/u, '');
  if (!net.isIP(clientIp)) contractError(400, 'RECEIVER_CLIENT_IP_INVALID', 'client_ip must be an IPv4 or IPv6 address.');
  const mailFromRaw = String(value.mail_from).trim();
  const mailFrom = mailFromRaw === '<>' ? '' : mailFromRaw;
  if (mailFrom.length > 320 || /[\r\n\u0000-\u001f\u007f]/u.test(mailFrom)) contractError(400, 'RECEIVER_MAIL_FROM_INVALID', 'mail_from is invalid.');
  const helo = String(value.helo).trim();
  const receiverId = String(value.receiver_id).trim();
  const authservId = String(value.authserv_id).trim();
  const eventId = String(value.event_id).trim();
  for (const [field, text, maximum] of [['helo', helo, 255], ['receiver_id', receiverId, 255], ['authserv_id', authservId, 255], ['event_id', eventId, 200]]) {
    if (!text || text.length > maximum || /[\r\n\u0000-\u001f\u007f]/u.test(text)) contractError(400, 'RECEIVER_METADATA_FIELD_INVALID', `${field} is invalid.`);
  }
  const receivedAt = new Date(value.received_at);
  if (Number.isNaN(receivedAt.getTime())) contractError(400, 'RECEIVER_EVENT_TIME_INVALID', 'received_at must be an ISO-8601 timestamp.');
  const integrationId = value.integration_id ? String(value.integration_id).trim() : null;
  if (integrationId && !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu.test(integrationId)) {
    contractError(400, 'RECEIVER_INTEGRATION_ID_INVALID', 'integration_id must be a UUID when provided.');
  }
  return {
    client_ip: clientIp,
    mail_from: mailFrom,
    helo,
    receiver_id: receiverId,
    authserv_id: authservId,
    received_at: receivedAt.toISOString(),
    event_id: eventId,
    integration_id: integrationId,
  };
}

function validateReceiverEvent(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) contractError(400, 'RECEIVER_EVENT_SCHEMA_INVALID', 'The receiver event must be a JSON object.');
  const allowed = ['org_id', 'integration_id', 'raw_eml_ref', 'client_ip', 'mail_from', 'helo', 'receiver_id', 'authserv_id', 'received_at'];
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
  if (unknown.length) contractError(400, 'RECEIVER_EVENT_SCHEMA_UNKNOWN_FIELD', `Unsupported fields: ${unknown.sort().join(', ')}.`);
  for (const field of allowed) {
    if (!value[field] || typeof value[field] !== 'string') contractError(400, 'RECEIVER_EVENT_FIELD_REQUIRED', `${field} is required.`);
  }
  const receivedAt = new Date(value.received_at);
  if (Number.isNaN(receivedAt.getTime())) contractError(400, 'RECEIVER_EVENT_TIME_INVALID', 'received_at must be an ISO-8601 timestamp.');
  return {
    ...Object.fromEntries(allowed.map((field) => [field, String(value[field]).trim()])),
    received_at: receivedAt.toISOString(),
  };
}

module.exports = {
  CAPABILITIES,
  EMAIL_AUTH_VERSION,
  EMAIL_EVIDENCE_SCHEMA,
  EMAIL_IDENTITY_VERSION,
  EMAIL_INFRASTRUCTURE_VERSION,
  EMAIL_THREAT_INTEL_VERSION,
  EMAIL_CAMPAIGN_VERSION,
  EMAIL_PASSPORT_VERSION,
  EMAIL_PARSER_VERSION,
  EMAIL_PIPELINE_VERSION,
  INPUT_MODES,
  MAX_ATTACHMENT_BYTES,
  MAX_DECODED_BYTES,
  MAX_HEADER_BYTES,
  MAX_MIME_DEPTH,
  MAX_MIME_PARTS,
  MAX_NORMALIZED_HTML_BYTES,
  MAX_RAW_EML_BYTES,
  PARSER_TIMEOUT_MS,
  SPECIALIST_STATES,
  normalizeRetention,
  validateOptionalUuid,
  validatePlainTextInput,
  validateReceiverEvent,
  validateTrustedReceiverMetadata,
};
