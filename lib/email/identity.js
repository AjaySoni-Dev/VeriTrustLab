const { domainToASCII, domainToUnicode } = require('url');
const { parse: parseDomain } = require('tldts');
const { EMAIL_IDENTITY_VERSION } = require('./contracts');

const PSL_VERSION = 'tldts-7.4.10';

function normalizeDomain(value) {
  const original = String(value || '').normalize('NFC').trim().replace(/^\[|\]$/gu, '').replace(/\.+$/u, '').toLowerCase();
  if (!original) return null;
  const ascii = domainToASCII(original);
  if (!ascii) return { original, ascii: null, unicode: original, registrable: null, public_suffix: null, valid: false };
  const parsed = parseDomain(ascii, { allowPrivateDomains: true, validateHostname: true });
  return {
    original,
    ascii,
    unicode: domainToUnicode(ascii),
    registrable: parsed.domain || null,
    public_suffix: parsed.publicSuffix || null,
    is_private_suffix: Boolean(parsed.isPrivate),
    valid: Boolean(parsed.isIcann || parsed.isPrivate || parsed.domain),
    psl_version: PSL_VERSION,
  };
}

function mailboxIdentity(item) {
  const address = String(item?.address || '').trim();
  const at = address.lastIndexOf('@');
  const domain = at > 0 ? normalizeDomain(address.slice(at + 1)) : null;
  return {
    name: String(item?.name || '').trim() || null,
    address: address || null,
    domain,
  };
}

function sameOrganizationalDomain(left, right) {
  const a = typeof left === 'string' ? normalizeDomain(left) : left;
  const b = typeof right === 'string' ? normalizeDomain(right) : right;
  return Boolean(a?.registrable && b?.registrable && a.registrable === b.registrable);
}

function mixedScript(value) {
  const text = String(value || '');
  const scripts = [
    /\p{Script=Latin}/u.test(text) ? 'latin' : null,
    /\p{Script=Cyrillic}/u.test(text) ? 'cyrillic' : null,
    /\p{Script=Greek}/u.test(text) ? 'greek' : null,
    /\p{Script=Devanagari}/u.test(text) ? 'devanagari' : null,
  ].filter(Boolean);
  return scripts.length > 1 ? scripts : [];
}

function createEdge(edge) {
  return {
    ...edge,
    confidence: edge.confidence ?? null,
    reason_code: edge.reason_code || null,
    provenance: { psl_version: PSL_VERSION, ...(edge.provenance || {}) },
    producer_version: EMAIL_IDENTITY_VERSION,
  };
}

function buildIdentityGraph(parsed, authObservations, urlRecords) {
  const limitations = [];
  const observations = [];
  const edges = [];
  const fromValues = (parsed.addresses?.from || []).map(mailboxIdentity);
  const replyValues = (parsed.addresses?.replyTo || []).map(mailboxIdentity);
  const returnValues = (parsed.addresses?.returnPath || []).map(mailboxIdentity);
  const senderValues = (parsed.addresses?.sender || []).map(mailboxIdentity);
  const author = fromValues.length === 1 ? fromValues[0] : null;
  if (!author) limitations.push(fromValues.length ? 'AMBIGUOUS_MULTIPLE_FROM' : 'AUTHOR_IDENTITY_UNAVAILABLE');
  if (author && !author.domain?.valid) limitations.push('AUTHOR_DOMAIN_MALFORMED_OR_UNAVAILABLE');
  if (replyValues.length > 1) limitations.push('AMBIGUOUS_MULTIPLE_REPLY_TO');
  if (returnValues.length > 1) limitations.push('AMBIGUOUS_MULTIPLE_RETURN_PATH');
  if (senderValues.length > 1) limitations.push('AMBIGUOUS_MULTIPLE_SENDER');

  const compare = (target, targetType, reasonCode) => {
    if (!author?.domain?.ascii || !target?.domain?.ascii) return;
    const aligned = sameOrganizationalDomain(author.domain, target.domain);
    edges.push(createEdge({
      edge_type: aligned ? 'aligned_with' : 'differs_from',
      source_type: 'author_domain',
      source_value: author.domain.ascii,
      target_type: targetType,
      target_value: target.domain.ascii,
      evidence_source: 'parsed_headers',
      confidence: 1,
      reason_code: aligned ? 'ORGANIZATIONAL_DOMAIN_ALIGNED' : reasonCode,
    }));
  };
  replyValues.forEach((value) => compare(value, 'reply_to_domain', 'REPLY_TO_DOMAIN_DIFFERS'));
  returnValues.forEach((value) => compare(value, 'return_path_domain', 'RETURN_PATH_DOMAIN_DIFFERS'));
  senderValues.forEach((value) => compare(value, 'sender_domain', 'SENDER_DOMAIN_DIFFERS'));
  const messageIdDomainValue = String(parsed.messageId || '').match(/@([^>\s]+)>?$/u)?.[1] || null;
  if (author?.domain?.ascii && messageIdDomainValue) {
    const messageIdDomain = normalizeDomain(messageIdDomainValue);
    if (messageIdDomain?.ascii) {
      const aligned = sameOrganizationalDomain(author.domain, messageIdDomain);
      edges.push(createEdge({
        edge_type: aligned ? 'aligned_with' : 'differs_from',
        source_type: 'author_domain',
        source_value: author.domain.ascii,
        target_type: 'message_id_domain',
        target_value: messageIdDomain.ascii,
        evidence_source: 'parsed_headers',
        confidence: 1,
        reason_code: aligned ? 'MESSAGE_ID_DOMAIN_ALIGNED' : 'MESSAGE_ID_DOMAIN_DIFFERS',
      }));
    }
  }

  for (const auth of authObservations || []) {
    if (!author?.domain?.ascii || !auth.domain || !['DKIM', 'SPF'].includes(auth.protocol)) continue;
    const authDomain = normalizeDomain(auth.domain);
    if (!authDomain?.ascii) continue;
    const aligned = sameOrganizationalDomain(author.domain, authDomain);
    edges.push(createEdge({
      edge_type: aligned ? 'aligned_with' : 'differs_from',
      source_type: 'author_domain',
      source_value: author.domain.ascii,
      target_type: `${auth.protocol.toLowerCase()}_domain`,
      target_value: authDomain.ascii,
      evidence_source: 'authentication_observation',
      confidence: auth.result === 'PASS' ? 1 : null,
      reason_code: aligned ? `${auth.protocol}_DOMAIN_ALIGNED` : `${auth.protocol}_DOMAIN_DIFFERS`,
      provenance: { auth_result: auth.result, auth_quality: auth.quality },
    }));
  }

  for (const record of urlRecords || []) {
    const domain = normalizeDomain(new URL(record.url).hostname);
    if (!domain?.ascii) continue;
    edges.push(createEdge({
      edge_type: 'links_to',
      source_type: 'email_artifact',
      source_value: parsed.rawSha256,
      target_type: 'url_registrable_domain',
      target_value: domain.registrable || domain.ascii,
      evidence_source: record.sources?.includes('html_href') ? 'html_href' : 'message_text',
      confidence: 1,
      reason_code: author?.domain && !sameOrganizationalDomain(author.domain, domain) ? 'LINK_DOMAIN_UNRELATED_TO_AUTHOR' : 'LINK_DOMAIN_OBSERVED',
    }));
  }

  for (const identity of [...fromValues, ...replyValues, ...returnValues, ...senderValues]) {
    if (identity.address && !identity.domain?.valid) observations.push({
      code: 'IDENTITY_ADDRESS_MALFORMED',
      source: 'identity_normalizer',
      producer_version: EMAIL_IDENTITY_VERSION,
      observed_at: new Date().toISOString(),
      quality: 'observed',
      address_hash_available: false,
    });
    const scripts = mixedScript(identity.domain?.unicode);
    if (scripts.length) observations.push({
      code: 'IDENTITY_DOMAIN_MIXED_SCRIPTS',
      source: 'identity_normalizer',
      producer_version: EMAIL_IDENTITY_VERSION,
      observed_at: new Date().toISOString(),
      quality: 'observed',
      domain: identity.domain.ascii,
      scripts,
    });
    if (scripts.length && /[\p{Script=Cyrillic}\p{Script=Greek}]/u.test(identity.domain?.unicode || '')) observations.push({
      code: 'IDENTITY_DOMAIN_CONFUSABLE',
      source: 'identity_normalizer',
      producer_version: EMAIL_IDENTITY_VERSION,
      observed_at: new Date().toISOString(),
      quality: 'observed',
      domain: identity.domain.ascii,
      confusable_skeleton_available: false,
    });
  }

  return { author, fromValues, replyValues, returnValues, senderValues, edges, observations, limitations };
}

module.exports = {
  PSL_VERSION,
  buildIdentityGraph,
  mailboxIdentity,
  normalizeDomain,
  sameOrganizationalDomain,
};
