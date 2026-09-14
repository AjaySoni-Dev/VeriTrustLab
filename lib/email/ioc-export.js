const crypto = require('node:crypto');
const net = require('node:net');
const { domainToASCII } = require('node:url');

const STIX_SPEC_VERSION = '2.1';
const STIX_NAMESPACE = '2c4d8e6a-1f73-5c24-9e49-d0f85b5d23bc';

function uuidBytes(uuid) {
  return Buffer.from(String(uuid).replace(/-/g, ''), 'hex');
}

function uuidV5(namespace, name) {
  const digest = crypto.createHash('sha1').update(Buffer.concat([uuidBytes(namespace), Buffer.from(String(name), 'utf8')])).digest().subarray(0, 16);
  digest[6] = (digest[6] & 0x0f) | 0x50;
  digest[8] = (digest[8] & 0x3f) | 0x80;
  const hex = digest.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function normalizeDomain(value) {
  const ascii = domainToASCII(String(value || '').trim().replace(/^\.+|\.+$/g, '').toLowerCase());
  if (!ascii || ascii.length > 253 || net.isIP(ascii) || !ascii.includes('.')) return null;
  if (!/^[a-z0-9.-]+$/u.test(ascii) || ascii.split('.').some((label) => !label || label.length > 63 || label.startsWith('-') || label.endsWith('-'))) return null;
  return ascii;
}

function collectIocs(evidence) {
  const iocs = new Map();
  const add = (type, value, source, confidence = 'observed') => {
    const normalized = type === 'domain' ? normalizeDomain(value) : String(value || '').trim();
    if (!normalized) return;
    const key = `${type}:${normalized.toLowerCase()}`;
    if (!iocs.has(key)) iocs.set(key, { type, value: normalized, sources: [], confidence });
    const row = iocs.get(key);
    if (source && !row.sources.includes(source)) row.sources.push(source);
  };

  for (const relation of evidence?.relationships || []) {
    const type = String(relation.target_type || '').toLowerCase();
    if (type.includes('domain')) add('domain', relation.target_value, `relationship:${relation.type || relation.edge_type || 'observed'}`);
  }
  for (const hop of evidence?.infrastructure || []) {
    if (net.isIP(String(hop.ip_address || ''))) add(net.isIP(hop.ip_address) === 6 ? 'ipv6' : 'ipv4', hop.ip_address, `smtp-hop:${hop.hop_index}`, hop.trust_level || 'observed');
    if (hop.host) add('domain', hop.host, `smtp-host:${hop.hop_index}`, hop.trust_level || 'observed');
  }
  for (const child of evidence?.children || []) {
    if (child.type === 'url') {
      const raw = child.metadata?.normalized_url || child.metadata?.url || null;
      if (raw) add('url', raw, 'email-url');
      if (child.metadata?.hostname) add('domain', child.metadata.hostname, 'email-url-host');
    }
    if (child.type === 'attachment' && /^[a-f0-9]{64}$/iu.test(String(child.metadata?.sha256 || ''))) {
      add('sha256', String(child.metadata.sha256).toLowerCase(), 'attachment');
    }
  }
  for (const item of evidence?.threat_intelligence?.domain_intelligence || []) add('domain', item.domain, 'rdap');
  for (const item of evidence?.threat_intelligence?.ip_reputation || []) {
    if (net.isIP(String(item.ip_address || ''))) add(net.isIP(item.ip_address) === 6 ? 'ipv6' : 'ipv4', item.ip_address, 'ip-reputation');
  }
  return [...iocs.values()].sort((a, b) => `${a.type}:${a.value}`.localeCompare(`${b.type}:${b.value}`));
}

function stixPattern(ioc) {
  const escaped = String(ioc.value).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
  if (ioc.type === 'domain') return `[domain-name:value = '${escaped}']`;
  if (ioc.type === 'url') return `[url:value = '${escaped}']`;
  if (ioc.type === 'ipv4') return `[ipv4-addr:value = '${escaped}']`;
  if (ioc.type === 'ipv6') return `[ipv6-addr:value = '${escaped}']`;
  if (ioc.type === 'sha256') return `[file:hashes.'SHA-256' = '${escaped}']`;
  return null;
}

function toStixBundle(scanId, evidence) {
  const generated = evidence?.completed_at || evidence?.evidence_manifest?.completed_at || new Date(0).toISOString();
  const iocs = collectIocs(evidence);
  const objects = iocs.map((ioc) => ({
    type: 'indicator',
    spec_version: STIX_SPEC_VERSION,
    id: `indicator--${uuidV5(STIX_NAMESPACE, `${scanId}:${ioc.type}:${ioc.value}`)}`,
    created: generated,
    modified: generated,
    name: `VeriTrust email IOC: ${ioc.type}`,
    description: `Observed during VeriTrust email investigation ${scanId}. Sources: ${ioc.sources.join(', ') || 'email evidence'}.`,
    indicator_types: ['malicious-activity'],
    pattern: stixPattern(ioc),
    pattern_type: 'stix',
    pattern_version: '2.1',
    valid_from: generated,
    labels: ['veritrust', 'email-forensics', ioc.confidence || 'observed'],
  })).filter((item) => item.pattern);
  return {
    type: 'bundle',
    id: `bundle--${uuidV5(STIX_NAMESPACE, `bundle:${scanId}:${objects.map((item) => item.id).join(':')}`)}`,
    objects,
  };
}

function csvCell(value) {
  const text = String(value ?? '');
  return /[",\r\n]/u.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function toCsv(evidence) {
  const rows = [['type', 'value', 'confidence', 'sources']];
  for (const ioc of collectIocs(evidence)) rows.push([ioc.type, ioc.value, ioc.confidence, ioc.sources.join('|')]);
  return `${rows.map((row) => row.map(csvCell).join(',')).join('\r\n')}\r\n`;
}

module.exports = { collectIocs, normalizeDomain, toCsv, toStixBundle, uuidV5 };
