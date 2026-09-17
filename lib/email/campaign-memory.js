const crypto = require('node:crypto');
const net = require('node:net');
const { domainToASCII } = require('node:url');

const CAMPAIGN_MEMORY_VERSION = 'mailgraph-campaign-memory-1';
const ENTITY_WEIGHTS = Object.freeze({
  attachment_sha256: 10,
  url_domain: 7,
  reply_to_domain: 6,
  return_path_domain: 5,
  infrastructure_ip_trusted: 6,
  infrastructure_ip_observed: 4,
  dkim_domain: 4,
  from_domain: 3,
  sender_domain: 3,
  message_id_domain: 2,
  infrastructure_host: 2,
  infrastructure_asn: 1,
});

function normalizeDomain(value) {
  const ascii = domainToASCII(String(value || '').trim().replace(/^\.+|\.+$/g, '').toLowerCase());
  return ascii && ascii.includes('.') && !net.isIP(ascii) && /^[a-z0-9.-]+$/u.test(ascii) ? ascii : null;
}

function entityHash(type, value) {
  return crypto.createHash('sha256').update(`${type}\u0000${String(value).toLowerCase()}`).digest('hex');
}

function normalizeEntity(type, value, options = {}) {
  let normalized = String(value || '').trim();
  if (type.includes('domain') || type === 'infrastructure_host') normalized = normalizeDomain(normalized) || '';
  if (type.startsWith('infrastructure_ip')) normalized = net.isIP(normalized) ? normalized : '';
  if (type === 'attachment_sha256') normalized = /^[a-f0-9]{64}$/iu.test(normalized) ? normalized.toLowerCase() : '';
  if (type === 'infrastructure_asn') normalized = String(normalized).replace(/^AS/iu, '');
  if (!normalized) return null;
  const weight = Number(options.weight ?? ENTITY_WEIGHTS[type] ?? 1);
  return {
    entity_type: type,
    entity_value: normalized,
    value_hash: entityHash(type, normalized),
    weight,
    trust_level: options.trustLevel || 'observed',
    provenance: options.provenance || {},
    producer_version: CAMPAIGN_MEMORY_VERSION,
  };
}

function buildThreatEntities({ parsed, identity, authObservations = [], extractedUrls = [], attachments = [], infrastructure = [] }) {
  const rows = [];
  const add = (type, value, options) => { const entity = normalizeEntity(type, value, options); if (entity) rows.push(entity); };
  const author = identity?.author;
  add('from_domain', author?.domain?.ascii, { provenance: { source: 'from' } });
  for (const item of identity?.replyValues || []) add('reply_to_domain', item?.domain?.ascii, { provenance: { source: 'reply-to' } });
  for (const item of identity?.returnValues || []) add('return_path_domain', item?.domain?.ascii, { provenance: { source: 'return-path' } });
  for (const item of identity?.senderValues || []) add('sender_domain', item?.domain?.ascii, { provenance: { source: 'sender' } });
  const messageIdDomain = String(parsed?.messageId || '').match(/@([^>\s]+)>?$/u)?.[1] || null;
  add('message_id_domain', messageIdDomain, { provenance: { source: 'message-id' } });
  for (const item of authObservations) if (String(item.protocol || '').toUpperCase() === 'DKIM') add('dkim_domain', item.domain, { provenance: { source: 'dkim', result: item.result } });
  for (const item of extractedUrls) {
    try { add('url_domain', new URL(item.url || item).hostname, { provenance: { source: 'url' } }); } catch { /* extraction already validates */ }
  }
  for (const attachment of attachments || []) add('attachment_sha256', attachment.sha256, { provenance: { source: 'attachment', filename: attachment.filename || null } });
  for (const hop of infrastructure || []) {
    if (hop.ip_classification === 'public' && hop.ip_address) {
      const trusted = hop.trust_level === 'trusted_receiver';
      add(trusted ? 'infrastructure_ip_trusted' : 'infrastructure_ip_observed', hop.ip_address, { trustLevel: hop.trust_level || 'observed_relay', provenance: { hop_index: hop.hop_index } });
    }
    add('infrastructure_host', hop.host, { trustLevel: hop.trust_level || 'observed_relay', provenance: { hop_index: hop.hop_index } });
    if (hop.asn) add('infrastructure_asn', hop.asn, { weight: ENTITY_WEIGHTS.infrastructure_asn, provenance: { asn_org: hop.asn_org || null } });
  }
  const deduped = new Map();
  for (const row of rows) {
    const current = deduped.get(row.value_hash);
    if (!current || row.weight > current.weight) deduped.set(row.value_hash, row);
  }
  return [...deduped.values()].sort((a, b) => b.weight - a.weight || a.entity_type.localeCompare(b.entity_type) || a.entity_value.localeCompare(b.entity_value));
}

function campaignFromMatches(currentScanId, currentEntities, matches) {
  const currentByHash = new Map(currentEntities.map((item) => [item.value_hash, item]));
  const grouped = new Map();
  for (const match of matches || []) {
    if (!match.scan_id || match.scan_id === currentScanId) continue;
    const current = currentByHash.get(match.value_hash);
    if (!current) continue;
    if (!grouped.has(match.scan_id)) grouped.set(match.scan_id, { scan_id: match.scan_id, score: 0, common_entities: new Map(), first_seen: match.created_at || null, last_seen: match.created_at || null });
    const group = grouped.get(match.scan_id);
    const contribution = Math.max(1, Math.min(Number(current.weight || 1), Number(match.weight || current.weight || 1)));
    if (!group.common_entities.has(current.value_hash)) {
      group.score += contribution;
      group.common_entities.set(current.value_hash, { entity_type: current.entity_type, entity_value: current.entity_value, weight: contribution, trust_level: current.trust_level });
    }
    if (match.created_at && (!group.first_seen || match.created_at < group.first_seen)) group.first_seen = match.created_at;
    if (match.created_at && (!group.last_seen || match.created_at > group.last_seen)) group.last_seen = match.created_at;
  }
  const candidates = [...grouped.values()].map((group) => ({ ...group, common_entities: [...group.common_entities.values()] }))
    .filter((group) => group.score >= 3)
    .sort((a, b) => b.score - a.score || String(a.scan_id).localeCompare(String(b.scan_id)))
    .slice(0, 30);
  const meaningful = candidates.filter((group) => {
    const types = new Set(group.common_entities.map((item) => item.entity_type));
    const exactAttachment = types.has('attachment_sha256');
    const independentSignals = types.size >= 2;
    return exactAttachment || (group.score >= 8 && independentSignals);
  });
  const strongest = candidates[0]?.score || 0;
  const clusterScans = [currentScanId, ...meaningful.map((item) => item.scan_id)].filter(Boolean).sort();
  const campaignId = meaningful.length ? `vt_camp_${crypto.createHash('sha256').update(clusterScans.join(':')).digest('hex').slice(0, 16)}` : null;
  const common = new Map();
  for (const group of meaningful) for (const entity of group.common_entities) common.set(`${entity.entity_type}:${entity.entity_value}`, entity);
  return {
    state: meaningful.length ? 'CORRELATED' : 'NO_STRONG_MATCH',
    campaign_id: campaignId,
    related_scan_count: meaningful.length,
    weak_candidate_count: Math.max(0, candidates.length - meaningful.length),
    strongest_match_score: strongest,
    related_scans: meaningful.slice(0, 20),
    common_entities: [...common.values()].sort((a, b) => b.weight - a.weight).slice(0, 30),
    scoring_notice: 'Campaign Memory uses deterministic weighted overlap. An exact attachment hash can correlate by itself; otherwise at least two independent entity types and sufficient combined weight are required. ASN-only, IP-only, sender-domain-only, or URL-domain-only overlap cannot create a campaign.',
    producer_version: CAMPAIGN_MEMORY_VERSION,
  };
}

module.exports = { CAMPAIGN_MEMORY_VERSION, ENTITY_WEIGHTS, buildThreatEntities, campaignFromMatches, entityHash, normalizeEntity };
