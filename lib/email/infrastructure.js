const crypto = require('crypto');
const net = require('net');
const { EMAIL_INFRASTRUCTURE_VERSION } = require('./contracts');

const MAX_GEO_LOOKUPS_PER_SCAN = 12;
const GEO_LOOKUP_CONCURRENCY = 4;

function ipv4Integer(ip) {
  return ip.split('.').reduce((value, octet) => (value * 256) + Number(octet), 0) >>> 0;
}

function inV4Range(ip, base, prefix) {
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (ipv4Integer(ip) & mask) === (ipv4Integer(base) & mask);
}

function classifyIp(value) {
  const ip = String(value || '').trim().replace(/^IPv6:/iu, '');
  const version = net.isIP(ip);
  if (!version) return 'malformed';
  if (version === 4) {
    if (inV4Range(ip, '127.0.0.0', 8)) return 'loopback';
    if (inV4Range(ip, '10.0.0.0', 8) || inV4Range(ip, '172.16.0.0', 12) || inV4Range(ip, '192.168.0.0', 16)) return 'private';
    if (inV4Range(ip, '0.0.0.0', 8) || inV4Range(ip, '100.64.0.0', 10) || inV4Range(ip, '169.254.0.0', 16)
      || inV4Range(ip, '192.0.0.0', 24) || inV4Range(ip, '192.0.2.0', 24) || inV4Range(ip, '198.18.0.0', 15)
      || inV4Range(ip, '198.51.100.0', 24) || inV4Range(ip, '203.0.113.0', 24) || inV4Range(ip, '224.0.0.0', 4)) return 'reserved';
    return 'public';
  }
  const normalized = ip.toLowerCase();
  if (normalized === '::1') return 'loopback';
  if (normalized === '::' || normalized.startsWith('ff') || normalized.startsWith('2001:db8:')) return 'reserved';
  if (/^f[cd]/u.test(normalized)) return 'private';
  if (/^fe[89ab]/u.test(normalized)) return 'reserved';
  return 'public';
}

function candidateIps(line) {
  const candidates = [];
  for (const match of String(line || '').matchAll(/\[?(IPv6:)?([0-9a-f:.]{3,})\]?/giu)) {
    const value = match[2].replace(/[.;]+$/u, '');
    if (net.isIP(value) && !candidates.includes(value)) candidates.push(value);
  }
  return candidates;
}

function extractInfrastructure(headerLines, options = {}) {
  const received = (headerLines || []).filter((row) => String(row.key || '').toLowerCase() === 'received');
  const hops = received.map((row, index) => {
    const line = String(row.line || '');
    const ips = candidateIps(line);
    const selected = ips.find((ip) => classifyIp(ip) === 'public') || ips[0] || null;
    const host = line.match(/\bfrom\s+([^\s(\[]+)/iu)?.[1]?.replace(/\.+$/u, '').toLowerCase() || null;
    return {
      hop_index: index,
      received_header_hash: crypto.createHash('sha256').update(line).digest('hex'),
      host,
      ip_address: selected,
      ip_classification: selected ? classifyIp(selected) : 'unknown',
      asn: null,
      asn_org: null,
      country: null,
      region: null,
      city: null,
      latitude: null,
      longitude: null,
      geo_provider: null,
      geo_observed_at: null,
      reverse_dns: null,
      trust_level: options.trustedReceiver && index === 0 ? 'trusted_receiver' : 'observed_relay',
      provenance: { source: 'received_header', all_candidate_ips: ips, exact_location_claim: false },
      producer_version: EMAIL_INFRASTRUCTURE_VERSION,
    };
  });
  return {
    hops,
    limitations: hops.some((hop) => hop.ip_classification === 'public') ? ['INFRASTRUCTURE_GEO_PROVIDER_UNAVAILABLE'] : ['NO_PUBLIC_INFRASTRUCTURE_IP_OBSERVED'],
  };
}

async function mapWithConcurrency(items, concurrency, mapper) {
  const source = Array.isArray(items) ? items : [];
  const limit = Math.max(1, Math.min(source.length || 1, Number(concurrency) || 1));
  const output = new Array(source.length);
  let cursor = 0;
  async function worker() {
    while (cursor < source.length) {
      const index = cursor;
      cursor += 1;
      output[index] = await mapper(source[index], index);
    }
  }
  await Promise.all(Array.from({ length: limit }, () => worker()));
  return output;
}

function hasInfrastructureContext(hop) {
  return Boolean(hop?.geo_provider && (hop.country || hop.region || hop.city || hop.asn || hop.asn_org));
}

function hasUsableCoordinates(hop) {
  if (hop?.latitude === null || hop?.latitude === undefined || hop?.latitude === ''
    || hop?.longitude === null || hop?.longitude === undefined || hop?.longitude === '') return false;
  const latitude = Number(hop.latitude);
  const longitude = Number(hop.longitude);
  return Number.isFinite(latitude) && latitude >= -90 && latitude <= 90
    && Number.isFinite(longitude) && longitude >= -180 && longitude <= 180;
}

async function enrichInfrastructure(hops, provider = null, options = {}) {
  const source = Array.isArray(hops) ? hops : [];
  const publicIps = [...new Set(source
    .filter((hop) => hop.ip_classification === 'public' && hop.ip_address)
    .map((hop) => String(hop.ip_address)))];
  if (!publicIps.length) {
    return { hops: source, state: 'UNAVAILABLE', provider: null, lookups: { unique_public_ips: 0, attempted: 0, succeeded: 0, failed: 0, skipped: 0 }, limitations: ['NO_PUBLIC_INFRASTRUCTURE_IP_OBSERVED'] };
  }
  if (!provider || typeof provider.lookup !== 'function') {
    return { hops: source, state: 'UNAVAILABLE', provider: null, lookups: { unique_public_ips: publicIps.length, attempted: 0, succeeded: 0, failed: 0, skipped: publicIps.length }, limitations: ['INFRASTRUCTURE_GEO_PROVIDER_UNAVAILABLE'] };
  }

  const maxLookups = Math.max(1, Math.min(64, Number(options.maxLookups) || MAX_GEO_LOOKUPS_PER_SCAN));
  const concurrency = Math.max(1, Math.min(8, Number(options.concurrency) || GEO_LOOKUP_CONCURRENCY));
  const lookupIps = publicIps.slice(0, maxLookups);
  const skippedIps = new Set(publicIps.slice(maxLookups));
  const lookupByIp = new Map();

  const results = await mapWithConcurrency(lookupIps, concurrency, async (ip) => {
    try {
      const result = await provider.lookup(ip);
      return { ip, ok: true, result: result || {}, observedAt: new Date().toISOString() };
    } catch (error) {
      return { ip, ok: false, errorCode: String(error?.code || 'LOOKUP_FAILED') };
    }
  });
  results.forEach((item) => lookupByIp.set(item.ip, item));

  const enriched = source.map((hop) => {
    if (hop.ip_classification !== 'public' || !hop.ip_address) return hop;
    const ip = String(hop.ip_address);
    if (skippedIps.has(ip)) {
      return { ...hop, provenance: { ...hop.provenance, enrichment_error: 'GEO_LOOKUP_CAP_REACHED' } };
    }
    const lookup = lookupByIp.get(ip);
    if (!lookup?.ok) {
      return { ...hop, provenance: { ...hop.provenance, enrichment_error: lookup?.errorCode || 'LOOKUP_FAILED' } };
    }
    const result = lookup.result;
    return {
      ...hop,
      asn: result.asn ?? null,
      asn_org: result.asn_org ?? null,
      country: result.country ?? null,
      region: result.region ?? null,
      city: result.city ?? null,
      latitude: hasUsableCoordinates({ latitude: result.latitude, longitude: result.longitude }) ? Number(result.latitude) : null,
      longitude: hasUsableCoordinates({ latitude: result.latitude, longitude: result.longitude }) ? Number(result.longitude) : null,
      reverse_dns: result.reverse_dns ?? null,
      geo_provider: provider.name || 'configured',
      geo_observed_at: lookup.observedAt,
      provenance: { ...hop.provenance, provider_quality: result.quality || 'unknown', exact_location_claim: false },
    };
  });

  const succeeded = results.filter((item) => item.ok).length;
  const failed = results.length - succeeded;
  const skipped = skippedIps.size;
  const state = succeeded === publicIps.length
    ? 'COMPLETED'
    : (succeeded > 0 ? 'PARTIAL' : 'UNAVAILABLE');
  const limitations = [];
  if (skipped) limitations.push('INFRASTRUCTURE_GEO_LOOKUP_CAP_REACHED');
  if (state === 'PARTIAL') limitations.push('INFRASTRUCTURE_GEO_PARTIAL');
  if (state === 'UNAVAILABLE') limitations.push('INFRASTRUCTURE_GEO_LOOKUP_FAILED');
  return {
    hops: enriched,
    state,
    provider: provider.name || 'configured',
    lookups: {
      unique_public_ips: publicIps.length,
      attempted: lookupIps.length,
      succeeded,
      failed,
      skipped,
      max_per_scan: maxLookups,
      concurrency,
    },
    limitations: [...new Set(limitations)],
  };
}

function summarizeInfrastructure(hops, options = {}) {
  const source = Array.isArray(hops) ? hops : [];
  const publicHops = source.filter((hop) => hop.ip_classification === 'public');
  const enrichedHops = publicHops.filter(hasInfrastructureContext);
  const coordinateHops = publicHops.filter(hasUsableCoordinates);
  const trustedBoundary = options.trustedReceiver
    ? publicHops.find((hop) => hop.trust_level === 'trusted_receiver') || null
    : null;
  const enrichmentState = !publicHops.length
    ? 'UNAVAILABLE'
    : (enrichedHops.length === publicHops.length ? 'COMPLETED' : (enrichedHops.length ? 'PARTIAL' : 'UNAVAILABLE'));
  const mapState = !publicHops.length || !coordinateHops.length
    ? 'UNAVAILABLE'
    : (coordinateHops.length === publicHops.length ? 'COMPLETED' : 'PARTIAL');
  return {
    state: trustedBoundary ? 'TRUSTED_BOUNDARY_OBSERVED' : (publicHops.length ? 'OBSERVED_UNVERIFIED' : 'UNAVAILABLE'),
    enrichment_state: enrichmentState,
    map_state: mapState,
    public_hop_count: publicHops.length,
    enriched_hop_count: enrichedHops.length,
    coordinate_hop_count: coordinateHops.length,
    // Backward-compatible field: "geolocated" now means actually mappable.
    geolocated_hop_count: coordinateHops.length,
    earliest_reliable_public_node: trustedBoundary ? {
      hop_index: trustedBoundary.hop_index,
      host: trustedBoundary.host || null,
      ip_address: trustedBoundary.ip_address || null,
      asn: trustedBoundary.asn || null,
      asn_org: trustedBoundary.asn_org || null,
      country: trustedBoundary.country || null,
      region: trustedBoundary.region || null,
      city: trustedBoundary.city || null,
      latitude: hasUsableCoordinates(trustedBoundary) ? Number(trustedBoundary.latitude) : null,
      longitude: hasUsableCoordinates(trustedBoundary) ? Number(trustedBoundary.longitude) : null,
      geo_provider: trustedBoundary.geo_provider || null,
      trust_level: trustedBoundary.trust_level,
    } : null,
    person_location_claim: false,
    wording: trustedBoundary
      ? 'A public infrastructure node is directly observed at the configured trusted receiver boundary. This does not identify the physical location or identity of a person.'
      : (publicHops.length
        ? 'Public Received-header infrastructure was observed, but no trusted receiver boundary proves sender origin. Locations are approximate infrastructure context only.'
        : 'No public mail-server infrastructure is available for origin interpretation.'),
  };
}

module.exports = {
  GEO_LOOKUP_CONCURRENCY,
  MAX_GEO_LOOKUPS_PER_SCAN,
  classifyIp,
  enrichInfrastructure,
  extractInfrastructure,
  hasInfrastructureContext,
  hasUsableCoordinates,
  summarizeInfrastructure,
};
