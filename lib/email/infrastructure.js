const crypto = require('crypto');
const net = require('net');
const { EMAIL_INFRASTRUCTURE_VERSION } = require('./contracts');

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

async function enrichInfrastructure(hops, provider = null) {
  const source = Array.isArray(hops) ? hops : [];
  const publicCount = source.filter((hop) => hop.ip_classification === 'public').length;
  if (!publicCount) {
    return { hops: source, state: 'UNAVAILABLE', provider: null, limitations: ['NO_PUBLIC_INFRASTRUCTURE_IP_OBSERVED'] };
  }
  if (!provider || typeof provider.lookup !== 'function') {
    return { hops: source, state: 'UNAVAILABLE', provider: null, limitations: ['INFRASTRUCTURE_GEO_PROVIDER_UNAVAILABLE'] };
  }

  const enriched = [];
  let completed = 0;
  for (const hop of source) {
    if (hop.ip_classification !== 'public') { enriched.push(hop); continue; }
    try {
      const result = await provider.lookup(hop.ip_address);
      completed += 1;
      enriched.push({
        ...hop,
        asn: result.asn ?? null,
        asn_org: result.asn_org ?? null,
        country: result.country ?? null,
        region: result.region ?? null,
        city: result.city ?? null,
        latitude: result.latitude ?? null,
        longitude: result.longitude ?? null,
        reverse_dns: result.reverse_dns ?? null,
        geo_provider: provider.name || 'configured',
        geo_observed_at: new Date().toISOString(),
        provenance: { ...hop.provenance, provider_quality: result.quality || 'unknown', exact_location_claim: false },
      });
    } catch (error) {
      enriched.push({ ...hop, provenance: { ...hop.provenance, enrichment_error: String(error.code || 'LOOKUP_FAILED') } });
    }
  }
  const state = completed === publicCount ? 'COMPLETED' : (completed > 0 ? 'PARTIAL' : 'UNAVAILABLE');
  const limitations = state === 'COMPLETED'
    ? []
    : [completed > 0 ? 'INFRASTRUCTURE_GEO_PARTIAL' : 'INFRASTRUCTURE_GEO_LOOKUP_FAILED'];
  return { hops: enriched, state, provider: provider.name || 'configured', limitations };
}

function summarizeInfrastructure(hops, options = {}) {
  const source = Array.isArray(hops) ? hops : [];
  const publicHops = source.filter((hop) => hop.ip_classification === 'public');
  const geolocated = publicHops.filter((hop) => hop.geo_provider && (hop.country || hop.asn || hop.asn_org));
  const trustedBoundary = options.trustedReceiver
    ? publicHops.find((hop) => hop.trust_level === 'trusted_receiver') || null
    : null;
  return {
    state: trustedBoundary ? 'TRUSTED_BOUNDARY_OBSERVED' : (publicHops.length ? 'OBSERVED_UNVERIFIED' : 'UNAVAILABLE'),
    public_hop_count: publicHops.length,
    geolocated_hop_count: geolocated.length,
    earliest_reliable_public_node: trustedBoundary ? {
      hop_index: trustedBoundary.hop_index,
      host: trustedBoundary.host || null,
      ip_address: trustedBoundary.ip_address || null,
      asn: trustedBoundary.asn || null,
      asn_org: trustedBoundary.asn_org || null,
      country: trustedBoundary.country || null,
      region: trustedBoundary.region || null,
      city: trustedBoundary.city || null,
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

module.exports = { classifyIp, enrichInfrastructure, extractInfrastructure, summarizeInfrastructure };
