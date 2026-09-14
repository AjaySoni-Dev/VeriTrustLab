const dns = require('node:dns').promises;
const net = require('node:net');
const { domainToASCII } = require('node:url');
const { classifyIp } = require('./infrastructure');
const { getOptionalEnv } = require('../config');

const THREAT_INTEL_VERSION = 'mailgraph-threat-intel-1';
const RDAP_BASE = 'https://rdap.org/domain/';
const ABUSEIPDB_BASE = 'https://api.abuseipdb.com/api/v2/check';
const MAX_RESPONSE_BYTES = 256 * 1024;
const LOOKUP_TIMEOUT_MS = 3500;
const MAX_REDIRECTS = 3;
const cache = new Map();

function normalizeDomain(value) {
  const ascii = domainToASCII(String(value || '').trim().replace(/^\.+|\.+$/g, '').toLowerCase());
  if (!ascii || ascii.length > 253 || net.isIP(ascii) || !ascii.includes('.')) return null;
  if (!/^[a-z0-9.-]+$/u.test(ascii)) return null;
  if (ascii.split('.').some((label) => !label || label.length > 63 || label.startsWith('-') || label.endsWith('-'))) return null;
  return ascii;
}

async function lookupPublicAddresses(hostname) {
  let timer;
  try {
    return await Promise.race([
      dns.lookup(hostname, { all: true, verbatim: true }),
      new Promise((_, reject) => { timer = setTimeout(() => reject(Object.assign(new Error('Threat-intelligence DNS lookup timed out.'), { code: 'TI_DNS_TIMEOUT' })), 1800); timer.unref?.(); }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function ensurePublicHttps(url) {
  let parsed;
  try { parsed = new URL(url); } catch { throw Object.assign(new Error('Threat-intelligence URL is invalid.'), { code: 'TI_URL_INVALID' }); }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.port) {
    throw Object.assign(new Error('Threat-intelligence requests require standard-port HTTPS.'), { code: 'TI_URL_DENIED' });
  }
  if (net.isIP(parsed.hostname) || parsed.hostname === 'localhost' || parsed.hostname.endsWith('.local')) {
    throw Object.assign(new Error('Threat-intelligence destination is not allowed.'), { code: 'TI_DESTINATION_DENIED' });
  }
  const addresses = await lookupPublicAddresses(parsed.hostname);
  if (!addresses.length || addresses.some((item) => classifyIp(item.address) !== 'public')) {
    throw Object.assign(new Error('Threat-intelligence destination did not resolve only to public IP space.'), { code: 'TI_DESTINATION_NON_PUBLIC' });
  }
  return parsed;
}

async function readJsonBounded(response) {
  const declared = Number(response.headers.get('content-length') || 0);
  if (declared > MAX_RESPONSE_BYTES) throw Object.assign(new Error('Threat-intelligence response was too large.'), { code: 'TI_RESPONSE_TOO_LARGE' });
  const reader = response.body?.getReader?.();
  if (!reader) {
    const bytes = Buffer.from(await response.arrayBuffer());
    if (bytes.length > MAX_RESPONSE_BYTES) throw Object.assign(new Error('Threat-intelligence response was too large.'), { code: 'TI_RESPONSE_TOO_LARGE' });
    try { return JSON.parse(bytes.toString('utf8')); } catch { throw Object.assign(new Error('Threat-intelligence provider returned invalid JSON.'), { code: 'TI_INVALID_RESPONSE' }); }
  }
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw Object.assign(new Error('Threat-intelligence response was too large.'), { code: 'TI_RESPONSE_TOO_LARGE' });
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }
  try { return JSON.parse(Buffer.concat(chunks, total).toString('utf8')); } catch { throw Object.assign(new Error('Threat-intelligence provider returned invalid JSON.'), { code: 'TI_INVALID_RESPONSE' }); }
}

async function safeJsonFetch(initialUrl, options = {}) {
  let current = initialUrl;
  for (let redirect = 0; redirect <= MAX_REDIRECTS; redirect += 1) {
    await ensurePublicHttps(current);
    const response = await fetch(current, {
      method: 'GET',
      headers: { Accept: 'application/rdap+json, application/json', 'User-Agent': 'VeriTrust-Forensics/2.0', ...(options.headers || {}) },
      signal: AbortSignal.timeout(options.timeoutMs || LOOKUP_TIMEOUT_MS),
      redirect: 'manual',
    });
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get('location');
      if (!location || redirect === MAX_REDIRECTS) throw Object.assign(new Error('Threat-intelligence redirect chain was invalid.'), { code: 'TI_REDIRECT_INVALID' });
      current = new URL(location, current).href;
      continue;
    }
    if (!response.ok) throw Object.assign(new Error('Threat-intelligence provider request failed.'), { code: `TI_HTTP_${response.status}` });
    return readJsonBounded(response);
  }
  throw Object.assign(new Error('Threat-intelligence redirect limit exceeded.'), { code: 'TI_REDIRECT_LIMIT' });
}

function rdapEvent(body, actions) {
  const expected = new Set(actions.map((item) => item.toLowerCase()));
  const row = (Array.isArray(body?.events) ? body.events : []).find((item) => expected.has(String(item?.eventAction || '').toLowerCase()));
  if (!row?.eventDate) return null;
  const date = new Date(row.eventDate);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function registrarName(body) {
  for (const entity of Array.isArray(body?.entities) ? body.entities : []) {
    if (!(Array.isArray(entity.roles) && entity.roles.map((role) => String(role).toLowerCase()).includes('registrar'))) continue;
    const entries = entity?.vcardArray?.[1];
    if (!Array.isArray(entries)) continue;
    const fn = entries.find((item) => Array.isArray(item) && item[0] === 'fn');
    if (fn?.[3]) return String(fn[3]).slice(0, 200);
  }
  return null;
}

function nameservers(body) {
  return [...new Set((Array.isArray(body?.nameservers) ? body.nameservers : [])
    .map((item) => normalizeDomain(item?.ldhName || item?.unicodeName))
    .filter(Boolean))].slice(0, 12);
}

async function lookupDomainRdap(domain, nowMs = Date.now()) {
  const normalized = normalizeDomain(domain);
  if (!normalized) throw Object.assign(new Error('Domain is not eligible for RDAP lookup.'), { code: 'RDAP_DOMAIN_INVALID' });
  const cacheKey = `rdap:${normalized}`;
  const cached = cache.get(cacheKey);
  if (cached?.expiresAt > Date.now()) return cached.value;
  const body = await safeJsonFetch(`${RDAP_BASE}${encodeURIComponent(normalized)}`);
  const registrationDate = rdapEvent(body, ['registration', 'registered']);
  const expirationDate = rdapEvent(body, ['expiration', 'expiry']);
  const changedDate = rdapEvent(body, ['last changed', 'last update of rdap database']);
  const ageDays = registrationDate ? Math.max(0, Math.floor((nowMs - new Date(registrationDate).getTime()) / 86400000)) : null;
  const value = {
    domain: normalized,
    state: 'COMPLETED',
    registration_date: registrationDate,
    expiration_date: expirationDate,
    changed_date: changedDate,
    age_days: ageDays,
    recently_registered: Number.isFinite(ageDays) ? ageDays <= 90 : null,
    very_new_domain: Number.isFinite(ageDays) ? ageDays <= 30 : null,
    registrar: registrarName(body),
    nameservers: nameservers(body),
    statuses: Array.isArray(body?.status) ? body.status.map(String).slice(0, 20) : [],
    handle: body?.handle ? String(body.handle).slice(0, 160) : null,
    provider: 'rdap.org',
    observed_at: new Date(nowMs).toISOString(),
    producer_version: THREAT_INTEL_VERSION,
  };
  cache.set(cacheKey, { value, expiresAt: Date.now() + 6 * 3600000 });
  return value;
}

async function lookupAbuseIpDb(ip) {
  if (classifyIp(ip) !== 'public') throw Object.assign(new Error('Only public IP addresses can be checked for reputation.'), { code: 'IP_REPUTATION_NON_PUBLIC' });
  const key = getOptionalEnv('ABUSEIPDB_API_KEY', '');
  if (!key) throw Object.assign(new Error('IP reputation provider is not configured.'), { code: 'IP_REPUTATION_NOT_CONFIGURED' });
  const cacheKey = `abuseipdb:${ip}`;
  const cached = cache.get(cacheKey);
  if (cached?.expiresAt > Date.now()) return cached.value;
  const url = `${ABUSEIPDB_BASE}?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose=false`;
  const body = await safeJsonFetch(url, { headers: { Key: key, Accept: 'application/json' } });
  const data = body?.data || {};
  const score = Number.isFinite(Number(data.abuseConfidenceScore)) ? Number(data.abuseConfidenceScore) : null;
  const value = {
    ip_address: ip,
    state: 'COMPLETED',
    abuse_confidence_score: score,
    reputation: score === null ? 'unknown' : (score >= 75 ? 'high-risk' : (score >= 25 ? 'elevated' : 'low-reported-abuse')),
    total_reports: Number.isFinite(Number(data.totalReports)) ? Number(data.totalReports) : null,
    last_reported_at: data.lastReportedAt || null,
    usage_type: data.usageType || null,
    network_domain: data.domain || null,
    is_tor: Boolean(data.isTor),
    provider: 'AbuseIPDB',
    observed_at: new Date().toISOString(),
    producer_version: THREAT_INTEL_VERSION,
  };
  cache.set(cacheKey, { value, expiresAt: Date.now() + 30 * 60000 });
  return value;
}

async function mapLimited(values, limit, worker) {
  const source = [...new Set(values)].slice(0, limit);
  return Promise.all(source.map(async (value) => {
    try { return { ok: true, value: await worker(value) }; } catch (error) { return { ok: false, input: value, code: String(error?.code || 'LOOKUP_FAILED') }; }
  }));
}

function collectDomains(identity, extractedUrls) {
  const values = [];
  for (const group of [identity?.fromValues, identity?.replyValues, identity?.returnValues, identity?.senderValues]) {
    for (const item of group || []) if (item?.domain?.ascii) values.push(item.domain.ascii);
  }
  for (const edge of identity?.edges || []) if (String(edge.target_type || '').includes('domain')) values.push(edge.target_value);
  for (const item of extractedUrls || []) {
    try { values.push(new URL(item.url || item).hostname); } catch { /* already validated elsewhere */ }
  }
  return [...new Set(values.map(normalizeDomain).filter(Boolean))];
}

async function enrichThreatIntelligence({ domains = [], infrastructure = [] }) {
  const rdapEnabled = !['off', 'disabled', 'none', 'false', '0'].includes(String(getOptionalEnv('VERITRUST_RDAP_PROVIDER', 'rdap.org')).toLowerCase());
  const domainResults = rdapEnabled ? await mapLimited(domains, 8, lookupDomainRdap) : [];
  const publicIps = (infrastructure || []).filter((hop) => hop.ip_classification === 'public').map((hop) => hop.ip_address).filter(Boolean);
  const ipResults = await mapLimited(publicIps, 8, lookupAbuseIpDb);
  const domainIntelligence = domainResults.filter((item) => item.ok).map((item) => item.value);
  const ipReputation = ipResults.filter((item) => item.ok).map((item) => item.value);
  const limitations = [];
  if (!rdapEnabled) limitations.push('RDAP_LOOKUP_DISABLED');
  limitations.push(...domainResults.filter((item) => !item.ok).map((item) => item.code));
  if (!getOptionalEnv('ABUSEIPDB_API_KEY', '')) limitations.push('IP_REPUTATION_NOT_CONFIGURED');
  else limitations.push(...ipResults.filter((item) => !item.ok).map((item) => item.code));
  const observations = [];
  for (const item of domainIntelligence) {
    if (item.very_new_domain) observations.push({ code: 'DOMAIN_REGISTERED_WITHIN_30_DAYS', source: 'rdap', domain: item.domain, age_days: item.age_days, quality: 'provider-derived', producer_version: THREAT_INTEL_VERSION });
    else if (item.recently_registered) observations.push({ code: 'DOMAIN_REGISTERED_WITHIN_90_DAYS', source: 'rdap', domain: item.domain, age_days: item.age_days, quality: 'provider-derived', producer_version: THREAT_INTEL_VERSION });
  }
  for (const item of ipReputation) {
    if (Number(item.abuse_confidence_score) >= 75) observations.push({ code: 'INFRASTRUCTURE_IP_HIGH_ABUSE_REPUTATION', source: 'AbuseIPDB', ip_address: item.ip_address, abuse_confidence_score: item.abuse_confidence_score, quality: 'provider-derived', producer_version: THREAT_INTEL_VERSION });
    else if (Number(item.abuse_confidence_score) >= 25) observations.push({ code: 'INFRASTRUCTURE_IP_ELEVATED_ABUSE_REPUTATION', source: 'AbuseIPDB', ip_address: item.ip_address, abuse_confidence_score: item.abuse_confidence_score, quality: 'provider-derived', producer_version: THREAT_INTEL_VERSION });
  }
  const usable = domainIntelligence.length + ipReputation.length;
  const attempted = domainResults.length + ipResults.length;
  return {
    state: usable && usable === attempted ? 'COMPLETED' : (usable ? 'PARTIAL' : 'UNAVAILABLE'),
    domain_intelligence: domainIntelligence,
    ip_reputation: ipReputation,
    observations,
    limitations: [...new Set(limitations)],
    provider_notice: 'Registration and IP-reputation data are third-party observations captured at analysis time. Domain age or IP reputation alone does not prove malicious intent.',
    producer_version: THREAT_INTEL_VERSION,
  };
}

module.exports = {
  THREAT_INTEL_VERSION,
  collectDomains,
  enrichThreatIntelligence,
  lookupAbuseIpDb,
  lookupDomainRdap,
  normalizeDomain,
  safeJsonFetch,
};
