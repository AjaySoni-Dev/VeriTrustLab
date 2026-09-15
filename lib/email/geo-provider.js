const { classifyIp } = require('./infrastructure');

const IPWHOIS_BASE = 'https://ipwho.is';
const MAX_RESPONSE_BYTES = 64 * 1024;
const LOOKUP_TIMEOUT_MS = 2500;
const cache = new Map();

function normalizeAsn(value) {
  if (value === null || value === undefined || value === '') return null;
  const text = String(value).trim().replace(/^AS/iu, '');
  const number = Number(text);
  return Number.isSafeInteger(number) && number >= 0 ? number : null;
}


function coordinate(value, minimum, maximum) {
  const number = Number(value);
  return Number.isFinite(number) && number >= minimum && number <= maximum ? number : null;
}

async function readJsonBounded(response) {
  const declared = Number(response.headers.get('content-length') || 0);
  if (declared > MAX_RESPONSE_BYTES) throw Object.assign(new Error('Geolocation response was too large.'), { code: 'GEO_RESPONSE_TOO_LARGE' });
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > MAX_RESPONSE_BYTES) throw Object.assign(new Error('Geolocation response was too large.'), { code: 'GEO_RESPONSE_TOO_LARGE' });
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch {
    throw Object.assign(new Error('Geolocation provider returned invalid JSON.'), { code: 'GEO_INVALID_RESPONSE' });
  }
}

async function lookupIpWhoIs(ip) {
  if (classifyIp(ip) !== 'public') {
    throw Object.assign(new Error('Only public infrastructure IP addresses can be enriched.'), { code: 'GEO_NON_PUBLIC_IP' });
  }
  if (cache.has(ip)) return cache.get(ip);

  const promise = (async () => {
    const response = await fetch(`${IPWHOIS_BASE}/${encodeURIComponent(ip)}`, {
      method: 'GET',
      headers: { Accept: 'application/json', 'User-Agent': 'VeriTrust-Forensics/1.0' },
      signal: AbortSignal.timeout(LOOKUP_TIMEOUT_MS),
      redirect: 'error',
    });
    if (!response.ok) {
      throw Object.assign(new Error('Geolocation provider request failed.'), { code: `GEO_HTTP_${response.status}` });
    }
    const body = await readJsonBounded(response);
    if (body?.success === false) {
      throw Object.assign(new Error('Geolocation provider could not resolve this IP.'), { code: 'GEO_LOOKUP_UNAVAILABLE' });
    }
    if (body?.ip && classifyIp(body.ip) !== 'public') {
      throw Object.assign(new Error('Geolocation provider returned a non-public address.'), { code: 'GEO_PROVIDER_IP_INVALID' });
    }
    if (body?.ip && classifyIp(ip) === 'public' && ip.includes('.') && String(body.ip) !== String(ip)) {
      throw Object.assign(new Error('Geolocation provider returned data for a different address.'), { code: 'GEO_PROVIDER_IP_MISMATCH' });
    }
    const result = {
      asn: normalizeAsn(body?.connection?.asn),
      asn_org: body?.connection?.org || body?.connection?.isp || null,
      country: body?.country || null,
      region: body?.region || null,
      city: body?.city || null,
      latitude: coordinate(body?.latitude, -90, 90),
      longitude: coordinate(body?.longitude, -180, 180),
      reverse_dns: null,
      quality: 'provider-derived-infrastructure',
    };
    if (![result.asn, result.asn_org, result.country, result.region, result.city, result.latitude, result.longitude].some((value) => value !== null && value !== undefined && value !== '')) {
      throw Object.assign(new Error('Geolocation provider returned no usable infrastructure data.'), { code: 'GEO_LOOKUP_EMPTY' });
    }
    return result;
  })();

  cache.set(ip, promise);
  try {
    return await promise;
  } catch (error) {
    cache.delete(ip);
    throw error;
  }
}

function getInfrastructureGeoProvider() {
  const configured = String(process.env.VERITRUST_GEO_PROVIDER || 'ipwhois').trim().toLowerCase();
  if (['off', 'disabled', 'none', 'false', '0'].includes(configured)) return null;
  if (!['ipwhois', 'ipwho.is'].includes(configured)) {
    throw Object.assign(new Error('Unsupported VERITRUST_GEO_PROVIDER value.'), { code: 'GEO_PROVIDER_CONFIG_INVALID' });
  }
  return { name: 'ipwho.is', lookup: lookupIpWhoIs };
}

module.exports = {
  getInfrastructureGeoProvider,
  lookupIpWhoIs,
};
