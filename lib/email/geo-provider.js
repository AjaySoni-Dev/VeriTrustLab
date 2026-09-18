const { classifyIp } = require('./infrastructure');

const IPWHOIS_BASE = 'https://ipwho.is';
const MAX_RESPONSE_BYTES = 64 * 1024;
const LOOKUP_TIMEOUT_MS = 2500;
const cache = new Map();

function normalizedCoordinate(value, min, max) {
  if (value === null || value === undefined || value === '') return null;
  const number = Number(value);
  return Number.isFinite(number) && number >= min && number <= max ? number : null;
}

function normalizedProviderResult(body, quality = 'provider-derived-infrastructure') {
  return {
    asn: normalizeAsn(body?.asn ?? body?.connection?.asn),
    asn_org: body?.asn_org || body?.asn_organization || body?.organization || body?.connection?.org || body?.connection?.isp || null,
    country: body?.country || body?.country_name || null,
    region: body?.region || body?.region_name || null,
    city: body?.city || null,
    latitude: normalizedCoordinate(body?.latitude ?? body?.lat, -90, 90),
    longitude: normalizedCoordinate(body?.longitude ?? body?.lon ?? body?.lng, -180, 180),
    reverse_dns: body?.reverse_dns || body?.reverse || null,
    quality: body?.quality || quality,
  };
}


function normalizeAsn(value) {
  if (value === null || value === undefined || value === '') return null;
  const text = String(value).trim().replace(/^AS/iu, '');
  const number = Number(text);
  return Number.isSafeInteger(number) && number >= 0 ? number : null;
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
    return normalizedProviderResult(body);
  })();

  cache.set(ip, promise);
  try {
    return await promise;
  } catch (error) {
    cache.delete(ip);
    throw error;
  }
}

function configuredProviderUrl(ip) {
  const raw = String(process.env.VERITRUST_GEO_PROVIDER_URL || '').trim();
  if (!raw) throw Object.assign(new Error('VERITRUST_GEO_PROVIDER_URL is required for the configured geo provider.'), { code: 'GEO_PROVIDER_URL_REQUIRED' });
  const value = raw.includes('{ip}')
    ? raw.replaceAll('{ip}', encodeURIComponent(ip))
    : `${raw.replace(/\/$/u, '')}/${encodeURIComponent(ip)}`;
  let parsed;
  try { parsed = new URL(value); } catch {
    throw Object.assign(new Error('VERITRUST_GEO_PROVIDER_URL is invalid.'), { code: 'GEO_PROVIDER_URL_INVALID' });
  }
  const localDevelopment = process.env.NODE_ENV !== 'production' && ['localhost', '127.0.0.1', '::1'].includes(parsed.hostname);
  if (parsed.protocol !== 'https:' && !(localDevelopment && parsed.protocol === 'http:')) {
    throw Object.assign(new Error('Configured geolocation provider must use HTTPS.'), { code: 'GEO_PROVIDER_URL_INVALID' });
  }
  if (parsed.username || parsed.password) {
    throw Object.assign(new Error('Configured geolocation provider URL must not contain credentials.'), { code: 'GEO_PROVIDER_URL_INVALID' });
  }
  return parsed.toString();
}

async function lookupConfiguredProvider(ip) {
  if (classifyIp(ip) !== 'public') {
    throw Object.assign(new Error('Only public infrastructure IP addresses can be enriched.'), { code: 'GEO_NON_PUBLIC_IP' });
  }
  const url = configuredProviderUrl(ip);
  const cacheKey = `configured:${url}`;
  if (cache.has(cacheKey)) return cache.get(cacheKey);
  const promise = (async () => {
    const token = String(process.env.VERITRUST_GEO_PROVIDER_TOKEN || '').trim();
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        'User-Agent': 'VeriTrust-Forensics/1.0',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      signal: AbortSignal.timeout(LOOKUP_TIMEOUT_MS),
      redirect: 'error',
    });
    if (!response.ok) throw Object.assign(new Error('Configured geolocation provider request failed.'), { code: `GEO_HTTP_${response.status}` });
    const body = await readJsonBounded(response);
    if (body?.success === false) throw Object.assign(new Error('Configured geolocation provider could not resolve this IP.'), { code: 'GEO_LOOKUP_UNAVAILABLE' });
    return normalizedProviderResult(body, 'configured-provider-infrastructure');
  })();
  cache.set(cacheKey, promise);
  try { return await promise; } catch (error) { cache.delete(cacheKey); throw error; }
}

function getInfrastructureGeoProvider() {
  const configured = String(process.env.VERITRUST_GEO_PROVIDER || 'ipwhois').trim().toLowerCase();
  if (['off', 'disabled', 'none', 'false', '0'].includes(configured)) return null;
  if (['ipwhois', 'ipwho.is'].includes(configured)) return { name: 'ipwho.is', lookup: lookupIpWhoIs };
  if (['configured', 'custom', 'proxy'].includes(configured)) return { name: 'configured', lookup: lookupConfiguredProvider };
  throw Object.assign(new Error('Unsupported VERITRUST_GEO_PROVIDER value.'), { code: 'GEO_PROVIDER_CONFIG_INVALID' });
}

module.exports = {
  configuredProviderUrl,
  getInfrastructureGeoProvider,
  lookupConfiguredProvider,
  lookupIpWhoIs,
  normalizedCoordinate,
  normalizedProviderResult,
};
