const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {
  MAX_GEO_LOOKUPS_PER_SCAN,
  enrichInfrastructure,
  summarizeInfrastructure,
} = require('../lib/email/infrastructure');
const { normalizedProviderResult } = require('../lib/email/geo-provider');

function hop(index, ip) {
  return {
    hop_index: index,
    ip_address: ip,
    ip_classification: 'public',
    trust_level: index === 0 ? 'trusted_receiver' : 'observed_relay',
    provenance: {},
  };
}

test('GeoTrace deduplicates lookup IPs and maps one provider result to duplicate hops', async () => {
  const calls = [];
  const provider = {
    name: 'test-provider',
    async lookup(ip) {
      calls.push(ip);
      return { asn: 64500, country: 'Example', latitude: 10, longitude: 20, quality: 'test' };
    },
  };
  const result = await enrichInfrastructure([hop(0, '8.8.8.8'), hop(1, '8.8.8.8')], provider);
  assert.deepEqual(calls, ['8.8.8.8']);
  assert.equal(result.state, 'COMPLETED');
  assert.equal(result.lookups.unique_public_ips, 1);
  assert.equal(result.hops[0].latitude, 10);
  assert.equal(result.hops[1].longitude, 20);
});

test('GeoTrace caps lookup work and reports partial coverage without fake coordinates', async () => {
  let calls = 0;
  const provider = { name: 'test-provider', async lookup() { calls += 1; return { country: 'Example', latitude: 1, longitude: 2 }; } };
  const hops = Array.from({ length: MAX_GEO_LOOKUPS_PER_SCAN + 3 }, (_, index) => hop(index, `8.8.4.${index + 1}`));
  const result = await enrichInfrastructure(hops, provider);
  assert.equal(calls, MAX_GEO_LOOKUPS_PER_SCAN);
  assert.equal(result.state, 'PARTIAL');
  assert.equal(result.lookups.skipped, 3);
  assert.ok(result.limitations.includes('INFRASTRUCTURE_GEO_LOOKUP_CAP_REACHED'));
  assert.equal(result.hops.at(-1).latitude ?? null, null);
});

test('GeoTrace summary distinguishes enrichment context from actually mappable coordinates', () => {
  const summary = summarizeInfrastructure([
    { ...hop(0, '8.8.8.8'), geo_provider: 'test', country: 'US', asn: 15169, latitude: null, longitude: null },
    { ...hop(1, '1.1.1.1'), geo_provider: 'test', country: 'AU', asn: 13335, latitude: -33.86, longitude: 151.20 },
  ], { trustedReceiver: true });
  assert.equal(summary.enriched_hop_count, 2);
  assert.equal(summary.coordinate_hop_count, 1);
  assert.equal(summary.geolocated_hop_count, 1);
  assert.equal(summary.map_state, 'PARTIAL');
  assert.equal(summary.state, 'TRUSTED_BOUNDARY_OBSERVED');
});

test('result-page CSS preserves the real world-map background image', () => {
  const root = path.resolve(__dirname, '..');
  const base = fs.readFileSync(path.join(root, 'assets/css/base/product-unified.css'), 'utf8');
  const resultCss = fs.readFileSync(path.join(root, 'assets/css/pages/phishing-result-sih.css'), 'utf8');
  const html = fs.readFileSync(path.join(root, 'phishing-result.html'), 'utf8');
  assert.match(base, /world-map-equirectangular\.svg/u);
  const resultRule = resultCss.match(/html body\.vt-email-result-page \.email-geotrace-map,[\s\S]*?\n\}/u)?.[0] || '';
  assert.match(resultRule, /background-color:\s*rgba\(16, 18, 22, 0\.9\)\s*!important;/u);
  assert.doesNotMatch(resultRule, /\n\s*background\s*:/u);
  assert.match(resultRule, /min-height:\s*0\s*!important;/u);
  assert.match(resultRule, /aspect-ratio:\s*2\s*\/\s*1\s*!important;/u);
  assert.match(html, /phishing-result-sih\.css\?v=20260918-geotrace1/u);
});


test('GeoTrace frontend rejects null/empty/out-of-range coordinates instead of coercing them to zero', () => {
  const root = path.resolve(__dirname, '..');
  const source = fs.readFileSync(path.join(root, 'assets/js/pages/email-investigation.js'), 'utf8');
  assert.match(source, /hop\.latitude !== null[\s\S]*hop\.longitude !== null/u);
  assert.match(source, /latitude >= -90 && latitude <= 90/u);
  assert.match(source, /longitude >= -180 && longitude <= 180/u);
  assert.match(source, /No public relay returned usable latitude\/longitude enrichment/u);
});

test('GeoTrace never coerces missing provider coordinates to the Gulf of Guinea', async () => {
  const provider = { name: 'test-provider', async lookup() { return { country: 'Example', latitude: null, longitude: null }; } };
  const result = await enrichInfrastructure([hop(0, '8.8.8.8')], provider);
  assert.equal(result.hops[0].latitude, null);
  assert.equal(result.hops[0].longitude, null);
  const summary = summarizeInfrastructure(result.hops, { trustedReceiver: true });
  assert.equal(summary.coordinate_hop_count, 0);
  assert.equal(summary.map_state, 'UNAVAILABLE');
});


test('Geo provider normalization rejects empty and out-of-range coordinate values', () => {
  assert.equal(normalizedProviderResult({ latitude: '', longitude: '' }).latitude, null);
  assert.equal(normalizedProviderResult({ latitude: 91, longitude: 181 }).latitude, null);
  assert.equal(normalizedProviderResult({ latitude: 91, longitude: 181 }).longitude, null);
  assert.equal(normalizedProviderResult({ latitude: '12.5', longitude: '-77.2' }).latitude, 12.5);
});
