const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');

function assertNo(source, patterns) {
  for (const pattern of patterns) assert.doesNotMatch(source, pattern);
}

test('public copy reflects the enabled product surface and raw-EML trust boundary', () => {
  const modules = JSON.parse(read('config/modules.json'));
  assert.equal(modules.deepfake, false);

  const index = read('index.html');
  const phishing = read('phishing.html');
  const docs = read('docs.html');
  const privacy = read('privacy.html');
  const performance = read('model-performance.html');

  assert.match(index, /FOUR IMPLEMENTED CAPABILITIES/);
  assert.match(index, /raw EML/i);
  assertNo(index, [/FOUR IMPLEMENTED PROOFS/i, /exact attacker/i]);

  assert.match(phishing, /raw \.eml export/i);
  assert.match(phishing, /file format alone does not prove/i);
  assertNo(phishing, [/Upload original email/i, /preserves .* exactly as the mail application received/i]);

  assert.match(docs, /does not fetch webpages, resolve shortened links, or follow redirects/i);
  assert.match(privacy, /Media\/deepfake analysis is disabled/i);
  assert.match(performance, /No VeriTrust Lab benchmark is currently published/i);
  assert.match(performance, /Cortex code exists .* not qualified/i);
});

test('developer and OpenAPI copy matches implemented endpoints and evidence semantics', () => {
  const developers = read('developers.html');
  const emailApi = read('openapi/veritrust-email-v2.yaml');
  const gatewayApi = read('openapi/veritrust-gateway-v1.yaml');

  assert.match(developers, /POST \/api\/v1\/link-check/);
  assert.match(developers, /curl -X POST "https:\/\/YOUR_DOMAIN\/api\/v1\/phishing"/);
  assert.match(developers, /media submissions while the deepfake module is disabled/i);
  assertNo(developers, [/private uploads/i, /complete normalized gateway report/i]);

  assert.match(emailApi, /summary: Investigate pasted email content/);
  assert.match(emailApi, /Both the passport and evidence object are required/);
  assert.match(emailApi, /- PARTIAL/);
  assert.match(emailApi, /dimensions:\s*\n\s*type: object/);
  assert.match(emailApi, /observed-artifact export/i);
  assertNo(emailApi, [/pasted email or SMS content/i, /IOC export\. Specialist/i]);

  assert.match(gatewayApi, /Media fields remain in the schema .* rejected while deepfake is disabled/i);
  assertNo(gatewayApi, [/immutable policy/i, /private signed uploads/i]);
});

test('cryptographic and correlation copy does not overstate what is proven', () => {
  const passport = read('lib/email/evidence-passport.js');
  const ui = read('assets/js/pages/email-investigation.js');
  const verifier = read('verify-evidence.html');
  const pdf = read('assets/js/core/email-report-pdf.js');
  const campaign = read('lib/email/campaign-memory.js');

  assert.match(passport, /does not establish content truth, sender identity, message safety, attribution, or legal admissibility/);
  assert.match(verifier, /Does not establish/);
  assert.match(ui, /not attribution to a person, actor, organization, or globally verified campaign/);
  assert.match(pdf, /not actor attribution or a globally verified campaign/);
  assert.match(campaign, /cannot create a correlation match/);
  assertNo(ui, [/No strong prior campaign match/]);
});

test('URL and STIX outputs avoid safety and maliciousness overclaims', () => {
  const links = read('lib/link-intelligence.js');
  const stix = read('lib/email/ioc-export.js');

  assert.match(links, /return 'Lower risk'/);
  assert.match(links, /does not establish destination safety/);
  assert.match(links, /configured heuristic watchlist/);
  assertNo(links, [/normalized < 0\.45\) return 'Safe'/, /frequently appears in low-trust/i, /commonly seen in phishing links/i]);

  assert.match(stix, /observed email artifact/);
  assert.match(stix, /does not independently classify the artifact as malicious/);
  assertNo(stix, [/indicator_types:\s*\['malicious-activity'\]/]);
});

test('account, security, cases, and demo copy preserve deployment boundaries', () => {
  const account = read('account.html');
  const security = read('security.html');
  const cases = read('assets/js/pages/cases.js');
  const auth = read('auth.html');
  const gateway = read('gateway-powershell.html');

  assert.match(account, /Database-side guarantees also depend on the compatible deployed Supabase schema/);
  assert.match(security, /service-role operations bypass ordinary RLS/);
  assert.match(security, /refresh cookie is configured for up to 30 days/);
  assertNo(security, [/session-scoped/i, /safe deployment/i]);

  assert.match(cases, /not every completed investigation necessarily creates a case/);
  assert.match(auth, /works only when the deployment operator has seeded/i);
  assert.match(gateway, /infrastructure provenance and approximate infrastructure location, not exact attacker or person geolocation/i);
});

test('repository documentation states reproducibility limits instead of claiming a self-contained deployment', () => {
  const readme = read('README.md');
  const securityPolicy = read('SECURITY.md');

  assert.match(readme, /does not contain the complete historical base schema\/RPC migration set/);
  assert.match(readme, /fresh Supabase project cannot be reconstructed from this snapshot alone/);
  assert.match(readme, /No controlled VeriTrust Lab accuracy\/precision\/recall\/F1 benchmark is claimed/);
  assert.match(securityPolicy, /does not independently attest to the state of any live deployment/);
});
