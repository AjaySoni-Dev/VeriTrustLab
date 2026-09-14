const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '..');
const ignoredDirectories = new Set(['.git', '.vercel', 'coverage', 'node_modules', 'output', 'tmp']);
const textExtensions = new Set([
  '.css', '.html', '.js', '.json', '.md', '.ts', '.txt', '.webmanifest', '.xml', '.yaml', '.yml',
]);
const failures = [];

function relative(file) {
  return path.relative(root, file).replaceAll(path.sep, '/');
}

function walk(directory = root) {
  const files = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory() && ignoredDirectories.has(entry.name)) continue;
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...walk(absolute));
    else if (entry.isFile()) files.push(absolute);
  }
  return files;
}

function read(relativePath) {
  const absolute = path.join(root, relativePath);
  if (!fs.existsSync(absolute)) {
    failures.push(`${relativePath} is missing`);
    return '';
  }
  return fs.readFileSync(absolute, 'utf8');
}

function requireText(relativePath, expected) {
  const source = read(relativePath);
  for (const value of expected) {
    if (!source.includes(value)) failures.push(`${relativePath} is missing ${value}`);
  }
}

const allFiles = walk().sort();
const sourceFiles = allFiles.filter((file) => ['.js', '.ts'].includes(path.extname(file)));
const htmlFiles = allFiles.filter((file) => path.dirname(file) === root && path.extname(file) === '.html');
const markdownFiles = allFiles.filter((file) => path.extname(file) === '.md');

for (const file of sourceFiles.filter((candidate) => path.extname(candidate) === '.js')) {
  const result = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
  if (result.status !== 0) failures.push(`${relative(file)} has invalid JavaScript syntax: ${result.stderr.trim()}`);
  const source = fs.readFileSync(file, 'utf8');
  for (const match of source.matchAll(/require\(["'](\.[^"']+)["']\)/gu)) {
    const target = path.resolve(path.dirname(file), match[1]);
    const candidates = [target, `${target}.js`, `${target}.json`, path.join(target, 'index.js')];
    if (!candidates.some((candidate) => fs.existsSync(candidate))) {
      failures.push(`${relative(file)} requires missing local module ${match[1]}`);
    }
  }
}

for (const file of markdownFiles) {
  const source = fs.readFileSync(file, 'utf8');
  for (const match of source.matchAll(/\[[^\]]*\]\(([^)]+)\)/gu)) {
    const reference = match[1].trim().replace(/^<|>$/gu, '').split(/\s+["']/u)[0].split('#')[0].split('?')[0];
    if (!reference || /^(?:[a-z]+:|\/\/)/iu.test(reference)) continue;
    let decoded = reference;
    try { decoded = decodeURIComponent(reference); } catch { /* invalid URLs are handled as missing paths */ }
    const target = path.resolve(path.dirname(file), decoded);
    if (!fs.existsSync(target)) failures.push(`${relative(file)} references missing local target ${reference}`);
  }
}

const vercel = JSON.parse(read('vercel.json'));
const rewriteSources = new Set((vercel.rewrites || []).map((entry) => entry.source));
const publicPages = new Map([
  ['index.html', '/'],
  ['detection.html', '/detection'],
  ['phishing.html', '/phishing'],
  ['link-check.html', '/link-check'],
  ['gateway.html', '/gateway'],
  ['developers.html', '/developers'],
  ['docs.html', '/docs'],
  ['gateway-powershell.html', '/gateway-powershell'],
  ['model-performance.html', '/model-performance'],
  ['privacy.html', '/privacy'],
  ['security.html', '/security'],
  ['terms.html', '/terms'],
  ['disclaimer.html', '/disclaimer'],
]);

function localTargetExists(reference) {
  const clean = reference.split('#')[0].split('?')[0];
  if (!clean || /^(?:[a-z]+:|\/\/)/iu.test(clean)) return true;
  if (clean.startsWith('/api/')) return true;
  const normalized = clean.startsWith('/') ? clean.slice(1) : clean;
  if (!normalized) return fs.existsSync(path.join(root, 'index.html'));
  const direct = path.join(root, normalized);
  if (fs.existsSync(direct)) return true;
  if (!path.extname(normalized) && fs.existsSync(`${direct}.html`)) return true;
  return rewriteSources.has(clean.startsWith('/') ? clean : `/${clean}`);
}

for (const file of htmlFiles) {
  const name = path.basename(file);
  const source = fs.readFileSync(file, 'utf8');
  for (const required of ['<!DOCTYPE html>', '<title>', 'name="description"']) {
    if (!source.toLowerCase().includes(required.toLowerCase())) failures.push(`${name} is missing ${required}`);
  }
  if (!/<html\b[^>]*\blang=["']en["']/iu.test(source)) failures.push(`${name} is missing an English html lang attribute`);
  const ids = [...source.matchAll(/\bid=["']([^"']+)["']/gu)].map((match) => match[1]);
  const duplicates = ids.filter((id, index) => ids.indexOf(id) !== index);
  if (duplicates.length) failures.push(`${name} has duplicate IDs: ${[...new Set(duplicates)].join(', ')}`);
  for (const match of source.matchAll(/\b(?:href|src)=["']([^"']+)["']/gu)) {
    const reference = match[1];
    if (!localTargetExists(reference)) failures.push(`${name} references missing local target ${reference}`);
  }
  if (publicPages.has(name)) {
    const canonical = `https://www.veritrustlab.in${publicPages.get(name)}`;
    const canonicalTag = [...source.matchAll(/<link\b[^>]*>/giu)].some((match) => /\brel=["']canonical["']/iu.test(match[0]) && match[0].includes(canonical));
    if (!canonicalTag) failures.push(`${name} has no canonical URL`);
    const publicRobots = [...source.matchAll(/<meta\b[^>]*>/giu)].some((match) => /\bname=["']robots["']/iu.test(match[0]) && /\bcontent=["']index, follow, max-image-preview:large["']/iu.test(match[0]));
    if (!publicRobots) failures.push(`${name} is missing the public robots directive`);
  } else {
    const privateRobots = [...source.matchAll(/<meta\b[^>]*>/giu)].some((match) => /\bname=["']robots["']/iu.test(match[0]) && /\bcontent=["']noindex, nofollow["']/iu.test(match[0]));
    if (!privateRobots) failures.push(`${name} must be excluded from search indexing`);
  }
}

const apiEntrypoints = fs.readdirSync(path.join(root, 'api'), { withFileTypes: true })
  .filter((entry) => entry.isFile() && /\.(?:js|ts)$/u.test(entry.name))
  .map((entry) => entry.name)
  .sort();
if (apiEntrypoints.length > 12) failures.push(`Vercel function budget exceeded: ${apiEntrypoints.length}/12`);
if (apiEntrypoints.some((name) => name.startsWith('_'))) failures.push('Private implementation files must not live in api/');
for (const [functionPath, configuration] of Object.entries(vercel.functions || {})) {
  if (Number(configuration.maxDuration) > 60) {
    failures.push(`${functionPath} exceeds the 60-second Vercel Hobby duration limit`);
  }
}
if (vercel.cleanUrls) {
  for (const entry of [...(vercel.redirects || []), ...(vercel.rewrites || [])]) {
    if (entry.source.endsWith('.html') || String(entry.destination).split('?')[0].endsWith('.html')) {
      failures.push(`cleanUrls routes must not include .html: ${entry.source} -> ${entry.destination}`);
    }
  }
}

const globalHeaders = vercel.headers?.find((entry) => entry.source === '/(.*)')?.headers || [];
const headerMap = new Map(globalHeaders.map((header) => [header.key.toLowerCase(), header.value]));
for (const required of [
  'content-security-policy', 'strict-transport-security', 'x-content-type-options', 'referrer-policy',
  'permissions-policy', 'x-frame-options', 'cross-origin-opener-policy', 'cross-origin-resource-policy',
]) {
  if (!headerMap.has(required)) failures.push(`vercel.json is missing ${required}`);
}
const csp = headerMap.get('content-security-policy') || '';
for (const directive of ["default-src 'self'", "base-uri 'none'", "object-src 'none'", "frame-ancestors 'none'", "script-src-attr 'none'"]) {
  if (!csp.includes(directive)) failures.push(`CSP is missing ${directive}`);
}
const inlineJsonLd = read('index.html').match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/u)?.[1];
if (!inlineJsonLd) {
  failures.push('index.html is missing JSON-LD');
} else {
  const inlineHash = `sha256-${crypto.createHash('sha256').update(inlineJsonLd).digest('base64')}`;
  if (!csp.includes(`'${inlineHash}'`)) failures.push('CSP does not authorize the current JSON-LD content');
}

requireText('lib/routes/account/auth-session.js', ['enforceRateLimit', 'validateJsonContentType']);
requireText('lib/routes/account/api-keys.js', ['validateJsonContentType']);
requireText('lib/routes/account/profile.js', ['AbortSignal.timeout', 'validateImageUpload']);
requireText('lib/supabase-server.js', ['AbortSignal.timeout', 'UPSTREAM_RESPONSE_TOO_LARGE']);
requireText('lib/billing.js', ['AbortSignal.timeout', 'BILLING_RESPONSE_TOO_LARGE']);

requireText('middleware.ts', ['moduleGuardMiddleware', 'config/modules.json']);
requireText('lib/email/service.js', ['evidence_completeness', 'evidence_manifest', 'infrastructure_summary', 'forensic_metadata']);
requireText('config/modules.json', ['"deepfake": false', '"phishing": true', '"link": true', '"gateway": true']);
requireText('supabase/migrations/20260911_forensic_intelligence.sql', [
  'email_threat_entities', 'email_evidence_passports', 'enable row level security',
  'veritrust_prevent_evidence_passport_update',
]);

const secretRules = [
  ['private key', /-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----/u],
  ['AWS access key', /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/u],
  ['GitHub token', /\bgh[pousr]_[A-Za-z0-9]{30,255}\b/u],
  ['Hugging Face token', /\bhf_[A-Za-z0-9]{24,}\b/u],
  ['Supabase access token', /\bsbp_[A-Za-z0-9]{24,}\b/u],
  ['Stripe live key', /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b/u],
  ['Stripe webhook secret', /\bwhsec_[A-Za-z0-9]{16,}\b/u],
  ['JWT credential', /\beyJ[A-Za-z0-9_-]{30,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/u],
];
for (const file of allFiles.filter((candidate) => textExtensions.has(path.extname(candidate)) || path.basename(candidate).startsWith('.env'))) {
  if (path.basename(file).startsWith('.env') && path.basename(file) !== '.env.example') {
    failures.push(`${relative(file)} is an environment file and must not be committed`);
    continue;
  }
  const source = fs.readFileSync(file, 'utf8');
  for (const [name, pattern] of secretRules) {
    if (pattern.test(source)) failures.push(`${relative(file)} may contain a ${name}`);
  }
}

for (const obsolete of [
  'test', 'transformation', 'db',
  'assets/js/pages/detection.dark-onepage-v5.js', 'assets/js/pages/detection.dark-onepage-v6.js',
  'assets/js/pages/reporting.dark-onepage-v5.js', 'assets/js/pages/reporting.dark-onepage-v6.js',
]) {
  if (fs.existsSync(path.join(root, obsolete))) failures.push(`obsolete artifact remains: ${obsolete}`);
}

const robots = read('robots.txt');
const sitemap = read('sitemap.xml');
if (!robots.includes('Sitemap: https://www.veritrustlab.in/sitemap.xml')) failures.push('robots.txt has no canonical sitemap URL');
for (const route of publicPages.values()) {
  const url = `https://www.veritrustlab.in${route}`;
  if (!sitemap.includes(`<loc>${url}</loc>`)) failures.push(`sitemap.xml is missing ${url}`);
}

if (failures.length) {
  console.error(`Verification failed with ${failures.length} issue(s):`);
  for (const failure of failures) console.error(`- ${failure}`);
  process.exitCode = 1;
} else {
  console.log(`Verified ${htmlFiles.length} pages, ${sourceFiles.length} source files, ${apiEntrypoints.length}/12 Vercel functions, security headers, SEO metadata, local links, and committed-secret rules.`);
}
