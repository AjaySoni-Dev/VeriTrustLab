const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const root = path.resolve(__dirname, '..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');

test('completed email analysis redirects to a dedicated, tabbed forensic result page', () => {
  const page = read('phishing.html');
  const resultPage = read('phishing-result.html');
  const ui = read('assets/js/pages/email-investigation.js');
  const css = read('assets/css/pages/email-investigation-final.css');
  const progress = read('assets/js/core/analysis-progress.js');

  assert.match(page, /id="analysisProgressCompleted">\+0 completed/u);
  assert.match(page, /trusted SMTP observation adds the strongest transport boundary/u);
  assert.doesNotMatch(page, /strongest available email evidence/u);
  assert.match(ui, /global\.location\.assign\(resultPath\(payload\.scan_id\)\)/u);
  assert.match(ui, /\/phishing-result/u);
  assert.match(resultPage, /data-email-result-page/u);
  assert.match(resultPage, /name="robots" content="noindex, nofollow"|content="noindex, nofollow" name="robots"/u);
  assert.match(resultPage, /Investigation result/u);
  assert.match(ui, /role="tablist" aria-label="VeriTrust forensic capabilities"/u);
  for (const tab of ['progressive', 'geotrace', 'campaign', 'passport']) {
    assert.match(ui, new RegExp(`data-usp-tab="${tab}"`, 'u'));
    assert.match(ui, new RegExp(`data-usp-panel="${tab}"`, 'u'));
  }
  assert.match(ui, /ArrowLeft/u);
  assert.match(ui, /ArrowRight/u);
  assert.match(ui, /Evidence coverage/u);
  assert.match(ui, /Trusted receiver/u);
  assert.match(ui, /Correlation weight/u);
  assert.match(ui, /Evidence SHA-256/u);
  assert.match(ui, /button\.innerHTML = '<span aria-hidden="true">i<\/span>'/u);
  assert.match(ui, /View Complete Report/u);
  assert.match(ui, /data-view-email-pdf/u);
  assert.match(ui, /openEmailReportPdf/u);
  assert.match(ui, /Evidence JSON/u);
  assert.match(ui, /STIX 2\.1/u);
  assert.match(ui, /IOC CSV/u);
  assert.match(css, /\.email-usp-tabs\s*\{/u);
  assert.match(css, /grid-template-columns:\s*repeat\(4, minmax\(0, 1fr\)\)/u);
  assert.match(css, /\.email-usp-tabpanel\[hidden\]/u);
  assert.match(css, /body\.vt-email-result-page/u);
  assert.match(progress, /\+\$\{completedCount\} completed/u);
  assert.match(progress, /details\.open = false/u);
});

test('USP result navigation stays connected across dashboard, verifier, case review, and module guard', () => {
  const dashboard = read('dashboard.html');
  const dashboardUi = read('assets/js/pages/dashboard.js');
  const verifierUi = read('assets/js/pages/verify-evidence.js');
  const cases = read('assets/js/pages/cases.js');
  const middleware = read('middleware.ts');
  const site = read('assets/js/core/site.js');

  assert.match(dashboard, /data-recent-scans/u);
  assert.match(dashboardUi, /isEmailForensicScan/u);
  assert.match(dashboardUi, /Email Investigation/u);
  assert.match(dashboardUi, /Open Investigation/u);
  assert.match(dashboardUi, /\/phishing-result\?scan_id=/u);
  assert.match(verifierUi, /Back to investigation/u);
  assert.match(verifierUi, /\/phishing-result\?scan_id=/u);
  assert.match(cases, /Open source email investigation/u);
  assert.match(cases, /\/phishing-result\?scan_id=/u);
  assert.match(middleware, /'phishing-result': 'phishing'/u);
  assert.match(site, /'phishing-result': 'Investigation result'/u);
});

test('saved investigations recover persisted risk_score and PDF supports the same compatibility contract', () => {
  const route = read('lib/routes/email/v2.js');
  const ui = read('assets/js/pages/email-investigation.js');
  const pdf = require('../assets/js/core/email-report-pdf.js');

  assert.match(route, /latestDecision\.risk_score \?\? latestDecision\.risk/u);
  assert.match(ui, /decision\?\.risk_score/u);
  assert.match(ui, /item\?\.risk_score/u);

  const bytes = pdf.buildEmailReportPdf({
    scan_id: 'saved-risk-score-test',
    gateway_decision: { risk_score: 0.87, recommendation: 'quarantine' },
    evidence: { state: 'LIKELY_PHISHING', input_mode: 'raw_eml', evidence_completeness: { level: 'moderate' } },
  });
  const content = Buffer.from(bytes).toString('ascii');
  assert.match(content, /87%/u);
  assert.match(content, /Progressive Evidence Escalation/u);
  assert.match(content, /EVIDENCE ACQUISITION LADDER/u);
});

test('landing page tells one Acquire → Trace → Correlate → Verify story with two primary CTAs', () => {
  const home = read('index.html');
  assert.match(home, /Email threat detection with/u);
  assert.match(home, /evidence-aware forensic intelligence/u);
  assert.match(home, /Start Investigation/u);
  assert.match(home, /Run Live SMTP Demo/u);
  assert.match(home, /Progressive Evidence Escalation™/u);
  assert.match(home, /Trust-Boundary GeoTrace™/u);
  assert.match(home, /MailGraph Campaign Memory™/u);
  assert.match(home, /Evidence Passport™/u);
  assert.doesNotMatch(home, /Open Evidence Correlation/u);
});
