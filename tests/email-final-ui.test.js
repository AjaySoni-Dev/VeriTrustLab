const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const root = path.resolve(__dirname, '..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');

test('SIH final email UI is compact, viewport-oriented, and opens the complete PDF report', () => {
  const page = read('phishing.html');
  const ui = read('assets/js/pages/email-investigation.js');
  const css = read('assets/css/pages/email-investigation-final.css');
  const progress = read('assets/js/core/analysis-progress.js');

  assert.match(page, /id="analysisProgressCompleted">\+0 completed/u);
  assert.match(page, /class="analysis-progress-current"/u);
  assert.match(page, /email-investigation-final\.css/u);
  assert.match(ui, /View Complete Report/u);
  assert.match(ui, /data-view-email-pdf/u);
  assert.match(ui, /openEmailReportPdf/u);
  assert.match(ui, /vt-email-has-result/u);
  assert.match(ui, /The browser view intentionally shows only decision-critical information/u);
  assert.match(css, /body\.vt-email-investigation\s*\{[\s\S]*?height:\s*100vh;[\s\S]*?overflow:\s*hidden;/u);
  assert.match(css, /grid-template-columns:\s*minmax\(0, 1fr\) minmax\(310px, 360px\)/u);
  assert.match(progress, /\+\$\{completedCount\} completed/u);
  assert.match(progress, /details\.open = false/u);
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

test('landing hero ships exactly the three requested primary paths in one row above phone width', () => {
  const home = read('index.html');
  assert.doesNotMatch(home, /Explore Investigation Workflows/u);
  for (const label of ['Investigate Suspicious Email', 'Live SMTP Gateway', 'Open Evidence Correlation']) {
    assert.match(home, new RegExp(label, 'u'));
  }
  assert.match(home, /\.hero-actions\s*\{[\s\S]*?grid-template-columns:\s*repeat\(3, minmax\(0, 1fr\)\)/u);
  assert.match(home, /@media \(max-width: 560px\)[\s\S]*?\.hero-actions\s*\{[\s\S]*?grid-template-columns:\s*minmax\(0, 1fr\)/u);
});
