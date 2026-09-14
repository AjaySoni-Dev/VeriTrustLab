const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const root = path.resolve(__dirname, '..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');

test('Unified Gateway exposes text, EML, and evidence email routes', () => {
  const configuration = JSON.parse(read('vercel.json'));
  const rewrites = new Map(configuration.rewrites.map((item) => [item.source, item.destination]));

  assert.equal(rewrites.get('/api/v1/gateway/email/analyze-text'), '/api/gateway?resource=email-text');
  assert.equal(rewrites.get('/api/v1/gateway/email/analyze-eml'), '/api/gateway?resource=email-eml');
  assert.equal(rewrites.get('/api/v1/gateway/email/evidence/:id'), '/api/gateway?resource=email-evidence&id=:id');
  assert.equal(rewrites.get('/internal/v2/phishing/receiver-eml'), '/api/gateway?resource=email-receiver-eml');
  const receiverRoute = read('lib/routes/email/v2.js');
  assert.match(receiverRoute, /trust_authentication_results_headers: false/u);
});

test('PowerShell guide supports both pasted text and an original EML file', () => {
  const guide = read('gateway-powershell.html');
  const command = read('assets/powershell/VeriTrust.EmailInvestigation.ps1');

  assert.match(guide, /assets\/powershell\/VeriTrust\.EmailInvestigation\.ps1/u);
  assert.match(guide, /Get-Command Invoke-VeriTrustEmailInvestigation -ErrorAction Stop/u);
  assert.match(guide, /if \(-not \(Get-Command Invoke-VeriTrustEmailInvestigation/u);
  assert.match(command, /function Invoke-VeriTrustEmailInvestigation/u);
  assert.match(command, /ParameterSetName = 'Text'/u);
  assert.match(command, /ParameterSetName = 'Eml'/u);
  assert.match(command, /\/api\/v1\/gateway\/email\/analyze-text/u);
  assert.match(command, /\/api\/v1\/gateway\/email\/analyze-eml/u);
  assert.match(command, /-ContentType 'message\/rfc822'/u);
  assert.match(command, /-InFile \$EmailFile\.FullName/u);
});

test('Email investigation UI uses the Gateway aliases and accessible contextual help', () => {
  const page = read('phishing.html');
  const script = read('assets/js/pages/email-investigation.js');

  assert.match(page, /id="emailHelpTooltip"[^>]*role="tooltip"/u);
  assert.match(page, /data-email-help=/u);
  assert.doesNotMatch(page, /data-email-mode="receiver"/u);
  assert.match(script, /\/api\/v1\/gateway\/email\/analyze-text/u);
  assert.match(script, /\/api\/v1\/gateway\/email\/analyze-eml/u);
  assert.match(script, /aria-label.*Explain/u);
  assert.match(script, /email-help-button/u);
  assert.match(page, /email-report-pdf\.js/u);
  assert.match(script, /data-view-email-pdf/u);
  assert.match(script, /await global\.VeriTrustEmailPdf\.openEmailReportPdf/u);
});

test('Email investigation builds a light PDF with complete evidence and a final glossary', () => {
  const pdf = require('../assets/js/core/email-report-pdf.js');
  const bytes = pdf.buildEmailReportPdf({
    ok: true,
    scan_id: 'scan-test-123',
    gateway_decision: { risk: 0.91, recommendation: 'quarantine', degraded: true },
    evidence: {
      state: 'LIKELY_PHISHING',
      input_mode: 'eml',
      limitations: ['SPF_UNAVAILABLE_WITHOUT_TRUSTED_RECEIVER_FACTS'],
      observations: [{ protocol: 'DKIM', result: 'PASS' }, { code: 'CREDENTIAL_REQUEST' }],
      relationships: [{ edge_type: 'FROM_TO_REPLY_TO', target_value: 'example.test' }],
      children: [{ type: 'url', state: 'completed', metadata: { hostname: 'example.test' } }],
      infrastructure: [{ ip_address: '203.0.113.10', country: 'Test' }],
      model_evidence: [{ status: 'completed', p_phish: 0.93 }],
    },
  });
  const content = Buffer.from(bytes).toString('ascii');

  assert.match(content, /^%PDF-1\.4/u);
  assert.match(content, /FORENSIC FINDINGS/u);
  assert.match(content, /Complete response data/u);
  assert.match(content, /"observations":/u);
  assert.match(content, /\/BaseFont \/Courier/u);
  assert.match(content, /Glossary: terms and meanings/u);
  assert.match(content, /SPF/u);
  assert.match(content, /Manual review/u);
  assert.ok((content.match(/\/Type \/Page\b/gu) || []).length >= 2);
});

test('Email report loads the official VeriTrust wordmark for browser downloads', () => {
  const generator = read('assets/js/core/email-report-pdf.js');

  assert.match(generator, /fetch\('\/assets\/images\/brand\.png'/u);
  assert.match(generator, /\/ASCIIHexDecode \/DCTDecode/u);
  assert.match(generator, /this\.image\('Logo'/u);
  assert.match(generator, /async function downloadEmailReportPdf/u);
});


test('SMTP enforcement gateway is packaged separately from Vercel with PowerShell controls', () => {
  const server = read('mail-gateway/server.js');
  const module = read('mail-gateway/powershell/VeriTrust.MailGateway.ps1');
  const guide = read('mail-gateway/README.md');

  assert.match(server, /trusted_receiver_event|analyzeTrustedReceiver/u);
  assert.match(server, /Message rejected by VeriTrust policy/u);
  assert.match(module, /function Start-VeriTrustMailGateway/u);
  assert.match(module, /function Test-VeriTrustMailGateway/u);
  assert.match(module, /function Send-VeriTrustGatewayTestMail/u);
  assert.match(module, /function Start-VeriTrustTestReceiver/u);
  assert.match(guide, /Sender laptop \/ mail client/u);
  assert.match(guide, /SMTP 550/u);
});


test('Persistent PowerShell SMTP CLI is integrated into public UI and packaged for download', () => {
  const guide = read('gateway-powershell.html');
  const home = read('index.html');
  const dashboard = read('dashboard.html');
  const gateway = read('gateway.html');
  const receiver = read('assets/powershell/VeriTrust-Receiver-CLI.ps1');
  const sender = read('assets/powershell/VeriTrust-Sender-CLI.ps1');
  const manifest = JSON.parse(read('assets/downloads/veritrust-cli-manifest.json'));

  assert.match(home, /gateway-powershell\.html#live-smtp/u);
  assert.match(dashboard, /workspace-card-live-gateway/u);
  assert.match(gateway, /gateway-powershell\.html#live-smtp/u);
  assert.match(guide, /id="live-smtp"/u);
  assert.match(guide, /VeriTrust-Lab-Persistent-CLI\.zip/u);
  assert.match(guide, /same Tailscale account/u);
  assert.match(guide, /VERITRUST_EMAIL_RECEIVER_SECRET/u);
  assert.match(guide, /VERITRUST_TRUSTED_AUTHSERV_IDS=veritrust-smtp-gateway/u);

  assert.match(receiver, /VTCLI2\|/u);
  assert.match(receiver, /Install-Tailscale/u);
  assert.match(receiver, /Get-Node24/u);
  assert.match(receiver, /VERITRUST_EMAIL_RECEIVER_SECRET/u);
  assert.doesNotMatch(receiver, /return\$match/u);
  assert.match(sender, /\/send <file\.eml>/u);
  assert.match(sender, /Test-PeerKnown/u);
  assert.equal(manifest.version, '2.0.1');
  assert.match(guide, /veritrust-live-cli-logo\.png/u);

  for (const file of [
    'assets/downloads/VeriTrust-Lab-Persistent-CLI.zip',
    'assets/downloads/VeriTrust-SMTP-Gateway-Runtime.zip',
    'assets/powershell/VeriTrust-Receiver-CLI.ps1',
    'assets/powershell/VeriTrust-Sender-CLI.ps1',
    'assets/images/veritrust-live-cli-logo.png',
  ]) {
    assert.equal(fs.existsSync(path.join(root, file)), true, `${file} should exist`);
  }
});

