const assert = require('node:assert/strict');
const test = require('node:test');
const { createGateway, dispositionForDecision } = require('../mail-gateway/server');
const { createSmtpServer } = require('../mail-gateway/lib/smtp-server');
const { relayMessage, SmtpResponseError } = require('../mail-gateway/lib/smtp-client');
const { stripSpoofableVeriTrustHeaders } = require('../mail-gateway/lib/message');
const { validateTrustedReceiverMetadata } = require('../lib/email/contracts');
const { clientAllowed, recipientAllowed } = require('../mail-gateway/config');

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(server.address().port));
  });
}

function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

function gatewayConfig(upstreamPort) {
  return {
    api: {
      baseUrl: 'https://example.test',
      apiKey: 'vtg_test_abcdefghijklmnopqrstuvwxyz',
      receiverSecret: 'abcdefghijklmnopqrstuvwxyz0123456789',
      integrationId: '',
      receiverId: 'gateway.lab.local',
      authservId: 'gateway.lab.local',
      timeoutMs: 10000,
    },
    inbound: {
      host: '127.0.0.1',
      port: 0,
      hostname: 'gateway.lab.local',
      maxMessageBytes: 10 * 1024 * 1024,
      connectionTimeoutMs: 30000,
      maxConnections: 10,
      requireAuth: true,
      authUsername: 'sender',
      authPassword: 'very-long-password',
      allowAllRecipients: false,
      allowedRecipients: new Set(),
      allowedRecipientDomains: new Set(['lab.local']),
    },
    upstream: {
      host: '127.0.0.1',
      port: upstreamPort,
      secure: false,
      startTls: 'off',
      username: '',
      password: '',
      ehloName: 'gateway.lab.local',
      tlsServername: '',
      rejectUnauthorized: true,
      timeoutMs: 10000,
    },
    decisions: {
      forwardActions: new Set(['allow', 'warn']),
      deferActions: new Set(['manual_review', 'hold']),
      degradedMode: 'defer',
      apiFailureMode: 'defer',
      addHeaders: true,
    },
  };
}

function response(recommendation, risk = 0.1, degraded = false) {
  return {
    ok: true,
    scan_id: `scan-${recommendation}`,
    gateway_decision: { recommendation, risk, degraded, severity: risk >= 0.75 ? 'high' : 'low' },
    evidence: { input_mode: 'trusted_receiver_event' },
  };
}

test('transport disposition follows the existing Gateway recommendation instead of recomputing risk', () => {
  const decisions = gatewayConfig(25).decisions;
  assert.equal(dispositionForDecision(response('allow'), decisions), 'forward');
  assert.equal(dispositionForDecision(response('warn'), decisions), 'forward');
  assert.equal(dispositionForDecision(response('manual_review'), decisions), 'defer');
  assert.equal(dispositionForDecision(response('hold'), decisions), 'defer');
  assert.equal(dispositionForDecision(response('quarantine'), decisions), 'reject');
  assert.equal(dispositionForDecision(response('block'), decisions), 'reject');
  assert.equal(dispositionForDecision(response('allow', 0.1, true), decisions), 'defer');
});



test('SMTP anti-open-relay allowlists normalize mapped IPv4 and restrict recipient domains', () => {
  const inbound = {
    allowedClientIps: new Set(['127.0.0.1']),
    allowAllRecipients: false,
    allowedRecipients: new Set(['special@other.test']),
    allowedRecipientDomains: new Set(['lab.local']),
  };
  assert.equal(clientAllowed('::ffff:127.0.0.1', inbound), true);
  assert.equal(clientAllowed('192.0.2.10', inbound), false);
  assert.equal(recipientAllowed('receiver@lab.local', inbound), true);
  assert.equal(recipientAllowed('special@other.test', inbound), true);
  assert.equal(recipientAllowed('outsider@other.test', inbound), false);
});

test('trusted receiver metadata validates direct SMTP facts and supports a null reverse-path', () => {
  const result = validateTrustedReceiverMetadata({
    client_ip: '::ffff:127.0.0.1',
    mail_from: '<>',
    helo: 'sender.lab.local',
    receiver_id: 'gateway.lab.local',
    authserv_id: 'gateway.lab.local',
    received_at: new Date().toISOString(),
    event_id: 'event-1',
    integration_id: null,
  });
  assert.equal(result.client_ip, '127.0.0.1');
  assert.equal(result.mail_from, '');
  assert.throws(() => validateTrustedReceiverMetadata({ ...result, client_ip: 'not-an-ip' }));
});

test('sender-supplied VeriTrust headers are removed before trusted relay headers are applied', () => {
  const raw = Buffer.from('From: a@lab.local\r\nX-VeriTrust-Decision: allow\r\n\tspoofed-fold\r\nSubject: hi\r\n\r\nbody', 'utf8');
  const clean = stripSpoofableVeriTrustHeaders(raw).toString('utf8');
  assert.doesNotMatch(clean, /X-VeriTrust-Decision/iu);
  assert.doesNotMatch(clean, /spoofed-fold/iu);
  assert.match(clean, /Subject: hi/u);
});

test('allowed mail is analyzed first and only then relayed to the downstream receiver', async () => {
  const received = [];
  const receiver = createSmtpServer({
    hostname: 'receiver.lab.local',
    maxMessageBytes: 10 * 1024 * 1024,
    connectionTimeoutMs: 30000,
    maxConnections: 10,
    requireAuth: false,
    authUsername: '',
    authPassword: '',
    isRecipientAllowed: () => true,
    onMessage: async (envelope) => { received.push(envelope.raw); return { code: 250, enhanced: '2.0.0', message: 'stored' }; },
  });
  const receiverPort = await listen(receiver);
  let analyzedRaw = null;
  const config = gatewayConfig(receiverPort);
  const gateway = createGateway(config, {
    analyze: async (raw, envelope) => {
      analyzedRaw = raw;
      assert.equal(envelope.mailFrom, 'sender@lab.local');
      assert.deepEqual(envelope.recipients, ['receiver@lab.local']);
      return response('allow', 0.08, false);
    },
  });
  const gatewayPort = await listen(gateway);

  try {
    await relayMessage({
      host: '127.0.0.1', port: gatewayPort, secure: false, startTls: 'off',
      username: 'sender', password: 'very-long-password', ehloName: 'sender.lab.local',
      tlsServername: '', rejectUnauthorized: true, timeoutMs: 10000,
    }, { mailFrom: 'sender@lab.local', recipients: ['receiver@lab.local'] }, Buffer.from('From: sender@lab.local\r\nTo: receiver@lab.local\r\nSubject: hello\r\n\r\nSafe body\r\n'));

    assert.ok(analyzedRaw);
    assert.match(analyzedRaw.toString('utf8'), /^Received: from sender\.lab\.local/iu);
    assert.equal(received.length, 1);
    const delivered = received[0].toString('utf8');
    assert.match(delivered, /X-VeriTrust-Scan-Id: scan-allow/iu);
    assert.match(delivered, /X-VeriTrust-Decision: allow/iu);
    assert.match(delivered, /Received: from sender\.lab\.local/iu);
  } finally {
    await close(gateway);
    await close(receiver);
  }
});

test('blocked mail returns SMTP 550 to the sender and never reaches the downstream receiver', async () => {
  let delivered = 0;
  const receiver = createSmtpServer({
    hostname: 'receiver.lab.local', maxMessageBytes: 10 * 1024 * 1024, connectionTimeoutMs: 30000,
    maxConnections: 10, requireAuth: false, authUsername: '', authPassword: '', isRecipientAllowed: () => true,
    onMessage: async () => { delivered += 1; return { code: 250, enhanced: '2.0.0', message: 'stored' }; },
  });
  const receiverPort = await listen(receiver);
  const gateway = createGateway(gatewayConfig(receiverPort), { analyze: async () => response('block', 0.99, false) });
  const gatewayPort = await listen(gateway);
  try {
    await assert.rejects(relayMessage({
      host: '127.0.0.1', port: gatewayPort, secure: false, startTls: 'off', username: 'sender', password: 'very-long-password',
      ehloName: 'sender.lab.local', tlsServername: '', rejectUnauthorized: true, timeoutMs: 10000,
    }, { mailFrom: 'attacker@lab.local', recipients: ['receiver@lab.local'] }, Buffer.from('From: attacker@lab.local\r\nTo: receiver@lab.local\r\nSubject: verify password\r\n\r\nClick now\r\n')), (error) => {
      assert.ok(error instanceof SmtpResponseError);
      assert.equal(error.smtpCode, 550);
      assert.match(error.message, /rejected by VeriTrust policy/iu);
      return true;
    });
    assert.equal(delivered, 0);
  } finally {
    await close(gateway);
    await close(receiver);
  }
});

test('analysis failure returns a temporary SMTP error and does not bypass inspection', async () => {
  const config = gatewayConfig(2526);
  const gateway = createGateway(config, { analyze: async () => { throw Object.assign(new Error('offline'), { code: 'TEST_OFFLINE' }); } });
  const gatewayPort = await listen(gateway);
  try {
    await assert.rejects(relayMessage({
      host: '127.0.0.1', port: gatewayPort, secure: false, startTls: 'off', username: 'sender', password: 'very-long-password',
      ehloName: 'sender.lab.local', tlsServername: '', rejectUnauthorized: true, timeoutMs: 10000,
    }, { mailFrom: 'sender@lab.local', recipients: ['receiver@lab.local'] }, Buffer.from('From: sender@lab.local\r\nTo: receiver@lab.local\r\n\r\nbody\r\n')), (error) => {
      assert.ok(error instanceof SmtpResponseError);
      assert.equal(error.smtpCode, 451);
      return true;
    });
  } finally {
    await close(gateway);
  }
});
