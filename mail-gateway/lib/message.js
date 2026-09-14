const net = require('node:net');

function safeToken(value, fallback = 'unknown') {
  const text = String(value || '').trim();
  if (!text || /[\r\n\u0000-\u001f\u007f]/u.test(text)) return fallback;
  return text.slice(0, 512);
}

function normalizeIp(value) {
  let ip = String(value || '').trim();
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  return net.isIP(ip) ? ip : '0.0.0.0';
}

function stripSpoofableVeriTrustHeaders(raw) {
  const source = Buffer.isBuffer(raw) ? raw : Buffer.from(raw || '');
  const marker = source.indexOf(Buffer.from('\r\n\r\n'));
  const fallbackMarker = marker === -1 ? source.indexOf(Buffer.from('\n\n')) : -1;
  const splitAt = marker !== -1 ? marker : fallbackMarker;
  if (splitAt === -1) return source;
  const separatorLength = marker !== -1 ? 4 : 2;
  const headerText = source.subarray(0, splitAt).toString('latin1');
  const body = source.subarray(splitAt + separatorLength);
  const lines = headerText.split(/\r?\n/u);
  const kept = [];
  let dropping = false;
  for (const line of lines) {
    if (/^[\t ]/u.test(line)) {
      if (!dropping) kept.push(line);
      continue;
    }
    dropping = /^x-veritrust-/iu.test(line);
    if (!dropping) kept.push(line);
  }
  return Buffer.concat([
    Buffer.from(`${kept.join('\r\n')}\r\n\r\n`, 'latin1'),
    body,
  ]);
}

function addReceivedHeader(raw, envelope) {
  const helo = safeToken(envelope.helo, 'unknown');
  const clientIp = normalizeIp(envelope.clientIp);
  const receiverId = safeToken(envelope.receiverId, 'veritrust-gateway');
  const eventId = safeToken(envelope.eventId, 'unknown');
  const date = new Date(envelope.receivedAt || Date.now()).toUTCString();
  const header = `Received: from ${helo} (${helo} [${clientIp}]) by ${receiverId} with ESMTP id ${eventId}; ${date}\r\n`;
  return Buffer.concat([Buffer.from(header, 'ascii'), Buffer.isBuffer(raw) ? raw : Buffer.from(raw || '')]);
}

function addDecisionHeaders(raw, response) {
  const decision = response?.gateway_decision || {};
  const risk = Number.isFinite(Number(decision.risk)) ? Number(decision.risk).toFixed(6) : 'unknown';
  const headers = [
    `X-VeriTrust-Scan-Id: ${safeToken(response?.scan_id, 'unknown')}`,
    `X-VeriTrust-Decision: ${safeToken(decision.recommendation, 'unknown')}`,
    `X-VeriTrust-Risk: ${risk}`,
    `X-VeriTrust-Severity: ${safeToken(decision.severity, 'unknown')}`,
  ];
  return Buffer.concat([Buffer.from(`${headers.join('\r\n')}\r\n`, 'ascii'), Buffer.isBuffer(raw) ? raw : Buffer.from(raw || '')]);
}

function normalizeForSmtpData(raw) {
  const input = Buffer.isBuffer(raw) ? raw : Buffer.from(raw || '');
  const bytes = [];
  let lineStart = true;
  for (let index = 0; index < input.length; index += 1) {
    const value = input[index];
    if (lineStart && value === 0x2e) bytes.push(0x2e);
    if (value === 0x0a) {
      if (index === 0 || input[index - 1] !== 0x0d) bytes.push(0x0d);
      bytes.push(0x0a);
      lineStart = true;
    } else {
      bytes.push(value);
      lineStart = false;
    }
  }
  if (bytes.length < 2 || bytes[bytes.length - 2] !== 0x0d || bytes[bytes.length - 1] !== 0x0a) {
    bytes.push(0x0d, 0x0a);
  }
  return Buffer.from(bytes);
}

module.exports = {
  addDecisionHeaders,
  addReceivedHeader,
  normalizeForSmtpData,
  normalizeIp,
  safeToken,
  stripSpoofableVeriTrustHeaders,
};
