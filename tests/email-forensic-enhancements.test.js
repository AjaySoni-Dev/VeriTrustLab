const assert = require('node:assert/strict');
const test = require('node:test');
const { analyzeAttachmentMetadata } = require('../lib/email/attachment-intelligence');
const { extractInfrastructure, summarizeInfrastructure } = require('../lib/email/infrastructure');

test('attachment intelligence flags risky metadata without executing content', () => {
  const result = analyzeAttachmentMetadata({
    filename: 'invoice.pdf.exe',
    declared_mime_type: 'application/octet-stream',
  });
  assert.equal(result.state, 'METADATA_ONLY');
  assert.equal(result.executable_content_processed, false);
  assert.equal(result.highest_severity, 'HIGH');
  assert.ok(result.flags.some((item) => item.code === 'DOUBLE_EXTENSION'));
  assert.ok(result.flags.some((item) => item.code === 'EXECUTABLE_OR_SCRIPT_EXTENSION'));
});

test('raw EML infrastructure never manufactures a reliable sender-origin node', () => {
  const extracted = extractInfrastructure([
    { key: 'received', line: 'from relay.example (relay.example [8.8.8.8]) by receiver.example with ESMTP' },
  ]);
  const summary = summarizeInfrastructure(extracted.hops, { trustedReceiver: false });
  assert.equal(summary.state, 'OBSERVED_UNVERIFIED');
  assert.equal(summary.earliest_reliable_public_node, null);
  assert.equal(summary.person_location_claim, false);
});

test('trusted receiver mode only promotes the receiver-observed public boundary', () => {
  const extracted = extractInfrastructure([
    { key: 'received', line: 'from sender.example (sender.example [8.8.8.8]) by trusted.example with ESMTP' },
    { key: 'received', line: 'from claimed.example (claimed.example [1.1.1.1]) by sender.example with ESMTP' },
  ], { trustedReceiver: true });
  const summary = summarizeInfrastructure(extracted.hops, { trustedReceiver: true });
  assert.equal(summary.state, 'TRUSTED_BOUNDARY_OBSERVED');
  assert.equal(summary.earliest_reliable_public_node.ip_address, '8.8.8.8');
  assert.equal(summary.earliest_reliable_public_node.trust_level, 'trusted_receiver');
  assert.equal(summary.person_location_claim, false);
});
