const test = require('node:test');
const assert = require('node:assert/strict');
const { enrichInfrastructure, extractInfrastructure, receivedSourceSegment, sourceCandidateIps } = require('../lib/email/infrastructure');

test('Received parsing selects source-side from IP instead of receiver by IP', () => {
  const line = 'Received: from sender.example (sender.example [8.8.8.8]) by receiver.example (receiver.example [1.1.1.1]) with ESMTPS id abc; Tue, 15 Sep 2026 10:00:00 +0000';
  assert.match(receivedSourceSegment(line), /8\.8\.8\.8/);
  assert.deepEqual(sourceCandidateIps(line), ['8.8.8.8']);
  const result = extractInfrastructure([{ key: 'received', line }]);
  assert.equal(result.hops[0].ip_address, '8.8.8.8');
  assert.deepEqual(result.hops[0].provenance.all_candidate_ips, ['8.8.8.8', '1.1.1.1']);
});

test('Received parsing does not substitute receiver IP when source segment has no IP', () => {
  const line = 'Received: from sender.example by receiver.example (receiver.example [1.1.1.1]) with ESMTPS id abc; Tue, 15 Sep 2026 10:00:00 +0000';
  const result = extractInfrastructure([{ key: 'received', line }]);
  assert.equal(result.hops[0].ip_address, null);
  assert.equal(result.hops[0].ip_classification, 'unknown');
});

test('trusted receiver marks only directly observed first source hop as trusted', () => {
  const rows = [
    { key: 'received', line: 'Received: from client.example (client.example [8.8.8.8]) by receiver.local with ESMTP; Tue, 15 Sep 2026 10:00:00 +0000' },
    { key: 'received', line: 'Received: from upstream.example (upstream.example [9.9.9.9]) by client.example with ESMTP; Tue, 15 Sep 2026 09:59:00 +0000' },
  ];
  const result = extractInfrastructure(rows, { trustedReceiver: true });
  assert.equal(result.hops[0].trust_level, 'trusted_receiver');
  assert.equal(result.hops[1].trust_level, 'observed_relay');
});


test('infrastructure enrichment uses per-IP provider results instead of fixed coordinates', async () => {
  const parsed = extractInfrastructure([
    { key: 'received', line: 'Received: from first.example (first.example [8.8.8.8]) by receiver.example with ESMTP; Tue, 15 Sep 2026 10:00:00 +0000' },
    { key: 'received', line: 'Received: from second.example (second.example [9.9.9.9]) by first.example with ESMTP; Tue, 15 Sep 2026 09:59:00 +0000' },
  ]);
  const provider = {
    name: 'test-provider',
    async lookup(ip) {
      if (ip === '8.8.8.8') return { country: 'US', city: 'Mountain View', latitude: 37.4, longitude: -122.1, quality: 'test' };
      if (ip === '9.9.9.9') return { country: 'CH', city: 'Zurich', latitude: 47.4, longitude: 8.5, quality: 'test' };
      throw new Error('unexpected IP');
    },
  };
  const result = await enrichInfrastructure(parsed.hops, provider);
  assert.equal(result.state, 'COMPLETED');
  assert.deepEqual(result.hops.map((hop) => [hop.ip_address, hop.latitude, hop.longitude]), [
    ['8.8.8.8', 37.4, -122.1],
    ['9.9.9.9', 47.4, 8.5],
  ]);
});
