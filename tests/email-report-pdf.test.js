const test = require('node:test');
const assert = require('node:assert/strict');
const { buildEmailReportPdf } = require('../assets/js/core/email-report-pdf');

function payload() {
  const children = Array.from({ length: 20 }, (_, index) => ({
    artifact_id: `url-${index}`,
    type: 'url',
    state: 'completed',
    score: index === 0 ? 0.82 : 0.15,
    verdict: index === 0 ? 'suspicious' : 'safe',
    metadata: { hostname: `example${index}.com`, path: `/path/${index}`, scheme: 'https' },
    reason_codes: index === 0 ? ['URL_BRAND_IMPERSONATION'] : [],
  }));
  return {
    scan_id: 'scan-test-1234567890', status: 'completed',
    gateway_decision: { risk: 0.62, severity: 'medium', verdict: 'medium', recommendation: 'manual_review', reason_codes: ['DETERMINISTIC_EMAIL_RISK'] },
    evidence: {
      input_mode: 'raw_eml', state: 'UNCERTAIN', started_at: '2026-09-15T05:00:00Z', completed_at: '2026-09-15T05:00:08Z',
      evidence_completeness: { level: 'STRONG', checked_dimensions: 7, total_dimensions: 8, wording: 'Evidence coverage is separate from risk.', next_actions: [{ action: 'USE_TRUSTED_RECEIVER' }], link_analysis: { extracted: 20, completed: 20, failed: 0, timed_out: 0, pending: 0, all_completed: true } },
      evidence_manifest: { schema_version: 'test', pipeline_version: 'test', parser_version: 'test', raw_sha256: 'a'.repeat(64) },
      observations: Array.from({ length: 20 }, (_, index) => ({ code: `TEST_SIGNAL_${index}` })),
      relationships: Array.from({ length: 12 }, (_, index) => ({ reason_code: `RELATIONSHIP_DIFFERS_${index}`, source_type: 'from', target_type: 'domain', target_value: `target${index}.example` })),
      children,
      infrastructure_summary: { state: 'OBSERVED_UNVERIFIED', wording: 'Observed infrastructure only; sender origin is unverified.' },
      infrastructure: Array.from({ length: 8 }, (_, index) => ({ hop_index: index, ip_classification: 'public', ip_address: `8.8.8.${index + 1}`, host: `mx${index}.example`, country: 'US', latitude: 20 + index, longitude: -30 - index, trust_level: 'observed_relay' })),
      threat_intelligence: { domain_intelligence: Array.from({ length: 10 }, (_, index) => ({ domain: `d${index}.example`, age_days: index + 1 })), ip_reputation: [], provider_notice: 'Context only.' },
      campaign_memory: { state: 'CORRELATED', campaign_id: 'campaign-1', related_scan_count: 3, common_entities: Array.from({ length: 10 }, (_, index) => ({ entity_type: 'url_domain', entity_value: `d${index}.example`, weight: 7 })) },
      model_evidence: [{ state: 'UNCERTAIN', p_phish: 0.48, status: 'completed' }],
      evidence_passport: { passport_id: 'p'.repeat(64), signature_algorithm: 'Ed25519', key_id: 'k'.repeat(64), evidence_sha256: 'e'.repeat(64) },
      limitations: Array.from({ length: 15 }, (_, index) => `LIMIT_${index}`),
    },
  };
}

test('email PDF stays concise and omits full response appendix', () => {
  const bytes = buildEmailReportPdf(payload());
  const text = Buffer.from(bytes).toString('latin1');
  assert.ok(text.startsWith('%PDF-1.4'));
  const countMatch = text.match(/\/Type \/Pages \/Count (\d+)/u);
  assert.ok(countMatch, 'page count should be present');
  const pages = Number(countMatch[1]);
  assert.ok(pages <= 10, `expected <=10 pages, got ${pages}`);
  assert.equal(text.includes('Complete response data'), false);
  assert.equal(text.includes('Glossary: terms and meanings'), false);
});
