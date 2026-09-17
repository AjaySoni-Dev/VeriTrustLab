const crypto = require('crypto');
const dns = require('dns');
const { authenticate, arc, dkimVerify, dmarc } = require('mailauth');
const { EMAIL_AUTH_VERSION } = require('./contracts');

const RESULT_MAP = Object.freeze({
  pass: 'PASS',
  fail: 'FAIL',
  softfail: 'SOFTFAIL',
  neutral: 'NEUTRAL',
  none: 'NONE',
  temperror: 'TEMPERROR',
  permerror: 'PERMERROR',
  unknown: 'UNKNOWN',
  unavailable: 'UNAVAILABLE',
});

function resultState(value) {
  return RESULT_MAP[String(value || '').toLowerCase()] || 'UNKNOWN';
}

function observation(protocol, result, value = {}) {
  return {
    protocol,
    result: resultState(result),
    identity: value.identity || null,
    domain: value.domain || null,
    selector: value.selector || null,
    algorithm: value.algorithm || null,
    source_type: value.source_type || 'local_validation',
    provenance: value.provenance || {},
    dns_observed_at: value.dns_observed_at || null,
    dns_response_hash: value.dns_response_hash || null,
    failure_reason: value.failure_reason || null,
    quality: value.quality || 'unknown',
    producer_version: EMAIL_AUTH_VERSION,
  };
}

function tracedResolver(trace, implementation = dns.promises.resolve.bind(dns.promises)) {
  return async (name, rrtype) => {
    const observedAt = new Date().toISOString();
    try {
      const answer = await implementation(name, rrtype);
      trace.push({
        name: String(name).toLowerCase(),
        rrtype: String(rrtype || '').toUpperCase(),
        observed_at: observedAt,
        answer_hash: crypto.createHash('sha256').update(JSON.stringify(answer)).digest('hex'),
        state: 'completed',
      });
      return answer;
    } catch (error) {
      trace.push({ name: String(name).toLowerCase(), rrtype: String(rrtype || '').toUpperCase(), observed_at: observedAt, state: 'failed', error_code: String(error.code || 'DNS_ERROR') });
      throw error;
    }
  };
}

function traceDigest(trace) {
  return trace.length ? crypto.createHash('sha256').update(JSON.stringify(trace)).digest('hex') : null;
}

function authenticationResultsObservations(headerLines, options = {}) {
  const allowlist = new Set((options.trustedAuthservIds || []).map((value) => String(value).trim().toLowerCase()).filter(Boolean));
  return (headerLines || [])
    .filter((row) => String(row.key || '').toLowerCase() === 'authentication-results')
    .map((row) => {
      const line = String(row.line || '');
      const authservId = line.replace(/^authentication-results\s*:/iu, '').trim().split(/[;\s]/u)[0].toLowerCase();
      const trusted = Boolean(options.trustedReceiver && authservId && authservId === String(options.authservId || '').toLowerCase() && allowlist.has(authservId));
      return observation('AUTHENTICATION_RESULTS', 'UNKNOWN', {
        identity: authservId || null,
        source_type: trusted ? 'trusted_receiver_header' : 'copied_header',
        quality: trusted ? 'trusted' : 'reported_untrusted',
        provenance: {
          trusted_boundary: trusted,
          header_hash: crypto.createHash('sha256').update(line).digest('hex'),
          raw_value_persisted: false,
        },
        failure_reason: trusted ? null : 'AUTH_RESULTS_TRUST_BOUNDARY_NOT_ESTABLISHED',
      });
    });
}

function dkimObservations(result, trace) {
  const digest = traceDigest(trace);
  const observedAt = trace[0]?.observed_at || new Date().toISOString();
  return (result?.results || []).map((item) => observation('DKIM', item.status?.result, {
    identity: item.identity || item.status?.header?.i || null,
    domain: item.signingDomain || item.status?.header?.d || null,
    selector: item.selector || item.status?.header?.s || null,
    algorithm: item.algo || item.algorithm || item.status?.header?.a || null,
    source_type: 'local_raw_bytes_validation',
    provenance: {
      raw_bytes_preserved: true,
      body_hash_result: item.status?.bodyHash || item.status?.body_hash || null,
      under_sized_key: Boolean(item.status?.underSized),
      dns_queries: trace,
    },
    dns_observed_at: observedAt,
    dns_response_hash: digest,
    failure_reason: item.status?.comment || null,
    quality: item.status?.result === 'pass' ? 'verified' : (item.status?.result === 'none' ? 'unavailable' : 'failed'),
  }));
}

function arcObservation(result, trace) {
  return observation('ARC', result?.status?.result, {
    source_type: 'local_raw_bytes_validation',
    quality: result?.status?.result === 'pass' ? 'verified' : (result?.status?.result === 'none' ? 'unavailable' : 'failed'),
    failure_reason: result?.status?.comment || null,
    dns_observed_at: trace[0]?.observed_at || null,
    dns_response_hash: traceDigest(trace),
    provenance: {
      chain_instance: result?.i ?? null,
      actor_trust_evaluated: false,
      content_safety_evaluated: false,
      dns_queries: trace,
    },
  });
}

function dmarcObservation(result, trace) {
  return observation('DMARC', result?.status?.result || 'none', {
    domain: result?.status?.header?.from || result?.domain || null,
    source_type: 'local_alignment_validation',
    quality: result?.status?.result === 'pass' ? 'verified' : (result ? 'failed' : 'unavailable'),
    failure_reason: result?.status?.comment || null,
    dns_observed_at: trace[0]?.observed_at || null,
    dns_response_hash: traceDigest(trace),
    provenance: {
      aligned_dkim: result?.alignment?.dkim || null,
      aligned_spf: result?.alignment?.spf || null,
      safety_assertion: false,
      dns_queries: trace,
    },
  });
}

async function withTimeout(promise, timeoutMs) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(Object.assign(new Error('Authentication evaluation timed out.'), { code: 'AUTH_TIMEOUT' })), timeoutMs);
        timer.unref?.();
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function evaluateRawAuthentication(raw, headerLines, options = {}) {
  const trusted = options.mode === 'trusted_receiver_event';
  const trace = [];
  const resolver = tracedResolver(trace, options.resolver);
  const observations = authenticationResultsObservations(headerLines, {
    trustedReceiver: trusted && Boolean(options.trustAuthenticationResultsHeaders),
    authservId: options.authservId,
    trustedAuthservIds: options.trustedAuthservIds,
  });
  try {
    if (trusted) {
      const result = await withTimeout(authenticate(raw, {
        ip: options.clientIp,
        helo: options.helo,
        sender: options.mailFrom,
        mta: options.receiverId,
        trustReceived: false,
        disableBimi: true,
        resolver,
      }), options.timeoutMs || 4500);
      observations.push(...dkimObservations(result.dkim, trace));
      observations.push(observation('SPF', result.spf?.status?.result, {
        identity: result.spf?.status?.smtp?.mailfrom || options.mailFrom,
        domain: result.spf?.domain || String(options.mailFrom || '').split('@').pop(),
        source_type: 'trusted_receiver_evaluation',
        quality: result.spf?.status?.result === 'pass' ? 'verified' : 'failed',
        failure_reason: result.spf?.status?.comment || null,
        dns_observed_at: trace[0]?.observed_at || null,
        dns_response_hash: traceDigest(trace),
        provenance: { client_ip: options.clientIp, helo: options.helo, receiver_id: options.receiverId, evaluation_time: new Date().toISOString(), dns_queries: trace },
      }));
      observations.push(arcObservation(result.arc, trace));
      observations.push(dmarcObservation(result.dmarc, trace));
    } else {
      observations.push(observation('SPF', 'UNAVAILABLE', {
        source_type: 'capability_contract',
        quality: 'unavailable',
        failure_reason: 'TRUSTED_SMTP_FACTS_UNAVAILABLE',
        provenance: { raw_eml_is_insufficient_for_historical_spf: true },
      }));
      const dkimResult = await withTimeout(dkimVerify(raw, { resolver }), options.timeoutMs || 4500);
      observations.push(...dkimObservations(dkimResult, trace));
      const arcResult = await arc(dkimResult.arc, { resolver });
      observations.push(arcObservation(arcResult, trace));
      let dmarcResult = false;
      if (dkimResult.headerFrom) {
        dmarcResult = await dmarc({
          headerFrom: dkimResult.headerFrom,
          spfDomains: [],
          dkimDomains: (dkimResult.results || []).filter((row) => row.status?.result === 'pass').map((row) => ({ id: row.id, domain: row.signingDomain, aligned: row.status?.aligned, underSized: row.status?.underSized })),
          arcResult,
          resolver,
        });
      }
      observations.push(dmarcObservation(dmarcResult, trace));
    }
    return { observations, limitations: trusted ? [] : ['SPF_UNAVAILABLE_WITHOUT_TRUSTED_RECEIVER_FACTS'], dnsTrace: trace };
  } catch (error) {
    observations.push(observation('DKIM', error.code === 'AUTH_TIMEOUT' ? 'TEMPERROR' : 'UNKNOWN', {
      source_type: 'local_raw_bytes_validation',
      quality: 'failed',
      failure_reason: String(error.code || 'AUTH_EVALUATION_FAILED'),
      dns_observed_at: trace[0]?.observed_at || null,
      dns_response_hash: traceDigest(trace),
      provenance: { dns_queries: trace },
    }));
    return { observations, limitations: [error.code === 'AUTH_TIMEOUT' ? 'AUTHENTICATION_TIMEOUT' : 'AUTHENTICATION_EVALUATION_FAILED'], dnsTrace: trace };
  }
}

module.exports = {
  authenticationResultsObservations,
  evaluateRawAuthentication,
  resultState,
  tracedResolver,
};
