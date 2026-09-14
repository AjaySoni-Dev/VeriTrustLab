const crypto = require('crypto');
const { getOptionalEnv, serverConfig } = require('../config');
const { contentHmac, safeUrlMetadata } = require('../gateway/extractor');
const { correlate } = require('../gateway/correlation');
const { compilePolicy } = require('../gateway/policy');
const { mapWithConcurrency, modelTimeoutMs } = require('../gateway/execution');
const {
  claimScan,
  completeArtifacts,
  createArtifacts,
  enqueueJob,
  failScan,
  getPolicyVersion,
  prepareModelRun,
  publishDecision,
  recordEvidence,
  resolveIntegration,
  scanReport,
  storeIdempotentResponse,
  submitScan,
} = require('../gateway/persistence');
const { uploadObject } = require('../gateway/storage');
const { invokeDetectionModule, invokeDetectionModuleQueue } = require('../module-communication');
const { evaluateRawAuthentication } = require('./auth');
const {
  CAPABILITIES,
  EMAIL_AUTH_VERSION,
  EMAIL_EVIDENCE_SCHEMA,
  EMAIL_IDENTITY_VERSION,
  EMAIL_INFRASTRUCTURE_VERSION,
  EMAIL_THREAT_INTEL_VERSION,
  EMAIL_CAMPAIGN_VERSION,
  EMAIL_PASSPORT_VERSION,
  EMAIL_PARSER_VERSION,
  EMAIL_PIPELINE_VERSION,
} = require('./contracts');
const { deterministicObservations, extractUrls, sha256 } = require('./content');
const { analyzeAttachmentMetadata } = require('./attachment-intelligence');
const { buildIdentityGraph } = require('./identity');
const { enrichInfrastructure, extractInfrastructure, summarizeInfrastructure } = require('./infrastructure');
const { getInfrastructureGeoProvider } = require('./geo-provider');
const { collectDomains, enrichThreatIntelligence } = require('./threat-intelligence');
const { buildThreatEntities, campaignFromMatches } = require('./campaign-memory');
const { createEvidencePassport } = require('./evidence-passport');
const { parseEml } = require('./parser');
const {
  createChildArtifacts,
  emailRecordsForScan,
  matchingThreatEntities,
  persistAuthObservations,
  persistEvidencePassport,
  persistEmailDetails,
  persistIdentityEdges,
  persistInfrastructure,
  persistThreatEntities,
  updateEmailArtifactStorage,
} = require('./persistence');

function now() { return new Date().toISOString(); }

function normalizeEmailObservation(item, observedAt = now()) {
  return {
    ...item,
    code: item.code || item.protocol || 'EMAIL_OBSERVATION',
    source: item.source || item.source_type || 'email_pipeline',
    producer_version: item.producer_version || EMAIL_PIPELINE_VERSION,
    observed_at: item.observed_at || item.dns_observed_at || observedAt,
    quality: item.quality || 'unknown',
    provenance: item.provenance || {},
    failure_reason: item.failure_reason || null,
  };
}

function requestHash(mode, digest, metadata = {}) {
  return crypto.createHash('sha256').update(JSON.stringify({ mode, digest, metadata, pipeline: EMAIL_PIPELINE_VERSION })).digest('hex');
}

function unavailableAuthObservations() {
  return ['SPF', 'DKIM', 'DMARC', 'ARC'].map((protocol) => ({
    protocol,
    result: 'UNAVAILABLE',
    identity: null,
    domain: null,
    selector: null,
    algorithm: null,
    source_type: 'capability_contract',
    provenance: { input_mode: 'plain_text', protocol_claimed: false },
    dns_observed_at: null,
    dns_response_hash: null,
    failure_reason: 'INPUT_MODE_LACKS_HEADER_OR_SMTP_EVIDENCE',
    quality: 'unavailable',
    producer_version: EMAIL_AUTH_VERSION,
  }));
}

function plainTextParsed(input) {
  const text = [input.subject ? `Subject: ${input.subject}` : '', input.body].filter(Boolean).join('\n\n');
  const digest = sha256(text);
  return {
    rawSha256: digest,
    rawBytes: Buffer.byteLength(text, 'utf8'),
    parserVersion: 'plain-text-contract-1',
    parseState: 'COMPLETED',
    headerBytes: 0,
    decodedBytes: Buffer.byteLength(text, 'utf8'),
    mimePartCount: 0,
    mimeDepthEstimate: 0,
    attachments: [],
    headers: new Map(),
    headerLines: [],
    addresses: { from: [], replyTo: [], returnPath: [], sender: [] },
    subject: input.subject,
    messageId: null,
    date: null,
    text,
    html: '',
    bodyTextHash: sha256(text),
    bodyHtmlHash: null,
    subjectHash: sha256(input.subject),
    limitations: ['PLAIN_TEXT_NO_HEADER_AUTH_OR_MIME_EVIDENCE'],
    malformed: [],
  };
}

function failedModelEvidence(kind, modelKey, artifactId, error, required = true) {
  const unavailableCode = kind === 'link' ? 'LINK_MODEL_UNAVAILABLE' : (kind === 'parser' ? 'EMAIL_PARSER_FAILED' : 'PHISHING_MODEL_UNAVAILABLE');
  const errorCode = String(error?.code || 'MODEL_RUNTIME_ERROR');
  return {
    artifactId,
    kind,
    modelKey,
    status: /TIMEOUT/u.test(errorCode) ? 'timed_out' : 'failed',
    score: null,
    verdict: 'unknown',
    confidence: 'unknown',
    confidenceValue: null,
    indicators: [],
    reasonCodes: [unavailableCode, errorCode],
    degraded: true,
    required,
    errorCode,
    rawResponseRedacted: { error_code: errorCode },
  };
}

async function runPreparedAdapter(orgId, scanId, artifact, modelKey, moduleKey, policy, required = true) {
  let prepared;
  try {
    prepared = await prepareModelRun(orgId, scanId, artifact, modelKey);
  } catch (error) {
    return failedModelEvidence(modelKey === 'mailguard' ? 'phishing' : 'link', modelKey, artifact.id, error, required);
  }
  const invocation = await invokeDetectionModule(moduleKey, artifact, {
    modelKey,
    required,
    timeoutMs: modelTimeoutMs(policy, prepared, serverConfig.gatewaySynchronousBudgetMs),
    allowProviderFallback: false,
    modelContract: prepared.configuration,
    correlationId: `${scanId}:${artifact.id}:${modelKey}`,
  });
  const result = invocation.result;
  return recordEvidence(orgId, scanId, artifact, result.evidence, prepared);
}

async function runPreparedLinkBatch(orgId, scanId, artifacts, policy) {
  if (!artifacts.length) return [];
  const slots = await mapWithConcurrency(artifacts, 8, async (artifact) => {
    try {
      return { artifact, prepared: await prepareModelRun(orgId, scanId, artifact, 'swift') };
    } catch (error) {
      return { artifact, error };
    }
  });
  const evidenceByArtifact = new Map(slots.filter((slot) => slot.error).map((slot) => [
    slot.artifact.id,
    failedModelEvidence('link', 'swift', slot.artifact.id, slot.error, true),
  ]));
  const runnable = slots.filter((slot) => slot.prepared);
  if (runnable.length) {
    const timeoutMs = Math.min(...runnable.map((slot) => modelTimeoutMs(
      policy,
      slot.prepared,
      serverConfig.gatewaySynchronousBudgetMs,
    )));
    const invocations = await invokeDetectionModuleQueue('link', runnable.map((slot) => slot.artifact), {
      modelKey: 'swift',
      required: true,
      timeoutMs,
      concurrency: serverConfig.gatewayModelConcurrency,
      allowProviderFallback: false,
      modelContract: runnable[0].prepared.configuration,
      correlationId: `${scanId}:mailgraph:swift`,
    });
    const results = invocations.map((invocation) => invocation.result);
    await mapWithConcurrency(results, 8, async (result, index) => {
      const slot = runnable[index];
      const evidence = await recordEvidence(orgId, scanId, slot.artifact, result.evidence, slot.prepared);
      evidenceByArtifact.set(slot.artifact.id, evidence);
    });
  }
  return artifacts.map((artifact) => evidenceByArtifact.get(artifact.id));
}

function gatewayObservationEvidence(authObservations, edges, contentObservations, artifactId) {
  const reasonCodes = [];
  for (const item of authObservations) {
    if (['FAIL', 'TEMPERROR', 'PERMERROR'].includes(item.result)) reasonCodes.push(`${item.protocol}_${item.result}`);
  }
  reasonCodes.push(...edges.map((edge) => edge.reason_code).filter(Boolean));
  reasonCodes.push(...contentObservations.map((item) => item.code));
  return {
    artifactId,
    kind: 'email_forensics',
    modelKey: 'email.forensics',
    status: 'completed',
    score: null,
    verdict: 'unknown',
    confidence: 'unknown',
    reasonCodes: [...new Set(reasonCodes)],
    required: false,
  };
}

function specialistState(parseState, modelEvidence) {
  if (parseState === 'UNSUPPORTED_LIMIT') return 'UNSUPPORTED';
  if (['FAILED', 'FAILED_TIMEOUT', 'MALFORMED_LIMIT'].includes(parseState)) return 'FAILED';
  if (modelEvidence?.status === 'completed') {
    const state = modelEvidence.rawResponseRedacted?.state;
    if (['LIKELY_BENIGN', 'LIKELY_PHISHING', 'UNCERTAIN'].includes(state)) return state;
  }
  return 'UNCERTAIN';
}

function infrastructureStateFromHops(hops) {
  const publicHops = (Array.isArray(hops) ? hops : []).filter((hop) => hop.ip_classification === 'public');
  if (!publicHops.length) return 'UNAVAILABLE';
  const enriched = publicHops.filter((hop) => hop.geo_provider && (hop.country || hop.asn || hop.asn_org)).length;
  if (enriched === publicHops.length) return 'COMPLETED';
  if (enriched > 0) return 'PARTIAL';
  return 'UNAVAILABLE';
}

function evidenceCompleteness(input) {
  const children = Array.isArray(input.children) ? input.children : [];
  const urlChildren = children.filter((child) => (child.artifact_type || child.type) === 'url');
  const urlStates = urlChildren.map((child) => input.childEvidence?.get?.(child.id)?.status || 'unavailable');
  const modelCompleted = input.modelEvidence?.status === 'completed';
  const authObservations = (input.observations || []).filter((item) => ['SPF', 'DKIM', 'DMARC', 'ARC'].includes(String(item.protocol || item.code || '').toUpperCase()));
  const authAvailable = authObservations.some((item) => !['UNAVAILABLE', 'FAILED'].includes(String(item.result || '').toUpperCase()));
  const identitySupported = input.mode !== 'plain_text';
  const infrastructureState = input.infrastructureState || infrastructureStateFromHops(input.infrastructure);

  const threatIntelState = String(input.threatIntelligence?.state || 'UNAVAILABLE').toUpperCase();
  const dimensions = {
    content: modelCompleted ? 'CHECKED' : 'LIMITED',
    ai_model: modelCompleted ? 'CHECKED' : 'LIMITED',
    authentication: input.mode === 'plain_text' ? 'UNAVAILABLE' : (authAvailable ? 'CHECKED' : 'LIMITED'),
    identity: input.mode === 'plain_text' ? 'UNAVAILABLE' : (identitySupported ? 'CHECKED' : 'LIMITED'),
    links: !urlChildren.length ? 'CHECKED' : (urlStates.every((state) => state === 'completed') ? 'CHECKED' : 'LIMITED'),
    attachments: input.mode === 'plain_text' ? 'UNAVAILABLE' : 'CHECKED',
    infrastructure: input.mode === 'plain_text' ? 'UNAVAILABLE' : (infrastructureState === 'COMPLETED' ? 'CHECKED' : 'LIMITED'),
    threat_intelligence: threatIntelState === 'COMPLETED' ? 'CHECKED' : (threatIntelState === 'PARTIAL' ? 'LIMITED' : 'UNAVAILABLE'),
  };
  const values = Object.values(dimensions);
  const checked = values.filter((value) => value === 'CHECKED').length;
  const limited = values.filter((value) => value === 'LIMITED').length;
  const unavailable = values.filter((value) => value === 'UNAVAILABLE').length;
  const level = checked >= 7 && unavailable <= 1 ? 'STRONG' : (checked >= 5 ? 'MODERATE' : 'LIMITED');
  const nextActions = [];
  if (input.mode === 'plain_text') {
    nextActions.push({
      action: 'UPLOAD_ORIGINAL_EML',
      label: 'Upload the original .eml to acquire sender, MIME, attachment and relay evidence',
      target_mode: 'raw_eml',
      unlocks: ['authentication', 'identity', 'attachments', 'infrastructure', 'domain_registration_intelligence'],
    });
  } else if (input.mode === 'raw_eml') {
    nextActions.push({
      action: 'USE_TRUSTED_RECEIVER',
      label: 'Analyze through the trusted SMTP receiver to acquire directly observed transport facts',
      target_mode: 'trusted_receiver_event',
      unlocks: ['spf', 'direct_client_ip', 'helo', 'mail_from', 'receiver_timestamp', 'trusted_origin_boundary'],
    });
  }
  return {
    level,
    checked_dimensions: checked,
    limited_dimensions: limited,
    unavailable_dimensions: unavailable,
    total_dimensions: values.length,
    dimensions,
    next_actions: nextActions,
    wording: 'Evidence completeness describes which forensic dimensions had usable evidence. It is separate from threat risk and is never proof that a message is safe.',
  };
}

function evidenceManifest(input) {
  const modelVersionIds = input.modelEvidence?.modelVersionId ? [input.modelEvidence.modelVersionId] : [];
  return {
    schema_version: EMAIL_EVIDENCE_SCHEMA,
    pipeline_version: EMAIL_PIPELINE_VERSION,
    parser_version: input.parserVersion || EMAIL_PARSER_VERSION,
    authentication_version: EMAIL_AUTH_VERSION,
    identity_version: EMAIL_IDENTITY_VERSION,
    infrastructure_version: EMAIL_INFRASTRUCTURE_VERSION,
    threat_intelligence_version: EMAIL_THREAT_INTEL_VERSION,
    campaign_memory_version: EMAIL_CAMPAIGN_VERSION,
    evidence_passport_version: EMAIL_PASSPORT_VERSION,
    input_mode: input.mode,
    raw_sha256: input.rawSha256 || null,
    model_version_ids: modelVersionIds,
    started_at: input.startedAt || null,
    completed_at: input.completedAt || null,
    provenance_notice: 'Versioned technical provenance supports reproducibility; it is not a legal certification or individual-attribution claim.',
  };
}

function evidenceBundle(input) {
  return {
    schema_version: EMAIL_EVIDENCE_SCHEMA,
    artifact_id: input.artifact.id,
    input_mode: input.mode,
    state: input.state,
    capabilities: CAPABILITIES[input.mode],
    evidence_completeness: evidenceCompleteness(input),
    evidence_manifest: evidenceManifest(input),
    infrastructure_summary: input.infrastructureSummary || summarizeInfrastructure(input.infrastructure, { trustedReceiver: input.mode === 'trusted_receiver_event' }),
    threat_intelligence: input.threatIntelligence || { state: 'UNAVAILABLE', domain_intelligence: [], ip_reputation: [], observations: [], limitations: ['THREAT_INTELLIGENCE_UNAVAILABLE'] },
    campaign_memory: input.campaignMemory || { state: 'UNAVAILABLE', campaign_id: null, related_scan_count: 0, related_scans: [], common_entities: [] },
    investigation_lineage: { parent_scan_id: input.parentScanId || null, current_scan_id: input.scanId || null, acquisition_stage: input.mode },
    observations: input.observations,
    authentication: input.authentication || [],
    model_evidence: input.modelEvidence ? [{
      model_version_id: input.modelEvidence.modelVersionId || null,
      state: input.modelEvidence.rawResponseRedacted?.state || (input.modelEvidence.status === 'failed' ? 'FAILED' : 'UNCERTAIN'),
      p_phish: input.modelEvidence.score,
      status: input.modelEvidence.status,
      reason_codes: input.modelEvidence.reasonCodes,
    }] : [],
    relationships: input.edges.map((edge) => ({
      type: edge.edge_type,
      source_type: edge.source_type,
      target_type: edge.target_type,
      target_value: edge.target_value,
      reason_code: edge.reason_code,
      quality: 'observed',
      producer_version: edge.producer_version,
    })),
    infrastructure: input.infrastructure.map((hop) => ({
      hop_index: hop.hop_index,
      host: hop.host,
      ip_address: hop.ip_address,
      ip_classification: hop.ip_classification,
      asn: hop.asn,
      asn_org: hop.asn_org,
      country: hop.country,
      region: hop.region,
      city: hop.city,
      latitude: hop.latitude,
      longitude: hop.longitude,
      geo_provider: hop.geo_provider,
      trust_level: hop.trust_level,
      wording: 'Sending Infrastructure - approximate infrastructure geolocation only',
    })),
    children: input.children.map((child) => ({
      artifact_id: child.id,
      parent_artifact_id: child.parent_artifact_id,
      type: child.artifact_type || child.type,
      ordinal: child.ordinal,
      state: input.childEvidence.get(child.id)?.status || (child.artifact_type === 'attachment' ? 'METADATA_ONLY' : 'PENDING'),
      reason_codes: input.childEvidence.get(child.id)?.reasonCodes || [],
      metadata: child.metadata,
    })),
    limitations: [...new Set(input.limitations)],
    started_at: input.startedAt,
    completed_at: input.completedAt,
  };
}

async function analyzeEmail(input) {
  const progress = input.onProgress || (() => {});
  progress('record', 'running', 'Resolving the email integration and reserving the scan.');
  const startedAt = now();
  const { auth, mode, idempotencyKey, requestId, traceId } = input;
  const integration = await resolveIntegration(auth, input.integrationId || null, 'gateway:scan');
  const parsedSeed = mode === 'plain_text' ? plainTextParsed(input.text) : null;
  const rawDigest = parsedSeed?.rawSha256 || crypto.createHash('sha256').update(input.raw).digest('hex');
  const submitted = await submitScan({
    orgId: auth.organization.id,
    integrationId: integration.id,
    idempotencyKey,
    requestHash: requestHash(mode, rawDigest, { channel: input.text?.channel || 'email', parent_scan_id: input.parentScanId || null }),
    apiKeyId: auth.apiKeyId,
    submittedBy: auth.user?.id || null,
    processingMode: mode === 'plain_text' ? 'synchronous' : 'hybrid',
    source: mode === 'trusted_receiver_event' ? 'trusted-receiver-v2' : 'phishing-v2',
    externalEventId: input.receiver?.event_id || input.receiver?.receiver_id || null,
    requestId,
    traceId,
    policyVersionId: null,
    deadlineAt: new Date(Date.now() + 120000).toISOString(),
    metadata: { input_mode: mode, evidence_schema: EMAIL_EVIDENCE_SCHEMA, pipeline_version: EMAIL_PIPELINE_VERSION, parent_scan_id: input.parentScanId || null },
  });
  if (submitted.replayed && submitted.response_body) return { status: Number(submitted.response_status || 200), body: submitted.response_body, replayed: true };
  const scanId = submitted.scan_id;
  const claimed = await claimScan(auth.organization.id, scanId);
  if (!claimed) return { status: 202, body: { ok: true, replayed: true, scan_id: scanId, status: 'processing' }, replayed: true };
  progress('record', 'completed', 'Email scan reserved.');

  try {
    const policy = compilePolicy((await getPolicyVersion(claimed.policy_version_id, auth.organization.id)).compiled_policy);
    const retentionHours = Math.max(1, Math.min(24, Number(policy.retention?.maximum_hours || 24)));
    const retentionUntil = mode === 'plain_text' ? null : new Date(Date.now() + retentionHours * 3600000).toISOString();
    const [artifact] = await createArtifacts(auth.organization.id, scanId, [{
      ordinal: 0,
      type: 'email',
      content: null,
      content_hmac: contentHmac(serverConfig.gatewayContentHmacKey, auth.organization.id, 'email', rawDigest),
      size_bytes: mode === 'plain_text' ? parsedSeed.rawBytes : input.raw.length,
      mime_type: mode === 'plain_text' ? 'text/plain' : 'message/rfc822',
      retention: mode === 'plain_text' ? 'metadata_only' : 'temporary_file',
      retention_until: retentionUntil,
      metadata: { input_mode: mode, raw_sha256: rawDigest, pipeline_version: EMAIL_PIPELINE_VERSION },
    }]);

    if (mode !== 'plain_text') {
      progress('storage', 'running', 'Storing the original email in private temporary storage.');
      // The deployed gateway_artifacts constraint requires org/scan prefixes. This
      // compatibility path is the inventory-safe form of the blueprint object key.
      const storagePath = `${auth.organization.id}/${scanId}/email/${artifact.id}/original.eml`;
      await uploadObject('gateway-uploads', storagePath, input.raw, 'message/rfc822', { upsert: false });
      await updateEmailArtifactStorage(auth.organization.id, scanId, artifact.id, {
        storage_bucket: 'gateway-uploads', storage_path: storagePath, status: 'processing',
      });
      artifact.storage_bucket = 'gateway-uploads';
      artifact.storage_path = storagePath;
      artifact.status = 'processing';
      await enqueueJob({
        orgId: auth.organization.id,
        scanId,
        artifactId: artifact.id,
        jobType: 'retention',
        dedupeKey: `retention:${artifact.id}`,
        payload: { artifact_id: artifact.id },
        availableAt: retentionUntil,
        maxAttempts: 8,
      });
      progress('storage', 'completed', 'Original email stored and retention cleanup scheduled.');
    }

    progress('parse', 'running', mode === 'plain_text' ? 'Reading the email text and extracting links.' : 'Parsing the original message, headers, and attachment metadata.');
    let parsed = parsedSeed;
    let parserFailure = null;
    if (!parsed) {
      try {
        parsed = await parseEml(input.raw);
      } catch (error) {
        parserFailure = error;
        parsed = {
          ...plainTextParsed({ subject: '', body: '' }),
          rawSha256: rawDigest,
          rawBytes: input.raw.length,
          parserVersion: 'mailparser-3.9.15+veritrust-1',
          parseState: ['UNSUPPORTED_LIMIT', 'MALFORMED_LIMIT', 'FAILED_TIMEOUT'].includes(error.code) ? error.code : 'FAILED',
          limitations: [String(error.code || 'PARSER_FAILED')],
        };
      }
    }

    progress('parse', parserFailure ? 'failed' : 'completed', parserFailure ? 'Email parsing was incomplete. The report will include this limitation.' : 'Message parsing finished.');
    const content = deterministicObservations(parsed.text, parsed.html);
    const extracted = extractUrls(parsed.text, parsed.html);
    progress('sender', mode === 'plain_text' ? 'skipped' : 'running', mode === 'plain_text' ? 'Sender authentication requires original email headers.' : 'Evaluating email authentication and sender alignment.');
    const authResult = mode === 'plain_text'
      ? { observations: unavailableAuthObservations(), limitations: ['AUTHENTICATION_UNAVAILABLE_FOR_PLAIN_TEXT'] }
      : await evaluateRawAuthentication(input.raw, parsed.headerLines, {
        mode,
        clientIp: input.receiver?.client_ip,
        helo: input.receiver?.helo,
        mailFrom: input.receiver?.mail_from,
        receiverId: input.receiver?.receiver_id,
        authservId: input.receiver?.authserv_id,
        trustedAuthservIds: getOptionalEnv('VERITRUST_TRUSTED_AUTHSERV_IDS', '').split(',').map((value) => value.trim()).filter(Boolean),
        trustAuthenticationResultsHeaders: Boolean(input.receiver?.trust_authentication_results_headers),
      });
    const identity = buildIdentityGraph(parsed, authResult.observations, extracted.urls);
    if (mode !== 'plain_text') progress('sender', 'completed', 'Sender checks finished. Unavailable checks are recorded in the report.');
    const infrastructureBase = mode === 'plain_text' ? { hops: [], limitations: ['INFRASTRUCTURE_UNAVAILABLE_FOR_PLAIN_TEXT'] } : extractInfrastructure(parsed.headerLines, { trustedReceiver: mode === 'trusted_receiver_event' });
    if (infrastructureBase.hops.length) progress('infrastructure', 'running', 'Looking up recorded public mail-server infrastructure.');
    const infrastructureResult = await enrichInfrastructure(infrastructureBase.hops, input.geoProvider || getInfrastructureGeoProvider());
    progress('infrastructure', infrastructureBase.hops.length ? 'completed' : 'skipped', infrastructureBase.hops.length ? 'Mail-server lookup finished.' : 'No eligible mail-server hops are available for lookup.');
    const infrastructure = infrastructureResult.hops;
    progress('threat-intel', 'running', 'Checking domain registration context and configured infrastructure reputation sources.');
    const threatIntelligence = await enrichThreatIntelligence({
      domains: collectDomains(identity, extracted.urls),
      infrastructure,
    }).catch((error) => ({
      state: 'UNAVAILABLE', domain_intelligence: [], ip_reputation: [], observations: [],
      limitations: [String(error?.code || 'THREAT_INTELLIGENCE_FAILED')],
      provider_notice: 'Threat-intelligence enrichment failed without changing the core forensic verdict.',
      producer_version: EMAIL_THREAT_INTEL_VERSION,
    }));
    progress('threat-intel', threatIntelligence.state === 'UNAVAILABLE' ? 'failed' : 'completed', threatIntelligence.state === 'UNAVAILABLE' ? 'Threat-intelligence enrichment was unavailable; the evidence gap is recorded.' : 'Domain and infrastructure intelligence enrichment finished.');
    for (const hop of infrastructure) {
      const targetValue = hop.host || hop.ip_address;
      if (!targetValue) continue;
      identity.edges.push({
        edge_type: 'sent_via',
        source_type: 'email_artifact',
        source_value: parsed.rawSha256,
        target_type: hop.host ? 'infrastructure_host' : 'infrastructure_ip',
        target_value: targetValue,
        evidence_source: 'received_header',
        confidence: hop.trust_level === 'trusted_receiver' ? 1 : null,
        reason_code: 'SENDING_INFRASTRUCTURE_OBSERVED',
        provenance: { hop_index: hop.hop_index, trust_level: hop.trust_level, ip_classification: hop.ip_classification },
        producer_version: EMAIL_IDENTITY_VERSION,
      });
    }
    const contentAndIdentityObservations = [...content, ...extracted.observations, ...identity.observations, ...(threatIntelligence.observations || [])].map((item) => normalizeEmailObservation(item));
    const allObservations = [...contentAndIdentityObservations, ...authResult.observations.map((item) => normalizeEmailObservation(item))];

    const childDefinitions = [];
    for (const record of extracted.urls) {
      childDefinitions.push({
        ordinal: childDefinitions.length + 1,
        type: 'url',
        content: record.url,
        content_hmac: contentHmac(serverConfig.gatewayContentHmacKey, auth.organization.id, 'url', record.url),
        size_bytes: Buffer.byteLength(record.url, 'utf8'),
        mime_type: 'text/uri-list',
        metadata: { ...safeUrlMetadata(record.url), sources: record.sources, visible_href_evidence: record.metadata },
      });
    }
    for (const attachment of parsed.attachments) {
      childDefinitions.push({
        ordinal: childDefinitions.length + 1,
        type: 'attachment',
        content: null,
        content_hmac: attachment.sha256 ? contentHmac(serverConfig.gatewayContentHmacKey, auth.organization.id, 'attachment', attachment.sha256) : null,
        size_bytes: attachment.decoded_size,
        mime_type: attachment.declared_mime_type,
        metadata: {
          original_filename_untrusted: attachment.filename,
          declared_mime_type: attachment.declared_mime_type,
          disposition: attachment.disposition,
          mime_part_index: attachment.part_index,
          sha256: attachment.sha256,
          forensic_metadata: analyzeAttachmentMetadata(attachment),
          media_authenticity: 'NOT_EVALUATED',
          executable_content_processed: false,
        },
      });
    }
    const childRows = await createChildArtifacts(auth.organization.id, scanId, artifact.id, childDefinitions);
    const childByOrdinal = new Map(childDefinitions.map((item) => [item.ordinal, item]));
    const hydratedChildren = childRows.map((row) => ({ ...row, type: row.artifact_type, content: childByOrdinal.get(Number(row.ordinal))?.content || null }));

    progress('campaign', 'running', 'Comparing durable forensic entities with prior investigations in this workspace.');
    const threatEntities = buildThreatEntities({ parsed, identity, authObservations: authResult.observations, extractedUrls: extracted.urls, attachments: parsed.attachments, infrastructure });
    let campaignMemory;
    let campaignSchemaLimitation = null;
    try {
      const matches = await matchingThreatEntities(auth.organization.id, scanId, threatEntities);
      campaignSchemaLimitation = matches.available ? null : matches.limitation;
      campaignMemory = matches.available
        ? campaignFromMatches(scanId, threatEntities, matches.rows)
        : { state: 'UNAVAILABLE', campaign_id: null, related_scan_count: 0, related_scans: [], common_entities: [], limitation: matches.limitation, producer_version: EMAIL_CAMPAIGN_VERSION };
      const persistedEntities = await persistThreatEntities(auth.organization.id, scanId, artifact.id, threatEntities);
      if (!persistedEntities.available) campaignSchemaLimitation = persistedEntities.limitation;
    } catch (error) {
      campaignMemory = { state: 'UNAVAILABLE', campaign_id: null, related_scan_count: 0, related_scans: [], common_entities: [], limitation: String(error?.code || 'CAMPAIGN_MEMORY_FAILED'), producer_version: EMAIL_CAMPAIGN_VERSION };
      campaignSchemaLimitation = 'CAMPAIGN_MEMORY_FAILED';
    }
    progress('campaign', campaignMemory.state === 'UNAVAILABLE' ? 'failed' : 'completed', campaignMemory.state === 'CORRELATED' ? `Campaign Memory linked ${campaignMemory.related_scan_count} prior investigation(s).` : (campaignMemory.state === 'UNAVAILABLE' ? 'Campaign Memory is unavailable; the scan remains valid and records the limitation.' : 'No strong prior campaign match was found.'));

    await Promise.all([
      persistEmailDetails(auth.organization.id, scanId, artifact.id, parsed, identity, extracted.urls.length, {
        content_observations: contentAndIdentityObservations,
        attachment_metadata_only: true,
        media_authenticity_analyzed: false,
        threat_intelligence: threatIntelligence,
        campaign_memory: campaignMemory,
        investigation_lineage: { parent_scan_id: input.parentScanId || null, current_scan_id: scanId, acquisition_stage: mode },
      }),
      persistAuthObservations(auth.organization.id, scanId, artifact.id, authResult.observations),
      persistIdentityEdges(auth.organization.id, scanId, artifact.id, identity.edges),
      persistInfrastructure(auth.organization.id, scanId, artifact.id, infrastructure),
    ]);

    const parentView = { ...artifact, type: 'email', content: parsed.text };
    const urlChildren = hydratedChildren.filter((child) => child.type === 'url');
    progress('specialists', 'running', parserFailure
      ? `Content analysis was skipped because parsing failed. Checking ${urlChildren.length} extracted link${urlChildren.length === 1 ? '' : 's'}.`
      : `Running the content specialist and analyzing ${urlChildren.length} extracted link${urlChildren.length === 1 ? '' : 's'}.`);
    const [modelEvidence, linkEvidence] = await Promise.all([
      parserFailure
        ? failedModelEvidence('phishing', 'mailguard', artifact.id, parserFailure, true)
        : runPreparedAdapter(auth.organization.id, scanId, parentView, 'mailguard', 'phishing', policy, true),
      runPreparedLinkBatch(auth.organization.id, scanId, urlChildren, policy),
    ]);
    const incomplete = modelEvidence.status !== 'completed' || linkEvidence.some((item) => item.status !== 'completed');
    progress('specialists', incomplete ? 'failed' : 'completed', incomplete ? 'Some specialist checks could not finish. Available evidence will be retained.' : 'Content and link specialist checks finished.');
    const childEvidence = new Map();
    urlChildren.forEach((child, index) => childEvidence.set(child.id, linkEvidence[index]));

    const observationEvidence = gatewayObservationEvidence(authResult.observations, identity.edges, contentAndIdentityObservations, artifact.id);
    const correlationInputs = [modelEvidence, ...childEvidence.values(), observationEvidence];
    if (parserFailure) correlationInputs.push({ ...failedModelEvidence('parser', 'email.parser', artifact.id, parserFailure, true), kind: 'email_parser' });
    progress('decision', 'running', 'Combining observed evidence under the workspace policy.');
    const decision = correlate(correlationInputs, policy);
    decision.decision_state = 'final';
    await publishDecision(scanId, decision, auth.user?.id || null);
    await completeArtifacts(auth.organization.id, scanId);
    progress('decision', 'completed', 'Policy decision recorded.');

    const limitations = [
      ...parsed.limitations,
      ...authResult.limitations,
      ...identity.limitations,
      ...(infrastructureResult.limitations || infrastructureBase.limitations),
      ...(threatIntelligence.limitations || []),
      ...(campaignSchemaLimitation ? [campaignSchemaLimitation] : []),
      ...(parsed.attachments.length ? ['ATTACHMENTS_METADATA_ONLY_NO_MALWARE_EXECUTION'] : []),
      ...(parsed.attachments.some((item) => String(item.declared_mime_type).startsWith('image/')) ? ['ATTACHMENT_MEDIA_AUTHENTICITY_NOT_EVALUATED'] : []),
      ...(modelEvidence.status === 'failed' ? ['CONTENT_MODEL_FAILED'] : []),
      ...[...childEvidence.values()].filter((item) => item.status !== 'completed').map(() => 'LINK_INTELLIGENCE_PARTIAL_FAILURE'),
    ];
    const completedAt = now();
    const bundle = evidenceBundle({
      artifact,
      mode,
      state: specialistState(parsed.parseState, modelEvidence),
      observations: allObservations,
      authentication: authResult.observations,
      modelEvidence,
      edges: identity.edges,
      infrastructure,
      infrastructureState: infrastructureResult.state,
      infrastructureSummary: summarizeInfrastructure(infrastructure, { trustedReceiver: mode === 'trusted_receiver_event' }),
      threatIntelligence,
      campaignMemory,
      parentScanId: input.parentScanId || null,
      scanId,
      children: hydratedChildren,
      childEvidence,
      limitations,
      startedAt,
      completedAt,
      rawSha256: parsed.rawSha256 || rawDigest,
      parserVersion: parsed.parserVersion,
    });
    const passport = createEvidencePassport({ scanId, evidence: bundle, decision });
    bundle.evidence_passport = passport;
    await persistEvidencePassport(auth.organization.id, scanId, artifact.id, passport).catch((error) => {
      console.error(JSON.stringify({ timestamp: now(), level: 'warn', service: 'veritrust-email', event: 'evidence_passport.persistence_failed', scan_id: scanId, code: String(error?.code || 'PASSPORT_PERSIST_FAILED') }));
      return null;
    });
    const body = {
      ok: true,
      request_id: requestId,
      scan_id: scanId,
      status: 'completed',
      gateway_decision: {
        risk: decision.risk,
        severity: decision.severity,
        verdict: decision.verdict,
        recommendation: decision.recommendation,
        degraded: decision.degraded,
        reason_codes: decision.reason_codes,
        correlation_version: decision.correlation_version,
      },
      evidence: bundle,
    };
    progress('save', 'running', 'Saving the complete email report.');
    await storeIdempotentResponse(scanId, 200, body);
    progress('save', 'completed', 'Email report saved.');
    return { status: 200, body, replayed: false };
  } catch (error) {
    await failScan(auth.organization.id, scanId, error).catch(() => null);
    throw error;
  }
}

async function emailEvidenceReport(orgId, scanId) {
  const [gateway, records] = await Promise.all([scanReport(orgId, scanId), emailRecordsForScan(orgId, scanId)]);
  if (!records.details) return null;
  const storedEvidence = gateway.scan?.response_body?.evidence;
  if (storedEvidence?.schema_version && storedEvidence?.evidence_passport) return storedEvidence;
  const mode = gateway.scan.metadata?.input_mode || 'raw_eml';
  const parentArtifactId = records.details.artifact_id;
  const parentModelEvidence = (gateway.evidence || []).find((item) => item.artifact_id === parentArtifactId && item.model_run_id);
  const parentModelRun = parentModelEvidence
    ? (gateway.model_runs || []).find((item) => item.id === parentModelEvidence.model_run_id)
    : null;
  const rawState = parentModelEvidence?.raw_response_redacted?.state;
  const state = ['LIKELY_BENIGN', 'LIKELY_PHISHING', 'UNCERTAIN'].includes(rawState)
    ? rawState
    : (records.details.parse_state === 'UNSUPPORTED_LIMIT' ? 'UNSUPPORTED'
      : (['FAILED', 'FAILED_TIMEOUT', 'MALFORMED_LIMIT'].includes(records.details.parse_state) ? 'FAILED' : 'UNCERTAIN'));
  const children = (gateway.artifacts || []).filter((item) => item.parent_artifact_id === parentArtifactId).map((child) => {
    const childEvidence = (gateway.evidence || []).find((item) => item.artifact_id === child.id);
    return {
      artifact_id: child.id,
      parent_artifact_id: parentArtifactId,
      type: child.artifact_type,
      ordinal: child.ordinal,
      state: childEvidence?.status || (child.artifact_type === 'attachment' ? 'METADATA_ONLY' : 'UNAVAILABLE'),
      reason_codes: childEvidence?.reason_codes || [],
      metadata: child.metadata || {},
    };
  });
  const report = {
    schema_version: EMAIL_EVIDENCE_SCHEMA,
    scan_id: scanId,
    artifact_id: parentArtifactId,
    input_mode: mode,
    state,
    capabilities: CAPABILITIES[mode],
    evidence_completeness: evidenceCompleteness({
      mode,
      observations: [...(records.details.metadata?.content_observations || []), ...(records.auth || [])],
      modelEvidence: parentModelEvidence ? { status: parentModelEvidence.status } : null,
      infrastructure: records.infrastructure || [],
      infrastructureState: infrastructureStateFromHops(records.infrastructure || []),
      children,
      childEvidence: new Map((gateway.evidence || []).map((item) => [item.artifact_id, { status: item.status }])),
      threatIntelligence: records.details.metadata?.threat_intelligence || null,
    }),
    evidence_manifest: evidenceManifest({
      mode,
      parserVersion: records.details.parser_version,
      rawSha256: records.details.metadata?.raw_sha256 || null,
      modelEvidence: parentModelRun ? { modelVersionId: parentModelRun.model_version_id } : null,
      startedAt: gateway.scan.created_at || null,
      completedAt: gateway.scan.completed_at || gateway.scan.updated_at || null,
    }),
    infrastructure_summary: summarizeInfrastructure(records.infrastructure || [], { trustedReceiver: mode === 'trusted_receiver_event' }),
    threat_intelligence: records.details.metadata?.threat_intelligence || { state: 'UNAVAILABLE', domain_intelligence: [], ip_reputation: [], observations: [], limitations: ['THREAT_INTELLIGENCE_NOT_RECORDED'] },
    campaign_memory: records.details.metadata?.campaign_memory || { state: 'UNAVAILABLE', campaign_id: null, related_scan_count: 0, related_scans: [], common_entities: [] },
    investigation_lineage: records.details.metadata?.investigation_lineage || { parent_scan_id: gateway.scan.metadata?.parent_scan_id || null, current_scan_id: scanId, acquisition_stage: mode },
    observations: [...(records.details.metadata?.content_observations || []), ...(records.auth || [])].map((item) => normalizeEmailObservation(item)),
    model_evidence: parentModelEvidence ? [{
      model_version_id: parentModelRun?.model_version_id || null,
      state: rawState || (parentModelEvidence.status === 'failed' ? 'FAILED' : 'UNCERTAIN'),
      p_phish: parentModelEvidence.score,
      status: parentModelEvidence.status,
      reason_codes: parentModelEvidence.reason_codes || [],
    }] : [],
    authentication: records.auth,
    relationships: records.edges,
    infrastructure: (records.infrastructure || []).map((hop) => ({
      ...hop,
      wording: 'Sending Infrastructure - approximate infrastructure geolocation only',
    })),
    children,
    limitations: records.details.limitations || [],
    gateway_decisions: gateway.decisions,
    started_at: gateway.scan.created_at || null,
    completed_at: gateway.scan.completed_at || gateway.scan.updated_at || null,
  };
  const latestDecision = (gateway.decisions || []).at(-1) || null;
  const decisionForPassport = latestDecision ? {
    risk: latestDecision.risk_score,
    severity: latestDecision.severity || null,
    verdict: latestDecision.verdict,
    recommendation: latestDecision.recommendation,
    degraded: latestDecision.degraded,
    reason_codes: latestDecision.reason_codes || [],
    correlation_version: latestDecision.correlation_version,
  } : null;
  report.evidence_passport = createEvidencePassport({ scanId, evidence: report, decision: decisionForPassport });
  return report;
}

module.exports = { analyzeEmail, emailEvidenceReport, evidenceBundle, evidenceCompleteness, evidenceManifest, infrastructureStateFromHops, normalizeEmailObservation, requestHash, specialistState };
