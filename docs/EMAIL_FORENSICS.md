# Email Forensics

## Input modes

### Plain text

Supports message-content and URL review. It cannot verify MIME structure, copied headers, authentication, attachments or delivery infrastructure.

### Raw EML

Supports bounded MIME/header parsing, DKIM/DMARC/ARC evidence, sender relationships, embedded URLs, attachment metadata and observable Received-header infrastructure. SPF remains unavailable when trusted SMTP transaction facts are absent.

### Trusted receiver event

Adds trusted SMTP facts such as client IP, HELO, MAIL FROM, receiver identity and authserv identity. This enables SPF evaluation and a stronger receiver-boundary interpretation.

### Live SMTP receiver path

The bundled SMTP gateway creates this mode at message-receipt time rather than reconstructing it later. It adds the receiver-owned top `Received:` header, sends the same exact received message bytes plus directly observed SMTP facts to the protected trusted-receiver endpoint, and waits for the Gateway policy decision before downstream relay. This is the strongest MailGraph input mode currently implemented because SPF can be evaluated against the observed connection boundary.

## Authentication boundary

- DKIM is locally verified from the available raw message where possible.
- DMARC uses available alignment evidence.
- ARC provides forwarded-message context.
- SPF requires trusted SMTP facts and is not reconstructed from a copied header alone.
- `Authentication-Results` is not blindly trusted merely because it is present inside an uploaded message.

## Sender identity graph

Relationships can include From, Reply-To, Return-Path, Sender, Message-ID, DKIM/SPF domains, URL domains and observable sending infrastructure. Organizational-domain normalization and confusable/mixed-script observations are supporting evidence, not proof of maliciousness.

## Delivery infrastructure

Received-header candidates are classified as public/private/reserved/loopback. Public infrastructure can be enriched by a configured provider with ASN/organization and approximate country/region/city coordinates.

For standalone EML, these hops remain observational. A trusted receiver event can identify a public node observed directly at that trust boundary, but this still does not prove the physical location or identity of a person.

## Attachment handling

Attachments are metadata-only in the MailGraph pipeline. VeriTrust can record filename, declared MIME, size, hash and deterministic metadata risk flags such as executable/script extensions, macro-enabled Office formats, double extensions, bidirectional filename controls and selected MIME/extension mismatches.

Attachment contents are not executed or malware-sandboxed by this parser.

## Evidence completeness

The response can describe seven dimensions:

- content;
- AI model;
- authentication;
- identity;
- links;
- attachments;
- infrastructure.

Each can be `CHECKED`, `LIMITED`, or `UNAVAILABLE`. The aggregate level is `STRONG`, `MODERATE`, or `LIMITED`. This describes forensic coverage only and never means “safe”.

## Evidence manifest

Reports can expose technical provenance including evidence schema, pipeline, parser, authentication, identity and infrastructure versions, input mode, raw evidence SHA-256 where available, model version IDs and timestamps.

This supports reproducibility. It is not a legal certification by itself.


## Trust-Boundary GeoTrace

GeoTrace visualizes only mail infrastructure for which latitude/longitude enrichment exists. Every node preserves its evidence semantics:

- `trusted_receiver` means the VeriTrust receiver directly observed the SMTP boundary;
- `observed_relay` means the hop was reconstructed from message headers and can be useful context but is not promoted to a verified sender origin.

The UI deliberately says *infrastructure observation* rather than *attacker location*.

## Threat intelligence

VeriTrust can collect bounded RDAP domain-registration context and configured AbuseIPDB reputation for eligible public IPs. Requests use standard-port HTTPS, DNS/public-address validation, redirect limits, response-size limits, request timeouts and bounded lookup counts. Provider-derived observations are timestamped and never treated as proof on their own.

Very-new domain or IP-reputation observations only increase deterministic email risk when combined with stronger phishing/context signals. Provider outage or missing credentials creates a limitation instead of a benign result.

## MailGraph Campaign Memory

Campaign Memory stores tenant-scoped, privacy-minimized entities such as attachment SHA-256, URL/domain identities, selected authentication domains, and SMTP infrastructure. Raw message bodies and complete mailbox addresses are not stored in this table.

Correlation is deterministic and weighted. An exact attachment hash can correlate by itself. Otherwise, a campaign requires multiple independent entity types and sufficient combined weight. ASN-only, IP-only, sender-domain-only and URL-domain-only overlap cannot create a campaign.

## Evidence Passport

Evidence Passport is the durable provenance primitive for completed investigations. New investigations canonicalize the final normalized evidence, hash that evidence and its manifest with SHA-256, construct the v1 signed payload, sign it once with Ed25519, self-verify the complete package, and persist the Passport together with the exact normalized evidence that produced `evidence_sha256`.

Verification has two explicit scopes:

- `FULL_PACKAGE` checks the v1 structure, Passport ID, Ed25519 signature, signing-key fingerprint, evidence SHA-256 and manifest SHA-256. `valid=true` is reserved for a complete package for which all of those checks passed and the signing key is currently in the VeriTrust trusted-issuer set.
- `PASSPORT_ONLY` can verify the signed Passport payload, key fingerprint and Passport ID, but evidence/manifest integrity is `NOT CHECKED`; it never returns full `valid=true`.

Issuer trust is deliberately separate from mathematical signature validity. A package may be cryptographically self-consistent while its issuer is `UNKNOWN` (registry unavailable) or `UNTRUSTED` (fingerprint not in the configured trusted set). Browser file/paste verification is local-first: Web Crypto performs SHA-256 and Ed25519 verification without uploading the evidence. Only public trust metadata is fetched. Server verification remains available for API clients and as an explicit browser fallback after disclosure.

Historical reads and exports never create or re-sign a Passport. New-format rows return the persisted exact evidence and original signed envelope after integrity checks. A legacy row without exact evidence may reuse a surviving historical idempotent response only if its digest/signature prove it is the exact package; otherwise the report is labeled reconstructed/unsigned and the original Passport metadata is kept separate. A report with no originally recorded Passport remains unsigned.

Production-like deployments require `VERITRUST_EVIDENCE_SIGNING_PRIVATE_KEY`. `VERITRUST_EVIDENCE_TRUSTED_KEY_IDS` retains trusted historical fingerprints during rotation. Removing a retired fingerprint makes issuer trust false without changing the old package or its mathematical signature validity.

The Passport establishes cryptographic integrity and recorded provenance only. It does not establish legal admissibility, WORM retention, sender/person identity, attacker identity, message safety, correctness of the phishing verdict, or a signature over PDF bytes. The PDF is a human-readable rendering; verification applies to the exported Evidence JSON / Evidence Passport unless the PDF is separately signed.

JSON export is labeled `signed_evidence_package` only when the exact verifiable package exists. Historical reconstruction is labeled `reconstructed_unsigned`. STIX/IOC exports are derived representations, not substitutes for the signed evidence package.

## Progressive evidence escalation

Evidence completeness is exposed as an acquisition ladder rather than hidden behind one confidence number:

`plain_text → raw_eml → trusted_receiver_event`

The response includes `next_actions` that tell the investigator whether uploading the original EML or acquiring live receiver evidence would unlock materially stronger dimensions. `parent_scan_id` links an upgraded investigation to its predecessor without mutating the prior signed result.
