# VeriTrust Architecture

## Product center of gravity

VeriTrust MailGraph is an email threat and forensic-intelligence workflow. Link Intelligence, the Evidence Correlation Gateway, Cases, reporting, privacy and API access support that workflow; they are not separate product stories.

## Runtime flow

1. **Input capability classification** — `plain_text`, `raw_eml`, or `trusted_receiver_event`.
2. **Bounded parsing** — raw email is parsed with explicit byte, MIME-depth, part-count and timeout limits.
3. **Content evidence** — MailGuard and deterministic content observations.
4. **Authentication evidence** — DKIM/DMARC/ARC from raw evidence; SPF only when trusted SMTP facts are supplied.
5. **Identity relationships** — visible and technical sender identities, linked domains and infrastructure relationships.
6. **URL intelligence** — extracted URLs become child artifacts evaluated independently.
7. **Attachment metadata** — attachment metadata/hashes are recorded; attachment content is not executed.
8. **Infrastructure context** — Received-header infrastructure is extracted, classified and optionally enriched with ASN/geolocation.
9. **Threat intelligence** — eligible domains receive bounded RDAP registration context and eligible public IPs can receive configured AbuseIPDB reputation context. Provider failure remains an explicit limitation.
10. **Campaign Memory** — privacy-minimized durable entities are compared only inside the authenticated organization; weak overlap such as ASN-only cannot create a campaign.
11. **Correlation** — the Gateway combines available specialist and deterministic evidence under policy.
12. **Evidence Passport** — the finalized evidence bundle is deterministically hashed and signed with Ed25519; verification requires both cryptographic validity and a recognized VeriTrust signing-key fingerprint.
13. **Persistence/reporting** — results, evidence, cases, campaign entities, passports and audit identifiers use the Supabase contract.

## Trust model

A saved email is not automatically a trusted record of the complete SMTP transaction. Copied `Authentication-Results` and lower Received headers can be misleading unless anchored to a trusted receiver boundary.

For `raw_eml`, infrastructure is therefore **observed/unverified**. For `trusted_receiver_event`, the receiver-added boundary can support stronger SMTP and SPF evidence. The system never converts this into a person-location claim.

## Risk versus evidence completeness

VeriTrust intentionally separates:

- specialist model score;
- deterministic rule evidence;
- correlated Gateway risk;
- evidence completeness.

Evidence completeness reports how much usable forensic evidence was available. It does not change the risk formula and is not a safety score.

## Database boundary

The forensic-intelligence release adds two server-only, RLS-protected tables through `supabase/migrations/20260911_forensic_intelligence.sql`:

- `email_threat_entities` stores privacy-minimized tenant-scoped correlation entities for MailGraph Campaign Memory. It does not store raw message bodies.
- `email_evidence_passports` stores immutable signature/hash metadata for issued Evidence Passports. An update trigger prevents modification after issuance.

Both tables reference the existing `organizations`, `gateway_scans`, and `gateway_artifacts` records. If the migration is not yet applied, the scan still completes but Campaign Memory/passport persistence records an explicit schema limitation rather than inventing evidence.

## Live SMTP enforcement path

The persistent SMTP gateway in `mail-gateway/` is a transport adapter around the existing MailGraph/Gateway stack, not a second threat engine. It receives SMTP on a private listener, records the directly observed client IP/HELO/MAIL FROM/receiver timestamp, prepends the receiver-owned `Received:` header, and submits the exact received RFC 822 bytes to `/internal/v2/phishing/receiver-eml`. The API authenticates both the scoped Gateway API key and the separate receiver secret before accepting those facts as `trusted_receiver_event` evidence.

The transport adapter then applies the already-computed Gateway recommendation: `allow/warn` relay downstream; `manual_review/hold` produce a temporary SMTP failure; `quarantine/block` produce a permanent policy rejection. Required evidence failure or API unavailability does not silently bypass inspection. This keeps model/rule scoring, deterministic floors, policy thresholds, case persistence and report provenance centralized in the existing Gateway.

Vercel continues to host the HTTP/API surface. The SMTP listener must run as a separate long-lived process on Windows/Linux or behind a mature MTA content-filter hook.
