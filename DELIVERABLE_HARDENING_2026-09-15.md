# VeriTrustLab Deliverable Hardening — 2026-09-15

This snapshot hardens the four issues reported against the email-investigation flow while preserving the existing four-USP architecture and its claim boundaries.

## 1. Complete clickable-link analysis

- Email extraction now treats `href`, `action`, and `formaction` HTTP(S) destinations as actionable links.
- Passive HTML resources such as image/tracking-pixel `src` URLs no longer consume the clickable-link analysis budget.
- All distinct extracted clickable URLs are queued and awaited; link inference uses bounded concurrency instead of an accidental single-consumer execution path.
- One link failure is isolated and recorded rather than aborting the whole link batch.
- The evidence contract now exposes link-analysis completeness (`extracted`, `completed`, `failed`, `timed_out`, `pending`, `all_completed`).
- The investigation UI lists each extracted link child and its state/verdict/score so incomplete coverage is visible rather than silently hidden.
- Resource safety remains explicit: the email parser analyzes at most 50 distinct clickable HTTP(S) URLs per investigation. This is a deliberate bounded-compute limit, not silent truncation.

Runtime control: `VERITRUST_LINK_ANALYSIS_CONCURRENCY` defaults to `4` and is clamped to `1..8`.

## 2. False-positive hardening

- Plain link presence is contextual evidence, not a suspicious finding by itself.
- Benign account/login wording, attachment references, contact information, and ordinary external links no longer receive aggressive standalone severity.
- Suspicious-domain heuristics require stronger structural evidence rather than generic words alone.
- A moderate MailGuard phishing probability is promoted to `UNCERTAIN` unless it is strongly confident or independently corroborated.
- Email-level correlation no longer promotes an otherwise benign email merely because several child links have isolated medium scores.
- Temporary/permanent authentication processing errors are not treated as verified SPF/DKIM/DMARC failure evidence.
- Strong deterministic evidence and high-confidence malicious links can still escalate risk, preserving fail-safe behavior.

These thresholds are conservative engineering defaults. They are not claimed as statistically calibrated production thresholds because this repository still contains no controlled labeled accuracy/FPR/FNR benchmark.

## 3. Trust-Boundary GeoTrace correctness

- `Received:` parsing now selects candidate IPs only from the source-side `from ...` segment for each hop.
- Receiver-side `by ...` infrastructure is not substituted as the sender/source hop when the source segment contains no IP.
- Geolocation remains provider-derived (`ipwho.is` by default), with public-IP, provider-address, coordinate-range, response-size, timeout, and mismatch validation.
- Each public hop is independently enriched. There are no hard-coded map coordinates.
- The UI and PDF no longer draw a connecting route line. `Received:` headers provide infrastructure observations; they do not prove a physical network path or a person's location.
- Trusted SMTP mode still marks only the directly observed first hop as `trusted_receiver`; reconstructed header hops remain `observed_relay`.

## 4. Concise PDF report

- Removed the full raw-response appendix from the PDF.
- Removed the full glossary appendix from the PDF.
- PDF output now focuses on decision, evidence coverage, important signals, authentication, significant identity mismatches, link-analysis coverage/risky links, attachments, independent infrastructure observations, noteworthy threat intelligence, campaign correlation, model provenance, Evidence Passport, and the most important limitations.
- Full machine-readable evidence remains available through JSON/STIX/IOC exports instead of being duplicated across many PDF pages.
- A deliberately oversized regression fixture (20 links plus dense forensic evidence) generates 7 pages and is guarded by a `<= 10` page regression assertion.

## Additional repository hardening

- Added `supabase/migrations/20260911_forensic_intelligence.sql` for `email_threat_entities` and `email_evidence_passports`, RLS read policies for active organization members, service-role access, and Evidence Passport update prevention.
- Added targeted Node regression tests for link completeness, benign-email false-positive handling, correlation, GeoTrace source-hop selection/per-IP enrichment, and compact PDF output.
- Updated browser asset query versions so an existing browser session does not retain the stale GeoTrace/report implementation after deployment.

## Validation performed on this snapshot

- `node --check` passes for all 126 JavaScript files in the deliverable tree.
- `npm run check` passes.
- Repository verifier: 20 pages, 127 source files, 6/12 Vercel functions, security headers, SEO metadata, local links, and committed-secret checks verified.
- Four independent module-disabled states verified.
- Node regression suite: 13/13 tests pass.
- Dense PDF stress fixture: 7 pages.

## Remaining deployment-validation boundary

Static/regression validation cannot prove live behavior of external services. Before a real production release, run the same checks in the deployed environment with the intended Supabase project, model-provider credentials, `ipwho.is` network access, DNS/authentication lookups, SMTP receiver, and a labeled benign/phishing email corpus. The code deliberately preserves `UNCERTAIN`/degraded states when evidence or providers are unavailable rather than manufacturing certainty.
