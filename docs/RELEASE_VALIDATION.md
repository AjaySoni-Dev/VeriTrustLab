# SIH Release Validation — 2026-09-11

This file records reproducible checks for the source archive delivered for SIH26106.

## Automated repository validation

Run from the repository root:

```bash
npm ci
npm run check
npm run config:check
npm audit --omit=dev --audit-level=high
git diff --check
```

The release-building environment executed `npm run check` after all source and dependency-lock changes. The suite passed **40/40 tests**, including SMTP enforcement/fail-safe behavior and dedicated regression coverage for all four forensic USPs.

The release-building environment also accepted the lockfile using `npm install --package-lock-only --ignore-scripts --offline`, parsed the OpenAPI 3.1 file with PyYAML, checked runtime JavaScript syntax, validated local page/assets over a static HTTP server, and ran `git diff --check`.

## Security dependency pins

`package.json` uses npm overrides to keep security-sensitive transitive dependencies on patched release lines:

- `undici` = `8.10.2`
- `nodemailer` = `9.1.1`
- `deepmerge-ts` = `8.0.1`

A regression test verifies the overrides and lockfile resolutions. The build sandbox could not reach the npm registry for a live `npm audit`; therefore the connected CI/deployment environment must still execute the audit command above before public deployment.

## USP regression coverage

The test suite checks that the shipped UI/API/schema continue to expose:

1. **Trust-Boundary GeoTrace** — trusted receiver observations remain distinguishable from copied/unverified relay claims.
2. **Evidence Passport** — unchanged evidence verifies; tampered evidence and self-consistent packages signed by an unrecognized issuer are rejected.
3. **MailGraph Campaign Memory** — durable cross-scan entities correlate; ASN-only and single weak/domain overlap cannot manufacture a campaign.
4. **Progressive Evidence Escalation** — the UI retains the Text → Original EML → Trusted Receiver acquisition workflow and export/verification routes.

## Database

Apply `supabase/migrations/20260911_forensic_intelligence.sql` only after confirming the target Supabase project contains the existing `organizations`, `gateway_scans`, and `gateway_artifacts` tables used by this repository. The migration is idempotent, enables RLS on the new tables, and makes issued Evidence Passport rows immutable to updates.

The separate Supabase inventory mentioned during development was not present in the available build inputs, so this release does not claim an external inventory comparison that could not be performed.

## Deployment boundaries

- The bundled SMTP listener is a trusted/private receiver reference implementation and does **not** implement inbound STARTTLS. Keep it on a trusted private segment/VPN or place a reviewed TLS-capable MTA in front.
- RDAP and AbuseIPDB are external enrichments. Provider failure is represented as unavailable/limited evidence and must never be interpreted as benign.
- A dedicated Ed25519 signing key is recommended for production Evidence Passports; keep retired valid key IDs in the trusted-key allowlist during rotation.
