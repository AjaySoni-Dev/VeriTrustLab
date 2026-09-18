# VeriTrust Lab Product Release Notes

Release date: 2026-09-15
Release intent: deployable product build focused on evidence-aware email threat detection, infrastructure provenance, campaign correlation, and cryptographic evidence verification.

## Product surface

Primary navigation is intentionally restricted to:

1. Home
2. Investigate
3. Live SMTP
4. Verify Evidence

The canonical story is **Acquire → Trace → Correlate → Verify** around the four implemented proof points:

- Progressive Evidence Escalation™
- Trust-Boundary GeoTrace™
- MailGraph Campaign Memory™
- Evidence Passport™

Cases and operational administration remain implemented but are secondary/direct-access surfaces.

## Deliberately removed presentation clutter

The following standalone browser pages are removed and redirected:

- `/detection` → `/phishing`
- `/link-check` → `/phishing`
- `/gateway` → `/phishing`
- `/cli` → `/gateway-powershell#live-smtp`

Their shared backend capabilities are not disabled. `link` and `gateway` remain enabled because the canonical email investigation depends on URL evidence and evidence correlation.

The obsolete page-specific Web CLI, standalone Link Check, generic Gateway, and Detection Hub frontend assets were also removed.

## Trusted SMTP demo package

`assets/downloads/VeriTrust-Lab-Persistent-CLI.zip` is the single version-matched Windows demo package. It contains:

- receiver CLI;
- sender CLI;
- launcher/validator helpers;
- matching `mail-gateway/` Node runtime;
- branding/readme.

The receiver no longer downloads a pinned GitHub runtime. It uses the bundled runtime by default, supports `VERITRUST_MAIL_GATEWAY_ROOT` as an explicit local override, and supports `VERITRUST_API_BASE_URL` to bind the package to the final Vercel deployment.

Keep the receiver secret and scoped `gateway:scan` API key on the receiver only. Do not copy them to the sender laptop.

## Production runtime configuration

This repository intentionally does not contain deployment secrets. Before Vercel deployment, configure the environment required by the enabled modules. At minimum the current runtime checker expects the applicable values for:

- `SUPABASE_URL`
- `SUPABASE_ANON_KEY`
- `SUPABASE_SERVICE_ROLE_KEY`
- `HF_TOKEN` or `HF_ACCESS_TOKEN`
- `VERITRUST_CONTENT_HMAC_KEY` (or compatible configured alias)
- `VERITRUST_EMAIL_RECEIVER_SECRET`
- `VERITRUST_GATEWAY_DISPATCH_SECRET`
- `VERITRUST_WEBHOOK_ENCRYPTION_KEY`

For the demo/release also configure:

- a dedicated Evidence Passport Ed25519 signing key and trusted key IDs;
- `VERITRUST_TRUSTED_AUTHSERV_IDS=veritrust-smtp-gateway`;
- final `VERITRUST_SITE_URL` and `VERITRUST_ALLOWED_ORIGINS`.

Verify the deployed Supabase project already contains the compatible forensic-intelligence migration/schema and its RLS/storage policy contract.

## Validation completed in this build workspace

- `npm run check`: **PASS**
- repository/static verification: **PASS** — 20 pages, 130 source files, 6/12 Vercel functions, security headers, SEO/local-link and committed-secret rules
- module-disabled matrix: **PASS** for all four independent module states
- Node regression suite: **44/44 PASS**
- removed-page/redirect/backend-retention contract: **PASS**
- unified CLI package content check: **PASS**
- receiver remote-runtime dependency check: **PASS** — no pinned GitHub runtime download remains
- CLI artifact SHA-256 manifest match: **PASS**

`npm run config:check` correctly reports missing secrets in this isolated build workspace; those secrets must be supplied only in the actual deployment environment.

`npm ci`/`npm audit` could not be completed here because the sandbox could not resolve the npm registry. The repository declares Node.js `24.x`, matching the CI workflow. Run both commands in the final connected CI/Vercel pre-deploy environment.

PowerShell Core is not installed in this Linux build container, so the Windows parser/dress-rehearsal step must be run on the two actual demo laptops before release.

## Final release validation gate

On a connected Node.js 24 environment:

```text
npm ci
npm run check
npm run config:check
npm audit --omit=dev --audit-level=high
```

Then on the two Windows demo laptops:

1. unzip the exact same `VeriTrust-Lab-Persistent-CLI.zip` release;
2. set the receiver-only credentials and final API origin;
3. validate sender/receiver PowerShell parsing;
4. verify Tailscale/private connectivity and recipient-domain allowlist;
5. send a controlled `.eml` end-to-end;
6. confirm allow/reject/defer behavior and the resulting `trusted_receiver_event` investigation;
7. finish with Evidence Passport verify → tamper → verify-fail proof.

The web/API app remains Vercel-hosted. The persistent SMTP receiver remains a long-running receiver-laptop process and must not be moved into a Vercel Function.
