# VeriTrustLab SIH26106 Internal-Hackathon Release Notes

> **Historical snapshot note (2026-09-18):** This file documents the 2026-09-15 release intent. Current repository behavior, enabled modules, test counts, and deployment prerequisites are defined by the present source, `README.md`, `config/modules.json`, and `npm run check`. Do not use historical counts below as current verification evidence.

Release date: 2026-09-15
Release intent: focused internal-hackathon build for **SIH26106 — AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform**.

In this implementation, **GeoLocation means approximate mail-infrastructure context only**; it does not claim a sender, attacker, or person's physical location.

## Judge-facing product surface

Primary navigation is intentionally restricted to:

1. Home
2. Investigate
3. Live SMTP
4. Verify Evidence

The canonical story is **Acquire → Trace → Correlate → Verify** around the four implementation-backed capability points:

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

## Validation note

The original 2026-09-15 build recorded static/module/package checks. Those file and test counts are intentionally not repeated here because the repository has changed since that snapshot. For the current checkout, treat only fresh command output as verification evidence:

```text
npm ci
npm run check
npm run config:check
npm audit --omit=dev --audit-level=high
```

`npm run config:check` is expected to fail in an isolated environment that does not contain deployment secrets. Connected dependency installation/audit and the Windows PowerShell dress rehearsal must be run in the actual release environment.

## Final pre-demo gate

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
7. finish with an Evidence Passport verify → tamper → verify-fail demonstration.

The web/API app remains Vercel-hosted. The persistent SMTP receiver remains a long-running receiver-laptop process and must not be moved into a Vercel Function.
