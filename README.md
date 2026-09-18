<h1 align="center">VeriTrust Lab MailGraph</h1>

<p align="center">
  <strong>AI-assisted email threat investigation, provenance-aware infrastructure context, and forensic evidence workflows</strong><br>
  A Vercel-hosted investigation platform with bounded email evidence parsing, authentication and identity analysis, URL intelligence, correlation, cases, reports, and an optional persistent SMTP enforcement gateway.
</p>

<p align="center">
  <img alt="Status" src="https://img.shields.io/badge/status-active%20prototype-blue">
  <img alt="Runtime" src="https://img.shields.io/badge/runtime-Node.js-green">
  <img alt="Email" src="https://img.shields.io/badge/email-MailGraph-purple">
  <img alt="Backend" src="https://img.shields.io/badge/backend-Supabase-success">
  <img alt="Deploy" src="https://img.shields.io/badge/deploy-Vercel-black">
  <img alt="License" src="https://img.shields.io/badge/license-repository%20license-lightgrey">
</p>

<p align="center">
  <a href="#overview">Overview</a> ·
  <a href="#what-this-repo-contains">Contents</a> ·
  <a href="#implemented-pages">Pages</a> ·
  <a href="#features">Features</a> ·
  <a href="#deployment">Deployment</a>
</p>

---

## Overview

**VeriTrust Lab MailGraph** turns suspicious email input into structured, provenance-aware threat evidence rather than stopping at a single phishing score.

The main flow is:

```text
Email / raw EML / trusted receiver event → Bounded parsing → Auth + identity + URL + relay evidence → Threat intelligence + campaign memory → Correlation → Signed Evidence Passport → Case/report/export
```

A separate long-running SMTP gateway can provide trusted transport observations before delivery. Infrastructure geolocation describes observable mail infrastructure; it does **not** establish a person's physical location or identity.

---

## What This Repo Contains

| Area | What is included |
|---|---|
| MailGraph email stack | Bounded parsing, authentication, identity, relay, infrastructure, and evidence contracts. |
| Gateway | Evidence correlation, policy, persistence, review, storage, and execution logic. |
| Model adapters | Phishing, URL, and configured model-provider integration. |
| Vercel APIs | Account, billing, detection, system, v1, and Gateway entry points. |
| Primary product UI | Home, canonical email investigation, trusted SMTP demo, Evidence Passport verifier, and a focused recent-investigations dashboard. Cases and administration remain secondary/direct-access surfaces. |
| SMTP enforcement | Persistent Node/PowerShell mail relay for controlled private/LAN deployment. |
| OpenAPI | Email v2 and Gateway contracts. |
| Tests and verification | Node regression tests, runtime checks, module checks, and repository verification. |

---

## Implemented Pages

| Page | Purpose |
|---|---|
| `index.html` | Minimal product entry: four implementation-backed capability cards, evidence ladder, and two primary actions. |
| `phishing.html` | Canonical email-threat and forensic investigation interface. |
| `gateway-powershell.html` | Two-laptop trusted SMTP sender/receiver demonstration guide. |
| `verify-evidence.html` | Evidence Passport package-integrity and configured-issuer verification. |
| `dashboard.html` | Focused recent email investigations and recovery. |
| `cases.html` / `case.html` | Secondary analyst case workflow. |
| `account.html` / `api-access.html` / `billing.html` | Direct-access operational administration; intentionally outside the presentation flow. |
| `developers.html` / `docs.html` / `model-performance.html` | Direct technical reference and claim-boundary documentation. |

---

## Features

| Area | Current Implementation |
|---|---|
| Evidence modes | `plain_text`, `raw_eml`, and `trusted_receiver_event`. |
| Email parsing | Bounded MIME/header/content processing with explicit failure states. |
| Authentication | SPF when trusted SMTP facts exist, plus DKIM, DMARC, and ARC evidence. |
| Identity graph | Sender/header/domain relationships and alignment/confusable analysis. |
| URL intelligence | Swift child-link classification plus deterministic URL-string observations; the current path does not fetch destination webpages or follow redirects. |
| Trust-Boundary GeoTrace | Received-hop extraction, IP classification, ASN/provider, approximate geo context, explicit trusted-receiver vs observed-relay semantics, bounded/deduplicated lookups, and separate enrichment-vs-coordinate map states. |
| Threat intelligence | Bounded RDAP registration intelligence plus optional AbuseIPDB reputation for eligible public infrastructure. |
| Campaign Memory | Tenant-scoped weighted correlation of normalized forensic entities across prior investigations. Hashed lookup keys are used, while normalized entity values can also be retained for explainability. |
| Evidence Passport | SHA-256-bound Ed25519 signed evidence manifests with trusted-issuer verification. Public full-package integrity verification requires both the passport and evidence object; JSON/STIX 2.1/observed-artifact CSV/JSON export is supported; exported artifacts are not independently classified as malicious. |
| Progressive evidence | Explicit `plain_text → raw_eml → trusted_receiver_event` evidence ladder with next-acquisition actions. Parent lineage is same-tenant and strictly forward-stage validated, but remains a user-linked evidence upgrade rather than cryptographic same-message proof. |
| Evidence correlation | Policy-aware aggregation with strong-signal floors and human-review escalation. |
| Cases and reports | Persistence, review/case routes, reports, identifiers, and provenance are implemented; runtime availability depends on the compatible deployed database contract. |
| SMTP enforcement | Relay, defer, or reject based on the existing Gateway recommendation. |
| Security controls | CSP/HSTS/security headers, scoped APIs, service-role storage paths, and retention logic. Database/storage privacy guarantees depend on the compatible deployed Supabase policy contract. |

---

## User Flow

```text
Submit suspicious email or receive it through the SMTP gateway
  ↓
Classify available evidence capabilities
  ↓
Analyze content, authentication/alignment, identity, URLs, attachment metadata/hashes, and relay infrastructure
  ↓
Correlate evidence with policy and completeness state
  ↓
Allow / warn / review / hold / quarantine / block as configured
  ↓
Persist available investigation/evidence records, create or review cases where the deployed workflow does so, correlate prior investigations, sign the Evidence Passport, and export JSON/STIX/CSV/PDF
```

---

## Structure

```text
VeriTrust-Site/
├── api/
├── assets/
├── config/
├── supabase/
│   └── migrations/
├── lib/
│   ├── email/
│   ├── gateway/
│   ├── models/
│   └── routes/
├── mail-gateway/
├── openapi/
├── scripts/
├── tests/
├── worker/
├── vercel.json
├── README.md
└── LICENSE
```

---

## Deployment

The web/API application is configured for Vercel through `vercel.json`. The persistent SMTP gateway is intentionally **not** a Vercel function; it requires a long-running Node.js process or a private/VPN/TLS-capable SMTP edge.

Local repository verification (Node.js 24.x, matching CI/Vercel engine):

```bash
npm ci
npm run check
npm run config:check
npm audit --omit=dev --audit-level=high
```

Deployments require the compatible existing Supabase base contract plus the forensic extension migration in `supabase/migrations/20260911_forensic_intelligence.sql`, and server-side provider/Gateway/receiver secrets. This repository still does not contain the complete historical base schema/RPC migration set; a fresh Supabase project cannot be reconstructed from this snapshot alone. Production Evidence Passport signing requires `VERITRUST_EVIDENCE_SIGNING_PRIVATE_KEY`. GeoTrace defaults to the public IPwho.is fallback for development/demo use; production can set `VERITRUST_GEO_PROVIDER=custom` plus `VERITRUST_GEO_PROVIDER_URL` and optional `VERITRUST_GEO_PROVIDER_TOKEN`. Service-role and receiver secrets must never be exposed to browser JavaScript.

---

## Important Notes

- Infrastructure geolocation is approximate infrastructure context, not person geolocation or actor attribution.
- Missing, failed, unavailable, or uncertain evidence must not be converted into a benign result. Generic Gateway media is rejected when the deepfake module is disabled rather than finalized as unanalyzed allow.
- Attachments are metadata/hash/filename/MIME-only in the email-forensics path and are never executed by the parser. Coverage is marked limited when parser budgets prevent complete metadata processing.
- No controlled VeriTrust Lab accuracy/precision/recall/F1 benchmark is claimed by this repository.
- Standalone Detection Hub, Link Check, generic Gateway UI, and Web CLI pages are intentionally removed. Their shared backend capabilities remain where the canonical email workflow depends on them.

---

## License

Use according to the repository's existing license and deployment policy.
