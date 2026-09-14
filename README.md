<h1 align="center">VeriTrust MailGraph</h1>

<p align="center">
  <strong>AI-powered email threat detection, infrastructure geolocation, and forensic intelligence</strong><br>
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

**VeriTrust MailGraph** turns suspicious email input into structured, provenance-aware threat evidence rather than stopping at a single phishing score.

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
| Judge-facing UI | Home, canonical email investigation, trusted SMTP demo, Evidence Passport verifier, and a focused recent-investigations dashboard. Cases and administration remain secondary/direct-access surfaces. |
| SMTP enforcement | Persistent Node/PowerShell mail relay for controlled private/LAN deployment. |
| OpenAPI | Email v2 and Gateway contracts. |
| Tests and verification | Node regression tests, runtime checks, module checks, and repository verification. |

---

## Implemented Pages

| Page | Purpose |
|---|---|
| `index.html` | Minimal product entry: four USP proof cards, evidence ladder, and two primary actions. |
| `phishing.html` | Canonical email-threat and forensic investigation interface. |
| `gateway-powershell.html` | Two-laptop trusted SMTP sender/receiver demonstration guide. |
| `verify-evidence.html` | Independent Evidence Passport integrity and trusted-issuer verification. |
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
| URL intelligence | Child-link analysis and deterministic suspicious-URL observations. |
| Trust-Boundary GeoTrace | Received-hop extraction, IP classification, ASN/provider, approximate geo context, and explicit trusted-receiver vs observed-relay semantics. |
| Threat intelligence | Bounded RDAP registration intelligence plus optional AbuseIPDB reputation for eligible public infrastructure. |
| Campaign Memory | Tenant-scoped weighted correlation of privacy-minimized domains, hashes, SMTP infrastructure, and identity artifacts across prior investigations. |
| Evidence Passport | SHA-256-bound Ed25519 signed evidence manifests with trusted-issuer verification and JSON/STIX 2.1/IOC CSV export. |
| Progressive evidence | Explicit `plain_text → raw_eml → trusted_receiver_event` evidence ladder with next-acquisition actions and scan lineage. |
| Evidence correlation | Policy-aware aggregation with strong-signal floors and human-review escalation. |
| Cases and reports | Persisted evidence, review/case workflows, reports, identifiers, and provenance. |
| SMTP enforcement | Relay, defer, or reject based on the existing Gateway recommendation. |
| Security controls | CSP/HSTS/security headers, private storage paths, retention controls, and scoped APIs. |

---

## User Flow

```text
Submit suspicious email or receive it through the SMTP gateway
  ↓
Classify available evidence capabilities
  ↓
Analyze content, authentication, identity, URLs, attachments, and relay infrastructure
  ↓
Correlate evidence with policy and completeness state
  ↓
Allow / warn / review / hold / quarantine / block as configured
  ↓
Preserve evidence in a case, correlate campaigns, sign the Evidence Passport, and export JSON/STIX/CSV/PDF
```

---

## Structure

```text
VeriTrust-Site/
├── api/
├── assets/
├── config/
├── docs/
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

Deployments require the compatible existing Supabase contract plus `supabase/migrations/20260911_forensic_intelligence.sql`, and server-side provider/Gateway/receiver secrets. Service-role and receiver secrets must never be exposed to browser JavaScript.

---

## Important Notes

- Infrastructure geolocation is approximate infrastructure context, not person geolocation or actor attribution.
- Missing, failed, unavailable, or uncertain evidence must not be converted into a benign result.
- Attachments are metadata-only in the email-forensics path and are never executed by the parser.
- No controlled VeriTrust accuracy/precision/recall/F1 benchmark is claimed by this repository.
- Standalone Detection Hub, Link Check, generic Gateway UI, and Web CLI pages are intentionally removed. Their shared backend capabilities remain where the canonical email workflow depends on them.

---

## License

Use according to the repository's existing license and deployment policy.
