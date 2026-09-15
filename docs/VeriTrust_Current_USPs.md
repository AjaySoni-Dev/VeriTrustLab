# VeriTrustLab — Current Implemented USP Portfolio

**Scope:** Internal hackathon presentation of the supplied current VeriTrustLab codebase.  
**Positioning rule:** Present these as implemented engineering capabilities in the current prototype. Do not convert future SIH hardening, enterprise integrations, or benchmark claims into current capabilities.

| Rank | USP | Competitive Strength | What Is Implemented Now | Judge-Facing Value | Best Demo Proof | Claim Boundary |
|---:|---|---|---|---|---|---|
| **1** | **Evidence Passport™** | **Very High** | Completed email investigations can be canonicalized, SHA-256 hashed, and signed with **Ed25519**. Verification checks evidence integrity, manifest integrity, signature validity, key identity, and optional trusted-issuer membership. | **“The investigation result is not just a report; it is a cryptographically verifiable evidence package.”** | Generate/obtain a passport → verify it successfully → modify evidence/manifest → show verification failure. | Say **cryptographically verifiable integrity/provenance**. Do not claim legal admissibility, WORM storage, or proof of human identity. |
| **2** | **Progressive Evidence Escalation™** | **High** | VeriTrust has three explicit acquisition modes: `plain_text` → `raw_eml` → `trusted_receiver_event`. Each stage exposes only the evidence capabilities actually available, and upgraded investigations preserve lineage through `parent_scan_id`. | **“VeriTrust knows the difference between evidence we were given, evidence reconstructed from the original email, and evidence directly observed at the SMTP boundary.”** | Analyze text → analyze original EML → show the stronger capability set / acquisition state → demonstrate trusted-receiver evidence when available. | A stronger acquisition stage gives **stronger evidence**, not a guaranteed more-correct phishing verdict. |
| **3** | **Trust-Boundary GeoTrace™** | **High** | Infrastructure extracted from message headers remains explicitly **observed/reconstructed** rather than being promoted to verified origin. Only directly observed trusted SMTP infrastructure receives the strongest trust state. ASN/provider and approximate geographic enrichment can be attached while preserving provenance semantics. | **“We do not mistake a forged `Received:` header for verified attacker origin.”** | Show a raw-EML relay as `OBSERVED_UNVERIFIED`; then show trusted receiver evidence as `TRUSTED_BOUNDARY_OBSERVED`. | Position this as **trust-aware infrastructure provenance**, not exact attacker/person geolocation. |
| **4** | **MailGraph Campaign Memory™** | **Moderate** | Current investigations are deterministically correlated with prior investigations using weighted, privacy-minimized forensic entities. Durable signals receive higher weight; weak single-signal overlaps are rejected; the matching evidence is explainable. | **“Instead of an opaque ‘similar email’ label, VeriTrust shows exactly why two investigations are linked—and refuses weak coincidences.”** | Show two related scans with matched entities/weights; contrast with a weak overlap that is deliberately not promoted to a campaign. | Campaign clustering is not globally unique. Differentiate on **explainability, conservative correlation, and tenant-controlled evidence**, not hyperscale telemetry. |

## One-line product story

> **Detection tells you what looks dangerous. VeriTrust tells you what evidence you actually have, where it came from, how strongly it can be trusted, how it relates to prior investigations, and whether the packaged evidence was altered afterward.**

## How the four USPs connect

`Acquire evidence` → **Progressive Evidence Escalation™** → `interpret provenance` → **Trust-Boundary GeoTrace™** → `correlate prior investigations` → **MailGraph Campaign Memory™** → `package and verify` → **Evidence Passport™**

## Supporting capabilities — valuable, but not standalone uniqueness claims

MIME/header parsing, SPF/DKIM/DMARC/ARC analysis, URL extraction/classification, attachment metadata/hashing, sender-identity/impersonation signals, deterministic + model evidence correlation, policy evaluation, optional SMTP enforcement, cases/review workflow, dashboard, API keys, OpenAPI contracts, JSON/STIX/IOC CSV exports, PDF reporting, Supabase-backed persistence/RLS, worker/webhook surfaces, and integration tooling should support the four-USP story rather than replace it.
