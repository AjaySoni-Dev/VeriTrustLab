# SIH26106 Release / Demo Checklist

This checklist is intentionally operational. Complete it against the actual deployment used in front of judges.

## 1. Repository gate

```bash
npm ci
npm run check
npm run config:check
git diff --check
npm audit --omit=dev --audit-level=high
```

`npm audit` needs access to the npm registry. If the build environment is offline, rerun it from the CI/deployment environment before presentation.

## 2. Supabase gate

1. Confirm the existing project contains `organizations`, `gateway_scans`, and `gateway_artifacts` with UUID primary keys matching this application's persistence layer.
2. Apply `supabase/migrations/20260911_forensic_intelligence.sql`.
3. Confirm `email_threat_entities` and `email_evidence_passports` exist with RLS enabled.
4. Confirm anonymous/authenticated browser roles have no direct policies on those tables; service-role server access is used.
5. Perform one real EML investigation and verify that threat entities and one immutable passport row are written.

## 3. Evidence Passport gate

- Configure a dedicated Ed25519 signing key for the SIH deployment when possible.
- Record the active `key_id` shown in a generated passport.
- Export Evidence JSON, verify it at `/verify-evidence`, and demonstrate that changing one byte/value causes verification to fail.
- If rotating a key, keep the retired valid fingerprint in `VERITRUST_EVIDENCE_TRUSTED_KEY_IDS` for packages that must remain verifiable.

## 4. Four-USP judge demo

### USP 1 — Trust-Boundary GeoTrace

1. Upload a copied/original EML and show relay nodes as observed/unverified.
2. Point out that VeriTrust does not call these nodes the attacker's physical location.
3. Submit a message through the trusted SMTP receiver and show the directly observed boundary promoted to `trusted_receiver`.

### USP 2 — Evidence Passport

1. Open the completed investigation.
2. Export Evidence JSON and STIX 2.1.
3. Verify the JSON on `/verify-evidence`.
4. Tamper with a copy and show signature/hash verification fail.

### USP 3 — MailGraph Campaign Memory

1. Scan two prepared messages sharing two durable indicators (for example URL domain + Reply-To domain, or an exact attachment hash).
2. Open the second scan and show the campaign ID and linked prior investigation.
3. Use an ASN-only pair as the negative control; it must not form a campaign.

### USP 4 — Progressive Evidence Escalation

1. Start with pasted text and show Limited evidence plus the EML upgrade action.
2. Upload the original EML and show authentication/identity/attachment/relay evidence appear.
3. Use the trusted receiver to show direct SMTP facts and SPF capability.

## 5. Live-provider gate

- RDAP: perform a scan containing a domain with public registration data and confirm a bounded result or an explicit provider limitation.
- AbuseIPDB: if a key is configured, confirm public-IP reputation appears; if not configured, the UI must say unavailable rather than low risk.
- Infrastructure geolocation: confirm the configured provider returns coordinates for at least one demo relay if GeoTrace mapping is part of the planned demonstration.

## 6. SMTP gate

Run the existing SMTP tests and a live private/LAN path. The bundled listener does not implement inbound STARTTLS; keep it on a trusted private segment/VPN or place a reviewed TLS-capable MTA in front. Never expose it as an unauthenticated public relay.

## 7. Presentation language

Use: **probable/or observed mail infrastructure**, **trusted receiver boundary**, **evidence integrity**, **campaign correlation**, **forensic evidence completeness**.

Do not claim: exact attacker physical location, legal admissibility, malware sandboxing, 100% detection accuracy, or that an unavailable provider/model means an email is safe.
