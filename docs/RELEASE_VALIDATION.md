# Evidence Passport Release Validation — 2026-09-14

This file records the reproducible validation gates for the Evidence Passport™ hardening pass. It does not substitute for production smoke tests against the target Supabase project or for Node 24 validation in CI/deployment.

## Automated repository validation

Run from the repository root under the repository-declared Node 24.x runtime:

```bash
node --version
npm ci
npm run check
npm test
npm run config:check
npm audit --omit=dev --audit-level=high
git diff --check
```

The hardening workspace validation on 14 September 2026 ran under Node `v22.16.0` because Node 24 was not available in the execution environment. `npm run check` and `npm test` passed **60/60 tests**. Runtime-identical Node 24 validation remains a deployment gate rather than an inferred pass.

`npm run config:check` is expected to fail in an unconfigured source workspace because production/server secrets are intentionally absent. A deployment must make it pass with the real environment. In particular, production-like environments now fail closed when `VERITRUST_EVIDENCE_SIGNING_PRIVATE_KEY` is missing.

## Evidence Passport regression coverage

The test suite now covers the provenance and verification invariants behaviorally, including:

- complete trusted package verification versus explicit `PASSPORT_ONLY` partial verification;
- evidence and manifest tampering;
- strict v1 Passport/JWK/signature/digest/ID validation;
- rejection of non-JSON canonicalization values, cycles, and complexity-limit abuse;
- fixed Node/browser canonicalization vectors and Node/browser verification parity;
- mathematical signature validity separated from current VeriTrust issuer trust;
- dedicated production signing-key enforcement and key-rotation/retirement behavior;
- exact normalized evidence persistence, safe idempotent replay, conflicting duplicate rejection, and ambiguous-insert readback;
- persisted-row hydration and duplicated-field consistency checks;
- historical exact-package retrieval across key rotation without re-signing;
- legacy rows reconstructed as unsigned when exact signed evidence is unavailable;
- browser-local verification that performs no evidence POST during the normal flow, plus explicit server fallback;
- issuer-registry outage producing `UNKNOWN` trust rather than a false pass;
- migration/OpenAPI/UI/PDF contract regressions and server-only RLS expectations.

The broader suite continues to cover the unrelated Gateway, SMTP enforcement, model-contract, campaign-memory, GeoTrace, escalation, UI, and PDF behavior.

## Database migration order

Apply migrations in repository order through:

```text
supabase/migrations/20260911_forensic_intelligence.sql
supabase/migrations/20260914_evidence_passport_hardening.sql
```

The hardening migration is additive and forward-only. It adds nullable `evidence_payload` storage for exact normalized evidence on new issuances, deliberately does **not** reconstruct/backfill historical evidence, preflights existing Passport rows before stronger constraints, adds same-tenant/same-scan composite foreign keys, preserves RLS/server-only access, and corrects the retention wording.

The Passport table is **update-protected, not WORM**: UPDATE is blocked, while deletion follows the parent investigation retention/deletion lifecycle. If any preflight detects inconsistent historical data, deployment must stop for investigation; the migration must not silently repair signed history.

## Signing-key deployment boundary

Production-like deployments require a dedicated rotatable Ed25519 private key in `VERITRUST_EVIDENCE_SIGNING_PRIVATE_KEY`. `VERITRUST_EVIDENCE_TRUSTED_KEY_IDS` may retain historical key fingerprints during a rotation window. Removing an old fingerprint from the trusted set changes issuer-trust status only; it must not cause old packages to be re-signed or rewritten.

Private key material must remain server-only and must never be logged, persisted in Evidence Passport rows, or exposed to browser code. The browser verifier fetches only public issuer-trust metadata.

## Browser and API verification boundary

Normal file/paste verification is local-first: the browser parses and validates the package, canonicalizes v1 JSON, computes SHA-256, derives/checks the key fingerprint and Passport ID, and verifies Ed25519 with Web Crypto. Only public trust metadata is fetched. Evidence is sent to VeriTrust only if a user explicitly invokes the disclosed server fallback, or when an API client directly calls the server verification endpoint.

A `valid: true` server/browser result is reserved for a complete package whose required evidence/manifest, signature, key ID, Passport ID, and current issuer-trust checks all pass. Passport-only verification is explicitly partial and cannot become a full valid result.

## Security dependency pins

`package.json` uses npm overrides to keep security-sensitive transitive dependencies on patched release lines:

- `undici` = `8.10.2`
- `nodemailer` = `9.1.1`
- `deepmerge-ts` = `8.0.1`

A regression test verifies these overrides and lockfile resolutions. A connected CI/deployment environment must still execute `npm audit --omit=dev --audit-level=high`; an offline or network-restricted workspace must not fabricate an audit pass.

## Deployment smoke tests

After applying the migration and configuring production keys, validate in order:

1. create a new investigation and confirm its exact evidence payload and Passport are durably stored together;
2. export the signed Evidence JSON and obtain `VERIFIED` from full local verification;
3. tamper evidence and manifest independently and confirm failure;
4. retrieve the same historical investigation repeatedly and confirm Passport ID/signature/key fingerprint are unchanged;
5. exercise a legacy row without `evidence_payload` and confirm it is labeled reconstructed/unsigned rather than re-signed;
6. rotate from key A to key B while A+B are trusted and confirm old A plus new B packages verify;
7. retire A from the trust registry and confirm old A remains mathematically valid but is no longer a trusted issuer;
8. verify RLS still prevents direct `anon`/`authenticated` writes to the Passport table.

## Claim boundary

Passing these gates supports the narrower claim that VeriTrust can package and later verify recorded investigation evidence against SHA-256 digests and an Ed25519 signature while evaluating key identity and issuer trust separately. It does not establish legal admissibility, sender/person identity, attacker identity, message safety, correctness of a phishing verdict, permanent WORM retention, or a cryptographic signature over the PDF bytes themselves.
