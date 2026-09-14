# Deployment

## Target

The repository is structured for Vercel serverless entry points plus the existing VeriTrust Gateway worker and Supabase persistence contract. The optional SMTP enforcement path is a separate long-running Node process because Vercel cannot host a persistent SMTP TCP listener.

## Database

Use the existing compatible VeriTrust Supabase schema. Apply forward migrations in order:

```text
supabase/migrations/20260911_forensic_intelligence.sql
supabase/migrations/20260914_evidence_passport_hardening.sql
```

The hardening migration is additive: it adds nullable exact `evidence_payload` storage for new issuances, preflights historical Passport rows, adds strict representation checks and same-tenant/same-scan composite foreign keys, preserves server-only RLS, and updates misleading immutability wording. It never backfills reconstructed evidence or rebuilds production tables. If preflight finds inconsistent historical rows, stop deployment and investigate; do not silently repair signed history.

## Required configuration

Exact requirements depend on enabled modules and integrations. Common configuration includes Supabase URL/keys, provider/model credentials, site/origin policy, Gateway worker credentials, email receiver secret/trusted authserv IDs, and optional infrastructure geolocation configuration.

For the forensic-intelligence USPs:

```text
# REQUIRED in production-like runtimes: dedicated rotatable Ed25519 PKCS#8 private key.
# Development/test may use the purpose-separated fallback; production fails closed if absent.
VERITRUST_EVIDENCE_SIGNING_PRIVATE_KEY=<PKCS8 Ed25519 PEM>

# Comma-separated historical/current key fingerprints accepted during verification.
# The active signing key is automatically trusted; add retired-but-valid fingerprints
# here during controlled signing-key rotation.
VERITRUST_EVIDENCE_TRUSTED_KEY_IDS=ed25519:<24-hex>,ed25519:<24-hex>

# RDAP is enabled by default through rdap.org. Set to off to disable explicitly.
VERITRUST_RDAP_PROVIDER=rdap.org

# Optional. Without this key, IP reputation is shown as unavailable, never benign.
ABUSEIPDB_API_KEY=<server-side key>
```

Never expose these values to browser-delivered JavaScript or logs. The browser verifier receives only public key/trusted-key metadata. Never put service-role or provider secrets into browser-delivered JavaScript.

## Module configuration

`config/modules.json` is the product-surface source of truth. The focused deployment enables email/phishing, Link Intelligence and Gateway correlation while the legacy deepfake product surface is disabled.

## Validation

Before deployment, copy `.env.example` into your secret-management/deployment workflow (do not commit the filled file), apply the migrations in order, configure the dedicated production Ed25519 key plus the active/historical trusted-key IDs, and run:

```bash
npm ci
npm run check
npm run config:check
npm audit --omit=dev --audit-level=high
git diff --check
```

Also verify the deployment environment can access the intended Supabase schema, model providers, storage buckets, worker and optional geolocation provider. Local static/unit verification cannot prove external service credentials or the live database are correctly configured.

## Security headers

Do not weaken the Vercel CSP/HSTS/frame/referrer/permissions/cross-origin controls to accommodate a new client dependency. Prefer same-origin or deliberately reviewed integrations.

## Retention

Raw EML storage is private and policy-bound when enabled. Preserve retention, legal-hold and deletion semantics already defined by the deployed data contract.

## SMTP gateway deployment

The transport service is under `mail-gateway/` and is excluded from the Vercel deployment bundle. Deploy the web/API normally, then run the SMTP process on the intermediary Windows/Linux host. Configure the same `VERITRUST_EMAIL_RECEIVER_SECRET` value on the API and `VERITRUST_RECEIVER_SECRET` on the SMTP process, and include the gateway's authserv ID in `VERITRUST_TRUSTED_AUTHSERV_IDS`. Use a scoped API key with `gateway:scan`.

For LAN exposure, restrict the SMTP listener by source-IP allowlist or SMTP AUTH and always configure a recipient allowlist to prevent open relay behavior. Prefer source-IP restriction on the bundled plaintext listener; use a TLS-capable edge before relying on reusable SMTP credentials. Inbound STARTTLS is not implemented in the bundled listener; keep it on a trusted private segment/VPN or place a reviewed TLS-capable MTA/terminator in front. Upstream delivery supports implicit TLS or STARTTLS.

Use `mail-gateway/powershell/VeriTrust.MailGateway.ps1` for Windows startup, connectivity testing and the bundled two-laptop test receiver. See `mail-gateway/README.md` for the exact topology and commands.


## Persistent Windows PowerShell SMTP CLI

The public PowerShell guide at `/gateway-powershell#live-smtp` exposes the validated persistent sender/receiver CLI. The canonical public assets are:

- `/assets/downloads/VeriTrust-Lab-Persistent-CLI.zip` — complete Windows CLI package;
- `/assets/powershell/VeriTrust-Receiver-CLI.ps1` — receiver/gateway console;
- `/assets/powershell/VeriTrust-Sender-CLI.ps1` — persistent sender console;
- `/assets/downloads/veritrust-cli-manifest.json` — release version and SHA-256 values.

The scripts preserve the live SMTP enforcement architecture already documented above. The receiver automatically installs or activates Tailscale when required, disables Tailscale shields-up for the receiver, creates a Tailscale-scoped inbound Windows Firewall rule for TCP 2525, downloads portable Node.js 24 when needed, obtains the SMTP gateway runtime, generates a session SMTP password, and emits a `VTCLI2|...` pairing code. The sender pairs once and can submit multiple `.eml` files without restarting the session.

For the simplest two-laptop demonstration, sign both laptops into the same Tailscale account/tailnet. Different identities are valid only when the receiver is shared/invited into a tailnet whose policy permits the sender. Same-laptop testing is supported by running receiver and sender in separate PowerShell windows; the sender automatically uses loopback when the pairing IP matches its own Tailscale IP.

Receiver-only server trust still requires deployment configuration and is intentionally never transferred to the sender:

```text
VERITRUST_EMAIL_RECEIVER_SECRET=<32+ byte shared receiver secret>
VERITRUST_TRUSTED_AUTHSERV_IDS=veritrust-smtp-gateway
```

Use a scoped VeriTrust API key with Gateway scan permission. The sender receives only the short-lived SMTP pairing code, not the API key or receiver secret.

## Evidence Passport deployment sequence

Deploy USP 1 in this order: review/back up the target database under the normal process; apply the forward hardening migration; verify its preflights, constraints and RLS; configure the dedicated production Ed25519 key; configure active/historical trusted fingerprints; deploy backend/API; deploy the local-first browser verifier/UI; then run a new-package smoke test, evidence/manifest tamper test, historical/legacy retrieval test and key-rotation test. Do not treat the feature as deployed until those environment-specific checks succeed.
