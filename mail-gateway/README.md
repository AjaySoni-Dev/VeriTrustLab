# VeriTrust SMTP Enforcement Gateway

This directory implements the transport-level path requested for VeriTrust:

```text
Sender laptop / mail client
        |
        | SMTP
        v
VeriTrust SMTP Enforcement Gateway (long-running Node process)
        |
        | exact RFC 822 message + trusted SMTP facts over HTTPS
        v
VeriTrust MailGraph / MailGuard / Swift / Gateway correlation
        |
        +--> allow / warn -----------------> relay to downstream SMTP receiver
        |
        +--> manual_review / hold ---------> SMTP 451 back to sender; do not relay
        |
        +--> quarantine / block -----------> SMTP 550 back to sender; do not relay
        |
        +--> API/model failure (default) --> SMTP 451 back to sender; do not relay
```

The SMTP process is deliberately **not** hosted inside Vercel. Vercel serves the existing web/API component, while the SMTP gateway must run on a persistent Windows/Linux machine because it listens on a TCP SMTP port.

## What the gateway preserves and adds

The gateway receives the message before downstream delivery and prepends a standard `Received:` header containing the directly observed client IP, HELO name, receiver ID, event ID and timestamp. It submits that received message to the new server-to-server endpoint `POST /internal/v2/phishing/receiver-eml` together with the same trusted SMTP facts and the separate receiver secret. This activates VeriTrust's `trusted_receiver_event` capability instead of treating the email as merely a saved `.eml` file.

That means the decision can reuse the existing MailGraph stack: bounded MIME parsing; original-message hashing and temporary storage; MailGuard phishing evidence; deterministic forensic content observations; Swift child-URL analysis; SPF at the trusted receiver boundary; DKIM/DMARC/ARC; sender-identity relationships; Received-hop extraction and infrastructure geolocation; attachment metadata intelligence; evidence persistence; Gateway correlation v3; policy enforcement; reports, reviews and cases.

The relay does not invent a second scoring system. The existing VeriTrust policy recommendation remains authoritative. The transport layer only converts that recommendation into SMTP behavior.

## Enforcement behavior

Default mapping:

| VeriTrust recommendation | SMTP action |
| --- | --- |
| `allow`, `warn` | Forward to the configured downstream SMTP server. |
| `manual_review`, `hold` | Return `451 4.7.1` to the sender and do not forward. |
| `quarantine`, `block` | Return `550 5.7.1` to the sender and do not forward. |
| Analysis unavailable / timed out | Return `451 4.7.1` by default and do not forward. |
| Degraded decision | Defer by default, even if the underlying policy recommendation would otherwise forward. |

`VERITRUST_SMTP_FORWARD_ACTIONS`, `VERITRUST_SMTP_DEFER_ACTIONS`, `VERITRUST_SMTP_DEGRADED_MODE` and `VERITRUST_SMTP_API_FAILURE_MODE` can change the transport mapping without changing the core risk engine.

## Security controls

The listener is loopback-only by default. A non-loopback/LAN listener must be restricted either by `VERITRUST_SMTP_ALLOWED_CLIENT_IPS` or by SMTP AUTH, and it also requires an explicit recipient allowlist unless `VERITRUST_SMTP_ALLOW_ALL_RECIPIENTS=true` is deliberately set. For a two-laptop LAN demo, the source-IP allowlist is preferable because the bundled listener does not provide inbound TLS and SMTP AUTH would otherwise expose reusable credentials to the local network. These controls prevent the process from silently becoming an open relay.

The process never logs message bodies, API keys, receiver secrets, SMTP passwords or upstream passwords. Sender-supplied `X-VeriTrust-*` headers are removed before relay, and genuine decision headers are then added by the trusted gateway. The exact received message is still analyzed before this sanitization so spoof attempts remain visible to the forensic pipeline.

Inbound STARTTLS is intentionally not implemented in this self-contained gateway. For LAN deployment, use an isolated trusted network, VPN, SSH tunnel or a TLS terminator in front of the listener. Upstream SMTP supports plaintext, implicit TLS and optional/required STARTTLS, including AUTH PLAIN/LOGIN. Do not expose the plaintext inbound listener directly to the public Internet.

## Required API-side configuration

The existing VeriTrust deployment must already have its normal Gateway/Supabase/model configuration. For this transport path also set:

```text
VERITRUST_EMAIL_RECEIVER_SECRET=<same 32+ byte value used by the SMTP gateway>
VERITRUST_TRUSTED_AUTHSERV_IDS=veritrust-smtp-gateway
```

Create/use a scoped API key with `gateway:scan` permission. The SMTP gateway sends that key only to the configured VeriTrust HTTPS origin.

## Windows / PowerShell deployment

From the repository root:

```powershell
. .\mail-gateway\powershell\VeriTrust.MailGateway.ps1
```

### Two-laptop lab demonstration

A Windows laptop is not automatically an SMTP receiver merely because it has a mail application. For a controlled lab, the project includes a small receiver that saves accepted messages as `.eml` files.

**Laptop B — receiver**

```powershell
. .\mail-gateway\powershell\VeriTrust.MailGateway.ps1
Start-VeriTrustTestReceiver `
  -ListenHost 0.0.0.0 `
  -Port 2526 `
  -OutputDirectory C:\VeriTrustLab\Inbox
```

Allow TCP 2526 through the receiver laptop's firewall only from the gateway machine.

**Gateway machine — intermediary**

```powershell
. .\mail-gateway\powershell\VeriTrust.MailGateway.ps1
Start-VeriTrustMailGateway `
  -ApiKey 'vtg_test_REPLACE_ME' `
  -ReceiverSecret 'REPLACE_WITH_32_PLUS_BYTE_SHARED_SECRET' `
  -ListenHost 0.0.0.0 `
  -ListenPort 2525 `
  -AllowedClientIps '192.168.1.30' `
  -AllowedRecipientDomains 'lab.local' `
  -UpstreamHost '192.168.1.20' `
  -UpstreamPort 2526 `
  -UpstreamStartTls off
```

Allow TCP 2525 through the gateway firewall only from Laptop A.

**Laptop A — sender**

Configure the mail sender/client to use the gateway machine as its outgoing SMTP server, port `2525`, on port `2525`. If you chose SMTP AUTH instead of the recommended source-IP restriction, configure the gateway username/password as well. For a simple source-IP-restricted PowerShell demo:

```powershell
. .\mail-gateway\powershell\VeriTrust.MailGateway.ps1
Send-VeriTrustGatewayTestMail `
  -GatewayHost '192.168.1.10' `
  -GatewayPort 2525 `
  -From 'sender@lab.local' `
  -To 'receiver@lab.local' `
  -Subject 'Gateway test' `
  -Body 'This message should only reach Laptop B after VeriTrust passes it.'
```

If VeriTrust returns `quarantine` or `block`, the send command receives an SMTP error and Laptop B receives nothing. If the message passes with `allow` or `warn`, the downstream receiver gets the message and the saved raw email contains the gateway's `Received:` boundary plus trusted `X-VeriTrust-*` decision headers.

## Production downstream

Replace the bundled test receiver with the real SMTP server that owns the recipient mailbox: Exchange, Postfix, hMailServer, a corporate smart host, or another authorized downstream MTA. Configure its host/port/TLS/authentication using the `VERITRUST_SMTP_UPSTREAM_*` variables in `config.example.env`.

For a production Internet-facing deployment, put a mature MTA/TLS edge in front of this gateway or integrate the same trusted-receiver endpoint into that MTA's content-filter hook. The bundled listener is designed for controlled/private deployment and SIH/demo validation, not as a drop-in public MX daemon.

## Run directly with Node

Set the environment variables from `config.example.env`, then:

```bash
npm run mail-gateway
```

The process emits structured JSON operational logs only. Stop it with `Ctrl+C` or terminate the returned process ID when started through PowerShell.

## Persistent PowerShell CLI

The user-facing Windows integration is published from the web project at:

```text
/assets/powershell/VeriTrust-Receiver-CLI.ps1
/assets/powershell/VeriTrust-Sender-CLI.ps1
/assets/downloads/VeriTrust-Lab-Persistent-CLI.zip
```

The receiver console automates Tailscale setup, the Tailscale-scoped Windows Firewall rule, portable Node.js 24 acquisition, gateway startup, downstream test receiver startup, pairing-code generation, live accepted-mail display, and session cleanup. The sender console pairs once and supports multiple `.eml` submissions in a persistent session.

Use `/gateway-powershell#live-smtp` for the complete operational guide, including the server-side receiver secret and trusted authserv requirements. For a simple demonstration, place both laptops in the same Tailscale tailnet (the same Tailscale account is the easiest option).


## Persistent PowerShell CLI distribution

The repository also ships the validated VeriTrust Lab persistent CLI used by the public `/gateway-powershell#live-smtp` guide. It is an operator-facing wrapper around this SMTP runtime, not a second scoring engine.

Public deployment assets:

- `/assets/powershell/VeriTrust-Receiver-CLI.ps1`
- `/assets/powershell/VeriTrust-Sender-CLI.ps1`
- `/assets/downloads/VeriTrust-Lab-Persistent-CLI.zip`

The receiver performs local prerequisite bootstrapping (Tailscale, firewall rule, portable Node.js when required), starts this runtime plus the bundled downstream test receiver, and prints a session pairing code. The sender keeps a persistent command prompt so multiple `.eml` files can be submitted without repeating setup.

For a two-laptop demo, the easiest configuration is the same Tailscale account/tailnet on both devices. A different-account setup must explicitly share/invite the receiver and allow the sender in tailnet policy. The VeriTrust API key and `VERITRUST_EMAIL_RECEIVER_SECRET` remain receiver-only credentials.
