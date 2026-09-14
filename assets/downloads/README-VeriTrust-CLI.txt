VeriTrust Lab — Trusted SMTP Demo Package 2.1.0

Purpose
-------
Two-laptop sender → trusted receiver demonstration for SIH26106.

Included
--------
- VeriTrust-Receiver-CLI.ps1
- VeriTrust-Sender-CLI.ps1
- Run-VeriTrust-Receiver.cmd
- Run-VeriTrust-Sender.cmd
- Validate-VeriTrust-CLI.ps1 / .cmd
- mail-gateway/ (version-matched Node runtime)
- VeriTrust-Logo.png

Receiver boundary
-----------------
The receiver requires a VeriTrust API key scoped to gateway:scan and VERITRUST_EMAIL_RECEIVER_SECRET.
The sender receives neither secret; it receives only the short-lived SMTP pairing credential.

Deployment origin
-----------------
VERITRUST_API_BASE_URL can override the default https://www.veritrustlab.in origin before launch.

Demo preparation
----------------
Preinstall/sign in to Tailscale on both laptops and keep Node.js 24 available on the receiver. Automatic setup remains a fallback, not the preferred presentation path.
Do not expose TCP 2525 to the public internet.
