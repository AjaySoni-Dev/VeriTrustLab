VeriTrust Lab Persistent PowerShell SMTP CLI 2.0.1

QUICKEST START
1. Extract this ZIP into a normal folder.
2. Receiver laptop: double-click Run-VeriTrust-Receiver.cmd.
3. Sender laptop: double-click Run-VeriTrust-Sender.cmd.
4. If Tailscale login is requested, sign both laptops into the same Tailscale account/tailnet for the simplest demo.
5. Receiver: enter the VeriTrust Gateway API key and VERITRUST_EMAIL_RECEIVER_SECRET when requested. These credentials stay on the receiver.
6. Copy the VTCLI2|... pairing code shown by the receiver and paste it once into the sender.
7. At the sender > prompt, type email.eml or /send <file.eml>. Keep sending additional EML files without restarting the console.

AUTOMATIC SETUP
- Tailscale is detected and installed when missing.
- Receiver incoming Tailscale access and Windows Firewall TCP 2525 are configured automatically.
- Portable Node.js 24 is downloaded by the receiver when required.
- The VeriTrust SMTP gateway runtime is downloaded automatically.
- The sender remains persistent after allow, defer, block, malformed-file, or temporary-network outcomes.

SERVER OWNER REQUIREMENTS
- Configure VERITRUST_EMAIL_RECEIVER_SECRET on the deployed VeriTrust API (32+ byte value).
- Configure VERITRUST_TRUSTED_AUTHSERV_IDS=veritrust-smtp-gateway.
- Create a scoped VeriTrust Gateway API key.
- Never share the API key or receiver secret with the sender.

NETWORK
Same Tailscale account/tailnet on both laptops is the easiest configuration. Different accounts require explicit tailnet invitation/device sharing and an access policy that permits sender -> receiver TCP 2525.

SENDER COMMANDS
/send <file.eml>
/files
/status
/check
/pair
/pwd
/cd <path>
/last
/history
/clear
/help
/quit

RECEIVER COMMANDS
/status
/pair
/files
/view last
/view <file.eml>
/path
/reset-credentials
/clear
/help
/quit
