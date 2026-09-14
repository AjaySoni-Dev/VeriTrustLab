#requires -Version 5.1
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch {}
$Host.UI.RawUI.WindowTitle = 'VeriTrust Lab // Sender CLI 2.0.1'

$MaxMessageBytes = (10MB) - 4096
$script:Ansi = $false
$script:Esc = [char]27
$script:LastResult = $null
$script:History = New-Object System.Collections.Generic.List[object]

function Initialize-Terminal {
    try {
        if (-not ('VeriTrustNative.ConsoleMode' -as [type])) {
            Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
namespace VeriTrustNative {
  public static class ConsoleMode {
    [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr GetStdHandle(int nStdHandle);
    [DllImport("kernel32.dll")] public static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);
    [DllImport("kernel32.dll")] public static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);
  }
}
"@ -ErrorAction SilentlyContinue
        }
        $h = [VeriTrustNative.ConsoleMode]::GetStdHandle(-11)
        [uint32]$mode = 0
        if ([VeriTrustNative.ConsoleMode]::GetConsoleMode($h,[ref]$mode)) {
            $script:Ansi = [VeriTrustNative.ConsoleMode]::SetConsoleMode($h,($mode -bor 0x0004))
        }
    } catch { $script:Ansi = $false }
}

function A {
    param([string]$Text,[string]$Rgb='',[switch]$Bold)
    if (-not $script:Ansi) { return $Text }
    $prefix = ''
    if ($Bold) { $prefix += "$($script:Esc)[1m" }
    if ($Rgb) { $prefix += "$($script:Esc)[38;2;$Rgb`m" }
    return "$prefix$Text$($script:Esc)[0m"
}

function Write-Line {
    param([string]$Text = '', [ConsoleColor]$Color = [ConsoleColor]::Gray)
    Write-Host $Text -ForegroundColor $Color
}

function Get-RuleWidth {
    try { return [Math]::Max(72,[Math]::Min(118,[Console]::WindowWidth - 2)) } catch { return 92 }
}

function Write-Rule {
    param([string]$Rgb='82;82;82')
    $line = '─' * (Get-RuleWidth)
    if ($script:Ansi) { [Console]::WriteLine((A $line $Rgb)) } else { Write-Line ('-' * (Get-RuleWidth)) DarkGray }
}

function Write-BrandHeader {
    param([string]$Role,[string]$State='READY',[string]$Detail='')
    Clear-Host
    $logo = @(
        '████████    ████████████████████████',
        '  ████████        ██████  ████████',
        '    ████████      ██████████████',
        '      ████████    ████████████',
        '        ████████  ██████████',
        '          ██████████████',
        '            ████████████',
        '              ████████',
        '                ████'
    )
    $logoRgb = @('0;197;208','0;193;204','0;190;201','0;187;198','0;184;195','0;181;192','0;178;189','0;175;186','0;172;183')
    $meta = @(
        (A 'VeriTrust Lab' '42;219;229' -Bold),
        (A 'SMTP Enforcement CLI 2.0' '210;210;210' -Bold),
        (A $Role '148;148;148'),
        (A 'MailGraph · MailGuard · Gateway Policy' '120;120;120'),
        (A ('State: {0}' -f $State) $(if ($State -eq 'CONNECTED' -or $State -eq 'READY') {'73;210;126'} else {'255;190;74'})),
        (A ('Path: {0}' -f (Get-Location).Path) '112;112;112'),
        (A $Detail '112;112;112'),
        '',
        ''
    )
    [Console]::WriteLine('')
    for ($i=0; $i -lt $logo.Count; $i++) {
        if ($script:Ansi) {
            [Console]::Write((A $logo[$i] $logoRgb[$i]))
            $pad = [Math]::Max(2,40 - $logo[$i].Length)
            [Console]::Write((' ' * $pad))
            [Console]::WriteLine($meta[$i])
        } else {
            Write-Host $logo[$i] -ForegroundColor Cyan -NoNewline
            $pad = [Math]::Max(2,40 - $logo[$i].Length)
            Write-Host (' ' * $pad) -NoNewline
            Write-Host ($meta[$i] -replace '\x1b\[[0-9;]*m','') -ForegroundColor Gray
        }
    }
    Write-Rule '72;72;72'
}

function Write-Footer {
    Write-Rule '72;72;72'
    if ($script:Ansi) {
        [Console]::WriteLine((A '?  ' '100;100;100') + (A '/help' '42;219;229') + (A ' for commands  ·  bare .eml filenames also work' '100;100;100'))
    } else {
        Write-Host '?  ' -ForegroundColor DarkGray -NoNewline; Write-Host '/help' -ForegroundColor Cyan -NoNewline; Write-Host ' for commands  ·  bare .eml filenames also work' -ForegroundColor DarkGray
    }
}

function Write-Prompt {
    if ($script:Ansi) { [Console]::Write((A '> ' '55;149;255' -Bold)) }
    else { Write-Host '> ' -ForegroundColor Cyan -NoNewline }
}

function Write-Tag {
    param([string]$Tag,[string]$Text,[ValidateSet('ok','warn','bad','info','dim')][string]$Kind='info')
    $rgb = switch ($Kind) { 'ok' {'73;210;126'} 'warn' {'255;190;74'} 'bad' {'255;99;99'} 'dim' {'120;120;120'} default {'42;219;229'} }
    if ($script:Ansi) { [Console]::WriteLine((A (('[{0}]' -f $Tag)) $rgb -Bold) + ' ' + $Text) }
    else {
        $c = switch ($Kind) { 'ok' {'Green'} 'warn' {'Yellow'} 'bad' {'Red'} 'dim' {'DarkGray'} default {'Cyan'} }
        Write-Host ('[{0}]' -f $Tag) -ForegroundColor $c -NoNewline; Write-Host (' ' + $Text) -ForegroundColor Gray
    }
}

function Test-Administrator {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Find-Tailscale {
    $cmd = Get-Command tailscale.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($path in @("$env:ProgramFiles\Tailscale\tailscale.exe","${env:ProgramFiles(x86)}\Tailscale\tailscale.exe")) {
        if ($path -and (Test-Path -LiteralPath $path)) { return $path }
    }
    return $null
}

function Restart-ElevatedForInstall {
    if (Test-Administrator) { return }
    if (-not $PSCommandPath) { throw 'Run this from the .ps1 file so it can elevate itself.' }
    $args = '-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $PSCommandPath
    Start-Process powershell.exe -Verb RunAs -ArgumentList $args -WorkingDirectory (Get-Location).Path | Out-Null
    exit
}

function Install-Tailscale {
    Restart-ElevatedForInstall
    Write-Tag 'SETUP' 'Tailscale not found; installing automatically.' 'warn'
    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    if ($winget) {
        & winget.exe install --id Tailscale.Tailscale -e --source winget --accept-package-agreements --accept-source-agreements --silent | Out-Null
        Start-Sleep -Seconds 4
        $found = Find-Tailscale
        if ($found) { return $found }
    }
    $page = Invoke-WebRequest -Uri 'https://pkgs.tailscale.com/stable/' -UseBasicParsing
    $archOrder = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') { @('arm64','amd64','x86') } elseif ($env:PROCESSOR_ARCHITECTURE -eq 'x86') { @('x86') } else { @('amd64','x86') }
    $package = $null
    foreach ($arch in $archOrder) {
        $rx = [regex]("tailscale-setup-(?<v>\d+\.\d+\.\d+)-" + [regex]::Escape($arch) + "\.msi")
        $items = @(); foreach ($m in $rx.Matches($page.Content)) { $items += [pscustomobject]@{Version=[version]$m.Groups['v'].Value;File=$m.Value} }
        $package = $items | Sort-Object Version -Descending | Select-Object -First 1
        if ($package) { break }
    }
    if (-not $package) { throw 'Could not locate a compatible official Tailscale MSI.' }
    $msi = Join-Path $env:TEMP $package.File
    Invoke-WebRequest -Uri ("https://pkgs.tailscale.com/stable/{0}" -f $package.File) -OutFile $msi -UseBasicParsing
    $install = Start-Process msiexec.exe -ArgumentList ('/i "{0}" /qn /norestart' -f $msi) -Wait -PassThru
    if ($install.ExitCode -notin @(0,3010)) { throw ('Tailscale installation failed with MSI code {0}.' -f $install.ExitCode) }
    Start-Sleep -Seconds 4
    $found = Find-Tailscale
    if (-not $found) { throw 'Tailscale installed but tailscale.exe could not be found.' }
    return $found
}

function Ensure-Tailscale {
    param([Parameter(Mandatory)][string]$Exe)
    try {
        $service = Get-Service -Name Tailscale -ErrorAction Stop
        if ($service.Status -ne 'Running') { if (-not (Test-Administrator)) { Restart-ElevatedForInstall }; Start-Service -Name Tailscale; Start-Sleep -Seconds 2 }
    } catch {}
    $ip = $null
    try { $candidate = (& $Exe ip -4 2>$null | Select-Object -First 1); if ($candidate) { $ip = ([string]$candidate).Trim() } } catch {}
    if (-not $ip) {
        Write-Tag 'TAILSCALE' 'Login required. Use the same/shared tailnet as the receiver.' 'warn'
        & $Exe up --timeout=120s
        if ($LASTEXITCODE -ne 0) { throw 'Tailscale could not connect.' }
        for ($i=0; $i -lt 30 -and -not $ip; $i++) { Start-Sleep -Seconds 2; try { $candidate = (& $Exe ip -4 2>$null | Select-Object -First 1); if ($candidate) { $ip = ([string]$candidate).Trim() } } catch {} }
    }
    if ($ip -notmatch '^100\.\d{1,3}\.\d{1,3}\.\d{1,3}$') { throw 'Tailscale did not provide a valid 100.x.x.x IPv4 address.' }
    return $ip
}

function Test-PeerKnown {
    param([string]$Exe,[string]$ReceiverIP,[string]$SenderIP)
    if ($ReceiverIP -eq $SenderIP) { return [pscustomobject]@{Known=$true;Local=$true;Detail='same laptop'} }
    try {
        $jsonText = (& $Exe status --json 2>$null | Out-String)
        if ($jsonText) {
            $status = $jsonText | ConvertFrom-Json
            foreach ($property in $status.Peer.PSObject.Properties) {
                $peer = $property.Value
                foreach ($peerIP in @($peer.TailscaleIPs)) {
                    if ([string]$peerIP -eq $ReceiverIP) {
                        $name = if ($peer.HostName) {[string]$peer.HostName} elseif ($peer.DNSName) {[string]$peer.DNSName} else {'receiver peer'}
                        return [pscustomobject]@{Known=$true;Local=$false;Detail=$name}
                    }
                }
            }
        }
    } catch {}
    return [pscustomobject]@{Known=$false;Local=$false;Detail='no matching peer'}
}

function Test-TcpPort {
    param([string]$HostName,[int]$Port,[int]$TimeoutMs=6000)
    $client = New-Object Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($HostName,$Port,$null,$null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs)) { return $false }
        $client.EndConnect($async); return $true
    } catch { return $false } finally { $client.Dispose() }
}

function Read-SmtpResponse {
    param([IO.StreamReader]$Reader,[switch]$Quiet)
    $lines = New-Object System.Collections.Generic.List[string]
    do {
        $line = $Reader.ReadLine(); if ($null -eq $line) { throw 'SMTP server closed the connection unexpectedly.' }
        $lines.Add($line)
        if (-not $Quiet) { Write-Tag 'SMTP' ('< ' + $line) 'dim' }
        if ($line -notmatch '^(\d{3})([ -])') { throw ('Malformed SMTP response: {0}' -f $line) }
        $code=[int]$Matches[1]; $done=$Matches[2] -eq ' '
    } until ($done)
    return [pscustomobject]@{Code=$code;Final=$lines[$lines.Count-1];Lines=$lines.ToArray()}
}

function Send-SmtpCommand {
    param([IO.StreamWriter]$Writer,[IO.StreamReader]$Reader,[string]$Command,[int[]]$Expected,[switch]$Secret,[switch]$Quiet)
    if (-not $Quiet) { Write-Tag 'SMTP' $(if ($Secret) {'> AUTH PLAIN ********'} else {'> ' + $Command}) 'dim' }
    $Writer.WriteLine($Command); $Writer.Flush(); $response=Read-SmtpResponse -Reader $Reader -Quiet:$Quiet
    if ($Expected -notcontains $response.Code) { throw $response.Final }
    return $response
}

function Send-EmlData {
    param([IO.Stream]$Stream,[string]$Path)
    $latin1=[Text.Encoding]::GetEncoding(28591); $bytes=[IO.File]::ReadAllBytes($Path)
    $text=$latin1.GetString($bytes).Replace("`r`n","`n").Replace("`r","`n"); $lines=[regex]::Split($text,"`n"); $count=$lines.Count
    if ($text.EndsWith("`n") -and $count -gt 0 -and $lines[$count-1] -eq '') { $count-- }
    for ($i=0;$i -lt $count;$i++) { $line=$lines[$i]; if ($line.StartsWith('.')) {$line='.'+$line}; $out=$latin1.GetBytes($line+"`r`n"); $Stream.Write($out,0,$out.Length) }
    if ($count -eq 0) { $blank=[Text.Encoding]::ASCII.GetBytes("`r`n"); $Stream.Write($blank,0,$blank.Length) }
    $end=[Text.Encoding]::ASCII.GetBytes(".`r`n"); $Stream.Write($end,0,$end.Length); $Stream.Flush()
}

function Resolve-EmlPath {
    param([string]$InputText)
    $value=$InputText.Trim(); if ($value.StartsWith('/send ',[StringComparison]::OrdinalIgnoreCase)) {$value=$value.Substring(6).Trim()}; if ($value.StartsWith('send ',[StringComparison]::OrdinalIgnoreCase)) {$value=$value.Substring(5).Trim()}
    $value=$value.Trim('"').Trim("'"); if (-not $value) { return $null }
    $path = if ([IO.Path]::IsPathRooted($value)) {$value} else {Join-Path (Get-Location).Path $value}
    try {$path=[IO.Path]::GetFullPath($path)} catch {return $null}
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {return $null}
    if ([IO.Path]::GetExtension($path).ToLowerInvariant() -ne '.eml') {return $null}
    return $path
}

function Parse-PairingCode {
    param([string]$Code)
    $parts=$Code.Trim() -split '\|'
    if ($parts.Count -ne 6 -or $parts[0] -notin @('VTCLI2','VTUI1')) { throw 'Invalid pairing code. Use the code shown by the VeriTrust receiver.' }
    [int]$port=0; if (-not [int]::TryParse($parts[2],[ref]$port) -or $port -lt 1 -or $port -gt 65535) {throw 'Pairing code contains an invalid SMTP port.'}
    if ($parts[1] -notmatch '^100\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {throw 'Pairing code does not contain a valid Tailscale IP.'}
    if (-not $parts[3] -or $parts[4].Length -lt 12) {throw 'Pairing code contains invalid SMTP credentials.'}
    if ($parts[5] -notmatch '^[A-Za-z0-9.-]+$') {throw 'Pairing code contains an invalid recipient domain.'}
    return [pscustomobject]@{ReceiverIP=$parts[1];Port=$port;Username=$parts[3];Password=$parts[4];Domain=$parts[5].ToLowerInvariant()}
}

function Show-Help {
    Write-Line ''
    if ($script:Ansi) { [Console]::WriteLine((A 'COMMANDS' '42;219;229' -Bold)) } else { Write-Line 'COMMANDS' Cyan }
    Write-Rule
    $rows = @(
        @('/send <file.eml>','Send an EML file. Relative and absolute paths work.'),
        @('/files','List .eml files in the current directory.'),
        @('/status','Show network, pairing and transaction counters.'),
        @('/check','Re-test Tailscale peer + SMTP endpoint.'),
        @('/pair','Replace the current receiver pairing code.'),
        @('/pwd','Show the current working directory.'),
        @('/cd <path>','Change the working directory used for relative file names.'),
        @('/last','Show the last VeriTrust decision.'),
        @('/history','Show recent send decisions for this session.'),
        @('/clear','Redraw the VeriTrust Lab console.'),
        @('/help','Show command reference.'),
        @('/quit','Exit the sender console.')
    )
    foreach ($r in $rows) { Write-Host ('  {0,-22}' -f $r[0]) -ForegroundColor Cyan -NoNewline; Write-Host $r[1] -ForegroundColor Gray }
    Write-Rule
}

function Show-Status {
    param($Pairing,[string]$SenderIP,[string]$ConnectHost,[int]$Sent,[int]$Allowed,[int]$Blocked,[int]$Deferred)
    Write-Line ''; Write-Tag 'STATUS' 'Sender session' 'info'; Write-Rule
    Write-Line ('  Sender Tail IP : {0}' -f $SenderIP) White
    Write-Line ('  Receiver       : {0}:{1}' -f $ConnectHost,$Pairing.Port) White
    Write-Line ('  SMTP user      : {0}' -f $Pairing.Username) White
    Write-Line ('  Domain         : {0}' -f $Pairing.Domain) White
    Write-Line ('  Working path   : {0}' -f (Get-Location).Path) White
    Write-Line ('  Transactions   : {0}' -f $Sent) White
    Write-Line ('  Allowed        : {0}' -f $Allowed) Green
    Write-Line ('  Deferred       : {0}' -f $Deferred) Yellow
    Write-Line ('  Blocked        : {0}' -f $Blocked) Red
    Write-Rule
}

function Send-OneFile {
    param([string]$Path,$Pairing,[string]$ConnectHost)
    $file=Get-Item -LiteralPath $Path; if ($file.Length -gt $MaxMessageBytes) {throw ('{0} exceeds the VeriTrust SMTP message limit.' -f $file.Name)}
    $mailFrom='sender@{0}' -f $Pairing.Domain; $mailTo='receiver@{0}' -f $Pairing.Domain
    $client=New-Object Net.Sockets.TcpClient; $client.ReceiveTimeout=180000; $client.SendTimeout=180000
    Write-Line ''; Write-Rule '0;157;167'; Write-Tag 'SEND' $file.Name 'info'; Write-Line ('  size      {0:N0} bytes' -f $file.Length) DarkGray; Write-Line ('  endpoint  {0}:{1}' -f $ConnectHost,$Pairing.Port) DarkGray; Write-Rule
    try {
        $client.Connect($ConnectHost,$Pairing.Port); $stream=$client.GetStream(); $stream.ReadTimeout=180000; $stream.WriteTimeout=180000
        $reader=New-Object IO.StreamReader($stream,[Text.Encoding]::ASCII,$false,4096,$true); $writer=New-Object IO.StreamWriter($stream,[Text.Encoding]::ASCII,4096,$true); $writer.NewLine="`r`n"; $writer.AutoFlush=$true
        $greeting=Read-SmtpResponse -Reader $reader -Quiet; if ($greeting.Code -ne 220) {throw $greeting.Final}
        Send-SmtpCommand $writer $reader 'EHLO veritrust-cli-sender' @(250) -Quiet | Out-Null
        $authPayload="`0$($Pairing.Username)`0$($Pairing.Password)"; $authToken=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($authPayload))
        Send-SmtpCommand $writer $reader ('AUTH PLAIN {0}' -f $authToken) @(235) -Secret -Quiet | Out-Null
        Send-SmtpCommand $writer $reader ('MAIL FROM:<{0}>' -f $mailFrom) @(250) -Quiet | Out-Null
        Send-SmtpCommand $writer $reader ('RCPT TO:<{0}>' -f $mailTo) @(250,251) -Quiet | Out-Null
        Send-SmtpCommand $writer $reader 'DATA' @(354) -Quiet | Out-Null
        Write-Tag 'ANALYZE' 'Uploading raw EML; waiting for VeriTrust policy decision…' 'warn'
        Send-EmlData $stream $Path; $decision=Read-SmtpResponse -Reader $reader -Quiet; try {$writer.WriteLine('QUIT');$writer.Flush()} catch {}
        $label='UNKNOWN';$kind='dim'
        if ($decision.Code -ge 200 -and $decision.Code -lt 300) {$label='ALLOWED';$kind='ok'} elseif ($decision.Code -ge 400 -and $decision.Code -lt 500) {$label='DEFERRED';$kind='warn'} elseif ($decision.Code -ge 500) {$label='BLOCKED';$kind='bad'}
        Write-Tag $label $decision.Final $kind; Write-Rule
        return [pscustomobject]@{Time=Get-Date;File=$file.Name;Label=$label;Code=$decision.Code;Message=$decision.Final}
    } finally { $client.Dispose() }
}

Initialize-Terminal
Write-BrandHeader -Role 'Sender Console' -State 'INITIALIZING' -Detail 'Persistent multi-message session'
Write-Tag 'INIT' 'Preparing sender environment.' 'info'
$ts=Find-Tailscale; if (-not $ts) {$ts=Install-Tailscale}; Write-Tag 'OK' 'Tailscale available.' 'ok'
$senderIP=Ensure-Tailscale -Exe $ts; Write-Tag 'OK' ('Sender Tail IP: {0}' -f $senderIP) 'ok'

$pairing=$null; $connectHost=$null; $sent=0; $allowed=0; $blocked=0; $deferred=0

function Connect-Pairing {
    param([string]$InitialCode='')
    $code=$InitialCode; if (-not $code) { Write-Host 'pair> ' -ForegroundColor Cyan -NoNewline; $code=Read-Host }
    $parsed=Parse-PairingCode $code; $peer=Test-PeerKnown $ts $parsed.ReceiverIP $senderIP
    if (-not $peer.Known) {throw ('Tailscale reports no matching peer for {0}. Put both laptops in the same/shared tailnet.' -f $parsed.ReceiverIP)}
    $target=if ($peer.Local) {'127.0.0.1'} else {$parsed.ReceiverIP}
    Write-Tag 'PAIR' ('Receiver: {0} ({1})' -f $target,$peer.Detail) 'info'
    if (-not (Test-TcpPort $target $parsed.Port 7000)) {throw ('SMTP endpoint {0}:{1} is unreachable.' -f $target,$parsed.Port)}
    Write-Tag 'OK' 'Receiver SMTP endpoint reachable.' 'ok'
    return [pscustomobject]@{Pairing=$parsed;ConnectHost=$target}
}

while (-not $pairing) {
    try { Write-Line ''; Write-Line 'Paste the pairing code shown by the VeriTrust receiver.' Yellow; $c=Connect-Pairing; $pairing=$c.Pairing; $connectHost=$c.ConnectHost }
    catch { Write-Tag 'PAIRING ERROR' $_.Exception.Message 'bad' }
}

Write-BrandHeader -Role 'Sender Console' -State 'CONNECTED' -Detail ('Receiver {0}:{1}  ·  Sender {2}' -f $connectHost,$pairing.Port,$senderIP)
Write-Line 'Type a .eml filename or use /send. The session stays open after every decision.' DarkGray
Write-Footer

$running=$true
while ($running) {
    Write-Prompt; $inputText=Read-Host; if ($null -eq $inputText) {continue}; $command=$inputText.Trim(); if (-not $command) {continue}
    switch -Regex ($command) {
        '^/(quit|exit|q)$' {$running=$false;continue}
        '^/(help|\?)$' {Show-Help;continue}
        '^/clear$' {Write-BrandHeader -Role 'Sender Console' -State 'CONNECTED' -Detail ('Receiver {0}:{1}  ·  Sender {2}' -f $connectHost,$pairing.Port,$senderIP);Write-Line 'Type a .eml filename or use /send. The session stays open after every decision.' DarkGray;Write-Footer;continue}
        '^/status$' {Show-Status $pairing $senderIP $connectHost $sent $allowed $blocked $deferred;continue}
        '^/pwd$' {Write-Tag 'PATH' (Get-Location).Path 'info';continue}
        '^/files$' {
            Write-Line ''; Write-Tag 'FILES' (Get-Location).Path 'info'; Write-Rule
            $files=Get-ChildItem -LiteralPath (Get-Location).Path -Filter '*.eml' -File -ErrorAction SilentlyContinue | Sort-Object Name
            if (-not $files) {Write-Tag 'EMPTY' 'No .eml files found.' 'warn'} else {$files|ForEach-Object {Write-Line ('  {0,-46} {1,12:N0} bytes' -f $_.Name,$_.Length) White}}; Write-Rule;continue
        }
        '^/cd\s+(.+)$' {
            $dest=$Matches[1].Trim().Trim('"').Trim("'"); try {Set-Location -LiteralPath $dest;Write-Tag 'PATH' (Get-Location).Path 'ok'} catch {Write-Tag 'PATH ERROR' $_.Exception.Message 'bad'};continue
        }
        '^/pair$' {
            try {Write-Line 'Paste the new pairing code.' Yellow;$n=Connect-Pairing;$pairing=$n.Pairing;$connectHost=$n.ConnectHost;Write-Tag 'OK' 'Pairing replaced.' 'ok'} catch {Write-Tag 'PAIRING ERROR' $_.Exception.Message 'bad'};continue
        }
        '^/check$' {
            $peer=Test-PeerKnown $ts $pairing.ReceiverIP $senderIP
            if (-not $peer.Known) {Write-Tag 'TAILSCALE' 'Receiver peer is not visible.' 'bad'} elseif (Test-TcpPort $connectHost $pairing.Port 7000) {Write-Tag 'CHECK' ('{0}:{1} reachable.' -f $connectHost,$pairing.Port) 'ok'} else {Write-Tag 'CHECK' ('{0}:{1} not reachable.' -f $connectHost,$pairing.Port) 'bad'};continue
        }
        '^/last$' {
            if (-not $script:LastResult) {Write-Tag 'LAST' 'No message has been sent yet.' 'warn'} else {Write-Tag $script:LastResult.Label ('{0} · {1}' -f $script:LastResult.File,$script:LastResult.Message) $(if ($script:LastResult.Label -eq 'ALLOWED') {'ok'} elseif ($script:LastResult.Label -eq 'BLOCKED') {'bad'} else {'warn'})};continue
        }
        '^/history$' {
            Write-Line '';Write-Tag 'HISTORY' 'Recent decisions' 'info';Write-Rule
            if ($script:History.Count -eq 0) {Write-Tag 'EMPTY' 'No transactions yet.' 'warn'} else {foreach ($h in ($script:History | Select-Object -Last 20)) {Write-Line ('  {0:HH:mm:ss}  {1,-26} {2,-9} {3}' -f $h.Time,$h.File,$h.Label,$h.Code) White}};Write-Rule;continue
        }
    }

    $path=Resolve-EmlPath $command
    if (-not $path) {Write-Tag 'INPUT' ('File not found or not .eml: {0}' -f $command) 'bad';Write-Line 'Use /files or /send <path.eml>.' DarkGray;continue}
    try {
        if (-not (Test-TcpPort $connectHost $pairing.Port 5000)) {throw ('Receiver SMTP endpoint {0}:{1} is offline or blocked.' -f $connectHost,$pairing.Port)}
        $sent++;$result=Send-OneFile $path $pairing $connectHost;$script:LastResult=$result;$script:History.Add($result)
        switch ($result.Label) {'ALLOWED' {$allowed++} 'BLOCKED' {$blocked++} 'DEFERRED' {$deferred++}}
    } catch {Write-Tag 'TRANSACTION ERROR' $_.Exception.Message 'bad';Write-Line 'Session remains active. Fix the issue and send another file.' DarkGray}
}

Write-Line '';Write-Rule;Write-Tag 'CLOSED' 'VeriTrust sender session ended.' 'dim';Write-Line ('Transactions {0} · Allowed {1} · Deferred {2} · Blocked {3}' -f $sent,$allowed,$deferred,$blocked) Gray
