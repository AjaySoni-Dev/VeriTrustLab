#requires -Version 5.1
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch {}
$Host.UI.RawUI.WindowTitle = 'VeriTrust Lab // Receiver CLI 2.0.1'

$GatewayPort = 2525
$SinkPort = 2526
$SmtpUsername = 'veritrust-sender'
$AllowedDomain = 'lab.local'
$ApiBaseUrl = 'https://www.veritrustlab.in'
$RepoCommit = '4d8dbfec96521782df1993127a0602f86bf80760'
$SaveDir = (Get-Location).Path
$CacheRoot = Join-Path $env:LOCALAPPDATA 'VeriTrust\MailConsole'
$RepoRoot = Join-Path $CacheRoot ('repo-' + $RepoCommit)
$NodeRoot = Join-Path $CacheRoot 'node24'
$CredFile = Join-Path $CacheRoot 'receiver-credentials.json'
$FirewallRuleName = 'VeriTrust SMTP over Tailscale 2525'
$script:Ansi = $false
$script:Esc = [char]27

New-Item -ItemType Directory -Force -Path $CacheRoot | Out-Null

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
        $h=[VeriTrustNative.ConsoleMode]::GetStdHandle(-11);[uint32]$mode=0
        if ([VeriTrustNative.ConsoleMode]::GetConsoleMode($h,[ref]$mode)) {$script:Ansi=[VeriTrustNative.ConsoleMode]::SetConsoleMode($h,($mode -bor 0x0004))}
    } catch {$script:Ansi=$false}
}

function A {
    param([string]$Text,[string]$Rgb='',[switch]$Bold)
    if (-not $script:Ansi) {return $Text}
    $prefix=''; if ($Bold) {$prefix+="$($script:Esc)[1m"}; if ($Rgb) {$prefix+="$($script:Esc)[38;2;$Rgb`m"}
    return "$prefix$Text$($script:Esc)[0m"
}

function Write-Line { param([string]$Text='',[ConsoleColor]$Color=[ConsoleColor]::Gray) Write-Host $Text -ForegroundColor $Color }
function Get-RuleWidth { try {return [Math]::Max(72,[Math]::Min(118,[Console]::WindowWidth-2))} catch {return 92} }
function Write-Rule { param([string]$Rgb='82;82;82') $line='─'*(Get-RuleWidth); if ($script:Ansi) {[Console]::WriteLine((A $line $Rgb))} else {Write-Line ('-'*(Get-RuleWidth)) DarkGray} }

function Write-BrandHeader {
    param([string]$Role,[string]$State='READY',[string]$Detail='')
    Clear-Host
    $logo=@(
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
    $logoRgb=@('0;197;208','0;193;204','0;190;201','0;187;198','0;184;195','0;181;192','0;178;189','0;175;186','0;172;183')
    $meta=@(
        (A 'VeriTrust Lab' '42;219;229' -Bold),
        (A 'SMTP Enforcement CLI 2.0' '210;210;210' -Bold),
        (A $Role '148;148;148'),
        (A 'MailGraph · MailGuard · Gateway Policy' '120;120;120'),
        (A ('State: {0}' -f $State) $(if ($State -eq 'ONLINE' -or $State -eq 'READY') {'73;210;126'} else {'255;190;74'})),
        (A ('Save: {0}' -f $SaveDir) '112;112;112'),
        (A $Detail '112;112;112'),
        '',
        ''
    )
    [Console]::WriteLine('')
    for ($i=0;$i -lt $logo.Count;$i++) {
        if ($script:Ansi) {[Console]::Write((A $logo[$i] $logoRgb[$i]));[Console]::Write((' '*([Math]::Max(2,40-$logo[$i].Length))));[Console]::WriteLine($meta[$i])}
        else {Write-Host $logo[$i] -ForegroundColor Cyan -NoNewline;Write-Host (' '*([Math]::Max(2,40-$logo[$i].Length))) -NoNewline;Write-Host ($meta[$i] -replace '\x1b\[[0-9;]*m','') -ForegroundColor Gray}
    }
    Write-Rule '72;72;72'
}

function Write-Footer {
    Write-Rule '72;72;72'
    if ($script:Ansi) {[Console]::WriteLine((A '?  ' '100;100;100')+(A '/help' '42;219;229')+(A ' for commands  ·  console remains live while mail arrives' '100;100;100'))}
    else {Write-Host '?  ' -ForegroundColor DarkGray -NoNewline;Write-Host '/help' -ForegroundColor Cyan -NoNewline;Write-Host ' for commands  ·  console remains live while mail arrives' -ForegroundColor DarkGray}
}

function Write-Tag {
    param([string]$Tag,[string]$Text,[ValidateSet('ok','warn','bad','info','dim')][string]$Kind='info')
    $rgb=switch($Kind){'ok'{'73;210;126'}'warn'{'255;190;74'}'bad'{'255;99;99'}'dim'{'120;120;120'}default{'42;219;229'}}
    if ($script:Ansi) {[Console]::WriteLine((A (('[{0}]' -f $Tag)) $rgb -Bold)+' '+$Text)}
    else {$c=switch($Kind){'ok'{'Green'}'warn'{'Yellow'}'bad'{'Red'}'dim'{'DarkGray'}default{'Cyan'}};Write-Host ('[{0}]' -f $Tag) -ForegroundColor $c -NoNewline;Write-Host (' '+$Text) -ForegroundColor Gray}
}

function Test-Administrator {
    $principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Restart-ElevatedIfNeeded {
    if (Test-Administrator) {return}
    if (-not $PSCommandPath) {throw 'Run this from the .ps1 file so it can elevate itself.'}
    $args='-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $PSCommandPath
    Start-Process powershell.exe -Verb RunAs -ArgumentList $args -WorkingDirectory (Get-Location).Path | Out-Null
    exit
}

function Find-Tailscale {
    $cmd=Get-Command tailscale.exe -ErrorAction SilentlyContinue;if($cmd){return $cmd.Source}
    foreach($path in @("$env:ProgramFiles\Tailscale\tailscale.exe","${env:ProgramFiles(x86)}\Tailscale\tailscale.exe")){if($path -and (Test-Path -LiteralPath $path)){return $path}}
    return $null
}

function Install-Tailscale {
    Write-Tag 'SETUP' 'Tailscale not found; installing automatically.' 'warn'
    $winget=Get-Command winget.exe -ErrorAction SilentlyContinue
    if($winget){& winget.exe install --id Tailscale.Tailscale -e --source winget --accept-package-agreements --accept-source-agreements --silent | Out-Null;Start-Sleep -Seconds 4;$found=Find-Tailscale;if($found){return $found}}
    $page=Invoke-WebRequest -Uri 'https://pkgs.tailscale.com/stable/' -UseBasicParsing
    $archOrder=if($env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64'){@('arm64','amd64','x86')}elseif($env:PROCESSOR_ARCHITECTURE -eq 'x86'){@('x86')}else{@('amd64','x86')}
    $package=$null
    foreach($arch in $archOrder){$rx=[regex]("tailscale-setup-(?<v>\d+\.\d+\.\d+)-"+[regex]::Escape($arch)+"\.msi");$items=@();foreach($m in $rx.Matches($page.Content)){$items+=[pscustomobject]@{Version=[version]$m.Groups['v'].Value;File=$m.Value}};$package=$items|Sort-Object Version -Descending|Select-Object -First 1;if($package){break}}
    if(-not $package){throw 'Could not locate a compatible official Tailscale MSI.'}
    $msi=Join-Path $env:TEMP $package.File;Invoke-WebRequest -Uri ("https://pkgs.tailscale.com/stable/{0}" -f $package.File) -OutFile $msi -UseBasicParsing
    $install=Start-Process msiexec.exe -ArgumentList ('/i "{0}" /qn /norestart' -f $msi) -Wait -PassThru;if($install.ExitCode -notin @(0,3010)){throw ('Tailscale installation failed with MSI code {0}.' -f $install.ExitCode)}
    Start-Sleep -Seconds 4;$found=Find-Tailscale;if(-not $found){throw 'Tailscale installed but tailscale.exe could not be found.'};return $found
}

function Ensure-Tailscale {
    param([string]$Exe)
    try{$service=Get-Service -Name Tailscale -ErrorAction Stop;if($service.Status -ne 'Running'){Start-Service -Name Tailscale;Start-Sleep -Seconds 2}}catch{}
    $ip=$null;try{$candidate=(& $Exe ip -4 2>$null|Select-Object -First 1);if($candidate){$ip=([string]$candidate).Trim()}}catch{}
    if(-not $ip){Write-Tag 'TAILSCALE' 'Login required. Complete browser login if prompted.' 'warn';& $Exe up --timeout=120s;if($LASTEXITCODE -ne 0){throw 'Tailscale could not connect.'};for($i=0;$i -lt 30 -and -not $ip;$i++){Start-Sleep -Seconds 2;try{$candidate=(& $Exe ip -4 2>$null|Select-Object -First 1);if($candidate){$ip=([string]$candidate).Trim()}}catch{}}}
    if($ip -notmatch '^100\.\d{1,3}\.\d{1,3}\.\d{1,3}$'){throw 'Tailscale did not provide a valid 100.x.x.x IPv4 address.'}
    & $Exe set --shields-up=false | Out-Null;if($LASTEXITCODE -ne 0){throw 'Could not enable incoming Tailscale connections.'}
    return $ip
}

function Repair-FirewallRule {
    Get-NetFirewallRule -DisplayName $FirewallRuleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    try {New-NetFirewallRule -DisplayName $FirewallRuleName -Direction Inbound -Action Allow -Protocol TCP -LocalPort $GatewayPort -RemoteAddress '100.64.0.0/10' -Profile Any -Enabled True | Out-Null}
    catch {& netsh advfirewall firewall delete rule name="$FirewallRuleName" | Out-Null;& netsh advfirewall firewall add rule name="$FirewallRuleName" dir=in action=allow protocol=TCP localport=$GatewayPort remoteip=100.64.0.0/10 profile=any | Out-Null;if($LASTEXITCODE -ne 0){throw 'Could not create the Windows Firewall rule.'}}
}

function Get-Node24 {
    $cmd=Get-Command node.exe -ErrorAction SilentlyContinue;if($cmd){try{$v=& $cmd.Source --version;if($v -match '^v24\.'){return $cmd.Source}}catch{}}
    $cached=Get-ChildItem -LiteralPath $NodeRoot -Filter node.exe -Recurse -ErrorAction SilentlyContinue|Select-Object -First 1;if($cached){try{$v=& $cached.FullName --version;if($v -match '^v24\.'){return $cached.FullName}}catch{}}
    Write-Tag 'SETUP' 'Downloading portable Node.js 24.' 'warn';New-Item -ItemType Directory -Force -Path $NodeRoot|Out-Null
    $index=Invoke-RestMethod -Uri 'https://nodejs.org/dist/index.json';$arm=($env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64');$tag=if($arm){'win-arm64-zip'}else{'win-x64-zip'}
    $release=$index|Where-Object{$_.version -match '^v24\.' -and $_.files -contains $tag}|Select-Object -First 1
    if(-not $release -and $arm){$tag='win-x64-zip';$release=$index|Where-Object{$_.version -match '^v24\.' -and $_.files -contains $tag}|Select-Object -First 1}
    if(-not $release){throw 'Could not locate a compatible Node.js 24 release.'}
    $arch=if($tag -eq 'win-arm64-zip'){'arm64'}else{'x64'};$zipName='node-{0}-win-{1}.zip' -f $release.version,$arch;$zipPath=Join-Path $NodeRoot $zipName
    Invoke-WebRequest -Uri ('https://nodejs.org/dist/{0}/{1}' -f $release.version,$zipName) -OutFile $zipPath -UseBasicParsing;Expand-Archive -LiteralPath $zipPath -DestinationPath $NodeRoot -Force
    $node=Get-ChildItem -LiteralPath $NodeRoot -Filter node.exe -Recurse|Select-Object -First 1;if(-not $node){throw 'Portable Node.js extraction failed.'};return $node.FullName
}

function Get-VeriTrustRepo {
    $server=Join-Path $RepoRoot 'mail-gateway\server.js';$sink=Join-Path $RepoRoot 'mail-gateway\test-receiver.js';if((Test-Path -LiteralPath $server)-and(Test-Path -LiteralPath $sink)){return}
    Write-Tag 'SETUP' 'Downloading pinned VeriTrust SMTP gateway.' 'warn';Remove-Item -LiteralPath $RepoRoot -Recurse -Force -ErrorAction SilentlyContinue
    $zipPath=Join-Path $CacheRoot ('veritrust-{0}.zip' -f $RepoCommit);$extractPath=Join-Path $CacheRoot ('extract-{0}' -f $RepoCommit);Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue;Remove-Item -LiteralPath $extractPath -Recurse -Force -ErrorAction SilentlyContinue
    Invoke-WebRequest -Uri ('https://github.com/AjaySoni-Dev/VeriTrust-Site/archive/{0}.zip' -f $RepoCommit) -OutFile $zipPath -UseBasicParsing;Expand-Archive -LiteralPath $zipPath -DestinationPath $extractPath -Force
    $source=Get-ChildItem -LiteralPath $extractPath -Directory|Select-Object -First 1;if(-not $source){throw 'Downloaded VeriTrust archive could not be extracted.'};Move-Item -LiteralPath $source.FullName -Destination $RepoRoot;Remove-Item -LiteralPath $extractPath -Recurse -Force -ErrorAction SilentlyContinue
    if(-not((Test-Path -LiteralPath $server)-and(Test-Path -LiteralPath $sink))){throw 'Downloaded VeriTrust revision does not contain the SMTP gateway.'}
}

function Read-SecretText {
    param([string]$Prompt)

    $secure = Read-Host $Prompt -AsSecureString
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)

    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }
}

function Protect-Text {
    param([string]$Value)

    $secure = ConvertTo-SecureString $Value -AsPlainText -Force
    return ($secure | ConvertFrom-SecureString)
}

function Unprotect-Text {
    param([string]$Value)

    $secure = ConvertTo-SecureString $Value
    $credential = New-Object System.Net.NetworkCredential('', $secure)
    return $credential.Password
}

function Get-ReceiverCredentials {
    $apiKey=$env:VERITRUST_API_KEY;$secret=$null;if($env:VERITRUST_RECEIVER_SECRET){$secret=$env:VERITRUST_RECEIVER_SECRET}elseif($env:VERITRUST_EMAIL_RECEIVER_SECRET){$secret=$env:VERITRUST_EMAIL_RECEIVER_SECRET}
    if(Test-Path -LiteralPath $CredFile){try{$stored=Get-Content -LiteralPath $CredFile -Raw|ConvertFrom-Json;if(-not $apiKey -and $stored.ApiKey){$apiKey=Unprotect-Text $stored.ApiKey};if(-not $secret -and $stored.ReceiverSecret){$secret=Unprotect-Text $stored.ReceiverSecret}}catch{Write-Tag 'CREDENTIALS' 'Stored values could not be decrypted; asking again.' 'warn'}}
    if(-not $apiKey){$apiKey=Read-SecretText 'Paste VeriTrust Gateway API key'};if($apiKey -notmatch '^vtg_(?:test|live)_[A-Za-z0-9_-]{20,}$'){throw 'Invalid VeriTrust Gateway API key format.'}
    if(-not $secret){$secret=Read-SecretText 'Paste VERITRUST_EMAIL_RECEIVER_SECRET'};if([Text.Encoding]::UTF8.GetByteCount($secret)-lt 32){throw 'VERITRUST_EMAIL_RECEIVER_SECRET must be at least 32 bytes.'}
    @{ApiKey=Protect-Text $apiKey;ReceiverSecret=Protect-Text $secret}|ConvertTo-Json|Set-Content -LiteralPath $CredFile -Encoding UTF8
    return [pscustomobject]@{ApiKey=$apiKey;ReceiverSecret=$secret}
}

function New-SmtpPassword {
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[] 24

    try {
        $rng.GetBytes($bytes)
    }
    finally {
        $rng.Dispose()
    }

    return (-join ($bytes | ForEach-Object { $_.ToString('x2') }))
}

function Start-NodeProcess {
    param([string]$Node,[string]$Script,[string]$WorkingDirectory,[hashtable]$Environment)
    $psi=New-Object System.Diagnostics.ProcessStartInfo;$psi.FileName=$Node;$psi.Arguments=('"{0}"' -f $Script);$psi.WorkingDirectory=$WorkingDirectory;$psi.UseShellExecute=$false;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true;$psi.CreateNoWindow=$true
    foreach($entry in $Environment.GetEnumerator()){$psi.EnvironmentVariables[[string]$entry.Key]=[string]$entry.Value}
    $process=New-Object System.Diagnostics.Process;$process.StartInfo=$psi;if(-not $process.Start()){throw('Could not start {0}' -f $Script)};$process.BeginOutputReadLine();$process.BeginErrorReadLine();return $process
}

function Test-SmtpGreeting {
    param([string]$HostName,[int]$Port)
    $client=New-Object Net.Sockets.TcpClient
    try{$async=$client.BeginConnect($HostName,$Port,$null,$null);if(-not $async.AsyncWaitHandle.WaitOne(6000)){return $false};$client.EndConnect($async);$stream=$client.GetStream();$stream.ReadTimeout=5000;$stream.WriteTimeout=5000;$reader=New-Object IO.StreamReader($stream,[Text.Encoding]::ASCII,$false,1024,$true);$writer=New-Object IO.StreamWriter($stream,[Text.Encoding]::ASCII,1024,$true);$writer.NewLine="`r`n";$writer.AutoFlush=$true;$line=$reader.ReadLine();if($line -notmatch '^220 '){return $false};$writer.WriteLine('QUIT');return $true}catch{return $false}finally{$client.Dispose()}
}

function Get-HeaderValue {
    param(
        [string]$Path,
        [string]$Name
    )

    try {
        $pattern = '^{0}:\s*(.+)$' -f [regex]::Escape($Name)
        $match = Select-String `
            -LiteralPath $Path `
            -Pattern $pattern `
            -CaseSensitive:$false |
            Select-Object -First 1

        if ($match -and $match.Matches.Count -gt 0) {
            return $match.Matches[0].Groups[1].Value.Trim()
        }
    }
    catch {
        # Header extraction is best-effort only.
    }

    return ''
}

function Show-Status {
    param([string]$TailIP,[string]$PairingCode,[int]$ReceivedCount,[string]$LastFile)
    Write-Line '';Write-Tag 'STATUS' 'Receiver session' 'info';Write-Rule
    Write-Line '  State          ONLINE' Green
    Write-Line ('  Tailscale IP   {0}' -f $TailIP) White
    Write-Line ('  SMTP endpoint  {0}:{1}' -f $TailIP,$GatewayPort) White
    Write-Line ('  SMTP user      {0}' -f $SmtpUsername) White
    Write-Line ('  Save folder    {0}' -f $SaveDir) White
    Write-Line ('  Accepted mails {0}' -f $ReceivedCount) White
    if($LastFile){Write-Line ('  Last accepted  {0}' -f (Split-Path -Leaf $LastFile)) White}
    Write-Rule
}

function Show-Pairing {
    param([string]$PairingCode)
    Write-Line '';Write-Tag 'PAIRING' 'Share only this code with the sender.' 'warn';Write-Rule
    if($script:Ansi){[Console]::WriteLine((A $PairingCode '42;219;229' -Bold))}else{Write-Line $PairingCode Cyan}
    try{Set-Clipboard -Value $PairingCode;Write-Tag 'COPIED' 'Pairing code copied to clipboard.' 'ok'}catch{}
    Write-Rule
}

function Show-MailCard {
    param([IO.FileInfo]$File)
    $subject=Get-HeaderValue $File.FullName 'Subject';$from=Get-HeaderValue $File.FullName 'From';$to=Get-HeaderValue $File.FullName 'To'
    Write-Line '';Write-Rule '73;210;126';Write-Tag 'ACCEPTED' 'VeriTrust approved message received.' 'ok'
    Write-Line ('  File     {0}' -f $File.Name) Cyan;Write-Line ('  Time     {0}' -f $File.LastWriteTime) White;Write-Line ('  Size     {0:N0} bytes' -f $File.Length) White
    if($from){Write-Line ('  From     {0}' -f $from) White};if($to){Write-Line ('  To       {0}' -f $to) White};if($subject){Write-Line ('  Subject  {0}' -f $subject) White}
    Write-Line ('  Saved    {0}' -f $File.FullName) DarkGray;Write-Rule '73;210;126'
}

function Show-Help {
    Write-Line '';if($script:Ansi){[Console]::WriteLine((A 'COMMANDS' '42;219;229' -Bold))}else{Write-Line 'COMMANDS' Cyan};Write-Rule
    $rows=@(
        @('/status','Show receiver/network status.'),
        @('/pair','Print + copy the current sender pairing code.'),
        @('/files','List accepted .eml files.'),
        @('/view [file|last]','Display a saved raw EML.'),
        @('/path','Show the directory where accepted mail is saved.'),
        @('/reset-credentials','Delete cached API/receiver credentials for the next run.'),
        @('/clear','Redraw the VeriTrust Lab receiver console.'),
        @('/help','Show this command reference.'),
        @('/quit','Stop gateway + receiver and exit.')
    )
    foreach($r in $rows){Write-Host ('  {0,-24}' -f $r[0]) -ForegroundColor Cyan -NoNewline;Write-Host $r[1] -ForegroundColor Gray};Write-Rule
}

function Clear-InputLine {
    try{$width=[Math]::Max(20,[Console]::WindowWidth-1);[Console]::Write("`r"+(' '*$width)+"`r")}catch{[Console]::Write("`r")}
}

function Draw-Prompt {
    param([string]$Buffer='')
    Clear-InputLine
    if($script:Ansi){[Console]::Write((A '> ' '55;149;255' -Bold)+$Buffer)}else{Write-Host '> ' -ForegroundColor Cyan -NoNewline;[Console]::Write($Buffer)}
}

function Process-ReceiverCommand {
    param([string]$Command,[string]$TailIP,[string]$PairingCode,[ref]$Running,[ref]$LastFile,[int]$ReceivedCount)
    $cmd=$Command.Trim();if(-not $cmd){return}
    switch -Regex ($cmd) {
        '^/(quit|exit|q)$' {$Running.Value=$false;return}
        '^/(help|\?)$' {Show-Help;return}
        '^/status$' {Show-Status $TailIP $PairingCode $ReceivedCount $LastFile.Value;return}
        '^/pair$' {Show-Pairing $PairingCode;return}
        '^/path$' {Write-Tag 'PATH' $SaveDir 'info';return}
        '^/files$' {
            Write-Line '';Write-Tag 'FILES' $SaveDir 'info';Write-Rule
            $files=Get-ChildItem -LiteralPath $SaveDir -Filter '*.eml' -File -ErrorAction SilentlyContinue|Sort-Object LastWriteTime -Descending|Select-Object -First 30
            if(-not $files){Write-Tag 'EMPTY' 'No accepted .eml files yet.' 'warn'}else{$files|ForEach-Object{Write-Line ('  {0,-46} {1,12:N0}  {2}' -f $_.Name,$_.Length,$_.LastWriteTime) White}};Write-Rule;return
        }
        '^/view(?:\s+(.+))?$' {
            $arg=$Matches[1]
            $path=$null
            if(-not $arg -or $arg.Trim().ToLowerInvariant() -eq 'last'){$path=$LastFile.Value}else{$candidate=$arg.Trim().Trim('"').Trim("'");$path=if([IO.Path]::IsPathRooted($candidate)){$candidate}else{Join-Path $SaveDir $candidate}}
            if(-not $path -or -not(Test-Path -LiteralPath $path -PathType Leaf)){Write-Tag 'VIEW' 'Requested EML file was not found.' 'bad';return}
            Write-Line '';Write-Tag 'RAW EML' (Split-Path -Leaf $path) 'info';Write-Rule;Get-Content -LiteralPath $path -Raw|Write-Host;Write-Rule;return
        }
        '^/reset-credentials$' {
            if(Test-Path -LiteralPath $CredFile){Remove-Item -LiteralPath $CredFile -Force;Write-Tag 'CREDENTIALS' 'Cached credentials removed. Restart receiver to enter new values.' 'ok'}else{Write-Tag 'CREDENTIALS' 'No cached credential file exists.' 'warn'};return
        }
        '^/clear$' {Write-BrandHeader -Role 'Receiver Console' -State 'ONLINE' -Detail ('Endpoint {0}:{1}  ·  Accepted {2}' -f $TailIP,$GatewayPort,$ReceivedCount);Write-Line 'Gateway is live. Type /help while incoming mail continues to be monitored.' DarkGray;Write-Footer;return}
        default {Write-Tag 'COMMAND' ('Unknown command: {0}' -f $cmd) 'bad';Write-Line 'Type /help for available commands.' DarkGray;return}
    }
}

Initialize-Terminal
Restart-ElevatedIfNeeded
Write-BrandHeader -Role 'Receiver Console' -State 'INITIALIZING' -Detail 'Persistent SMTP enforcement + live mail monitor'
Write-Tag 'INIT' 'Preparing receiver environment.' 'info'

$ts=Find-Tailscale;if(-not $ts){$ts=Install-Tailscale};Write-Tag 'OK' 'Tailscale available.' 'ok'
$tailIP=Ensure-Tailscale -Exe $ts;Write-Tag 'OK' ('Receiver Tail IP: {0}' -f $tailIP) 'ok'
Repair-FirewallRule;Write-Tag 'OK' ('Windows Firewall: TCP {0} allowed from Tailscale peers.' -f $GatewayPort) 'ok'
$node=Get-Node24;Write-Tag 'OK' ('Node.js {0}' -f (& $node --version)) 'ok'
Get-VeriTrustRepo;Write-Tag 'OK' ('VeriTrust SMTP gateway pinned at {0}' -f $RepoCommit.Substring(0,12)) 'ok'
$credentials=Get-ReceiverCredentials;Write-Tag 'OK' 'Receiver/API credentials loaded and DPAPI protected.' 'ok'

$smtpPassword=New-SmtpPassword
$pairingCode='VTCLI2|{0}|{1}|{2}|{3}|{4}' -f $tailIP,$GatewayPort,$SmtpUsername,$smtpPassword,$AllowedDomain
try{Set-Clipboard -Value $pairingCode}catch{}

$gatewayScript=Join-Path $RepoRoot 'mail-gateway\server.js';$sinkScript=Join-Path $RepoRoot 'mail-gateway\test-receiver.js'
$seen=@{};Get-ChildItem -LiteralPath $SaveDir -Filter '*.eml' -File -ErrorAction SilentlyContinue|ForEach-Object{$seen[$_.FullName]=$true}
$receivedCount=0;$lastFile=$null;$sinkProcess=$null;$gatewayProcess=$null

try {
    $sinkEnv=@{VERITRUST_TEST_RECEIVER_HOST='127.0.0.1';VERITRUST_TEST_RECEIVER_PORT=[string]$SinkPort;VERITRUST_TEST_RECEIVER_OUTPUT=$SaveDir}
    $sinkProcess=Start-NodeProcess $node $sinkScript $RepoRoot $sinkEnv;Start-Sleep -Milliseconds 700;if($sinkProcess.HasExited){throw 'Local downstream receiver exited during startup.'};Write-Tag 'OK' ('Downstream receiver: 127.0.0.1:{0}' -f $SinkPort) 'ok'

    $gatewayEnv=@{
        VERITRUST_API_BASE_URL=$ApiBaseUrl;VERITRUST_API_KEY=$credentials.ApiKey;VERITRUST_RECEIVER_SECRET=$credentials.ReceiverSecret;
        VERITRUST_SMTP_LISTEN_HOST='0.0.0.0';VERITRUST_SMTP_LISTEN_PORT=[string]$GatewayPort;VERITRUST_SMTP_RECEIVER_ID='veritrust-smtp-gateway';VERITRUST_SMTP_AUTHSERV_ID='veritrust-smtp-gateway';
        VERITRUST_SMTP_ALLOWED_CLIENT_IPS='';VERITRUST_SMTP_REQUIRE_AUTH='true';VERITRUST_SMTP_AUTH_USERNAME=$SmtpUsername;VERITRUST_SMTP_AUTH_PASSWORD=$smtpPassword;
        VERITRUST_SMTP_ALLOWED_RECIPIENTS='';VERITRUST_SMTP_ALLOWED_RECIPIENT_DOMAINS=$AllowedDomain;VERITRUST_SMTP_ALLOW_ALL_RECIPIENTS='false';
        VERITRUST_SMTP_UPSTREAM_HOST='127.0.0.1';VERITRUST_SMTP_UPSTREAM_PORT=[string]$SinkPort;VERITRUST_SMTP_UPSTREAM_STARTTLS='off';VERITRUST_SMTP_UPSTREAM_SECURE='false';
        VERITRUST_SMTP_ANALYSIS_TIMEOUT_MS='90000';VERITRUST_SMTP_DEGRADED_MODE='defer';VERITRUST_SMTP_API_FAILURE_MODE='defer';VERITRUST_SMTP_ADD_DECISION_HEADERS='true'
    }
    $gatewayProcess=Start-NodeProcess $node $gatewayScript $RepoRoot $gatewayEnv;Start-Sleep -Seconds 1;if($gatewayProcess.HasExited){throw 'VeriTrust SMTP gateway exited during startup.'}
    if(-not(Test-SmtpGreeting '127.0.0.1' $GatewayPort)){throw ('SMTP gateway started but localhost:{0} did not return a valid SMTP greeting.' -f $GatewayPort)}
    if(-not(Test-SmtpGreeting $tailIP $GatewayPort)){throw ('SMTP gateway started but Tailscale endpoint {0}:{1} did not return a valid SMTP greeting.' -f $tailIP,$GatewayPort)}
    Write-Tag 'OK' ('SMTP enforcement gateway: {0}:{1}' -f $tailIP,$GatewayPort) 'ok'

    Write-BrandHeader -Role 'Receiver Console' -State 'ONLINE' -Detail ('Endpoint {0}:{1}  ·  Save folder ready' -f $tailIP,$GatewayPort)
    Write-Line 'Gateway is live. Incoming approved EML files appear here immediately.' DarkGray
    Show-Pairing $pairingCode
    Write-Footer

    $running=$true;$buffer='';Draw-Prompt $buffer
    while($running){
        if($sinkProcess.HasExited){throw 'The downstream receiver process stopped unexpectedly.'}
        if($gatewayProcess.HasExited){throw 'The VeriTrust gateway process stopped unexpectedly.'}

        $files=Get-ChildItem -LiteralPath $SaveDir -Filter '*.eml' -File -ErrorAction SilentlyContinue|Sort-Object LastWriteTime
        foreach($file in $files){
            if(-not $seen.ContainsKey($file.FullName)){
                $seen[$file.FullName]=$true;$receivedCount++;$lastFile=$file.FullName
                Clear-InputLine;Show-MailCard $file;Draw-Prompt $buffer
            }
        }

        if([Console]::KeyAvailable){
            $key=[Console]::ReadKey($true)
            if($key.Key -eq [ConsoleKey]::Enter){Clear-InputLine;[Console]::WriteLine('');$cmd=$buffer;$buffer='';Process-ReceiverCommand $cmd $tailIP $pairingCode ([ref]$running) ([ref]$lastFile) $receivedCount;if($running){Draw-Prompt $buffer}}
            elseif($key.Key -eq [ConsoleKey]::Backspace){if($buffer.Length -gt 0){$buffer=$buffer.Substring(0,$buffer.Length-1);Draw-Prompt $buffer}}
            elseif($key.Key -eq [ConsoleKey]::Escape){$buffer='';Draw-Prompt $buffer}
            elseif(-not [char]::IsControl($key.KeyChar)){$buffer += $key.KeyChar;[Console]::Write($key.KeyChar)}
        }
        Start-Sleep -Milliseconds 120
    }
}
catch {
    Clear-InputLine;Write-Line '';Write-Rule '255;99;99';Write-Tag 'RECEIVER ERROR' $_.Exception.Message 'bad';Write-Rule '255;99;99';throw
}
finally {
    if($gatewayProcess -and -not $gatewayProcess.HasExited){try{$gatewayProcess.Kill()}catch{}}
    if($sinkProcess -and -not $sinkProcess.HasExited){try{$sinkProcess.Kill()}catch{}}
    $credentials=$null;$smtpPassword=$null
    Write-Line '';Write-Tag 'CLOSED' 'VeriTrust receiver stopped.' 'dim'
}
