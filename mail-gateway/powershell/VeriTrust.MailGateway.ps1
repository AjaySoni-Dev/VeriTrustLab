#requires -Version 5.1
Set-StrictMode -Version 2.0

function Get-VeriTrustMailGatewayServerPath {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string] $ProjectRoot = ''
    )

    if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
        $ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    }
    $ServerPath = Join-Path $ProjectRoot 'mail-gateway\server.js'
    if (-not (Test-Path -LiteralPath $ServerPath -PathType Leaf)) {
        throw "VeriTrust SMTP Gateway server.js was not found at $ServerPath"
    }
    return (Resolve-Path -LiteralPath $ServerPath).Path
}

function Start-VeriTrustNodeProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $ScriptPath,

        [Parameter(Mandatory)]
        [hashtable] $Environment,

        [Parameter()]
        [switch] $Wait
    )

    $Node = Get-Command node -ErrorAction Stop
    $StartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $StartInfo.FileName = $Node.Source
    $StartInfo.Arguments = '"{0}"' -f $ScriptPath
    $StartInfo.WorkingDirectory = Split-Path -Parent (Split-Path -Parent $ScriptPath)
    $StartInfo.UseShellExecute = $false
    $StartInfo.RedirectStandardOutput = $false
    $StartInfo.RedirectStandardError = $false
    $StartInfo.CreateNoWindow = $false

    foreach ($Entry in $Environment.GetEnumerator()) {
        if ($null -ne $Entry.Value -and -not [string]::IsNullOrWhiteSpace([string] $Entry.Value)) {
            $StartInfo.EnvironmentVariables[[string] $Entry.Key] = [string] $Entry.Value
        }
    }

    $Process = New-Object System.Diagnostics.Process
    $Process.StartInfo = $StartInfo
    if (-not $Process.Start()) { throw 'Node process could not be started.' }
    if ($Wait) {
        $Process.WaitForExit()
        if ($Process.ExitCode -ne 0) { throw "VeriTrust process exited with code $($Process.ExitCode)." }
        return
    }
    [PSCustomObject] @{
        ProcessId = $Process.Id
        Script    = $ScriptPath
        StartedAt = [DateTimeOffset]::Now
    }
}

function Start-VeriTrustMailGateway {
    <#
    .SYNOPSIS
    Starts the Windows/Node SMTP enforcement gateway that sits between a sender and a downstream SMTP receiver.

    .DESCRIPTION
    The listener accepts SMTP, submits each message to the VeriTrust trusted-receiver API, and only relays
    messages whose Gateway recommendation is configured for forwarding. It is intentionally separate from
    the Vercel web application because SMTP requires a long-running TCP listener.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^vtg_(live|test)_[A-Za-z0-9_-]{20,}$')]
        [string] $ApiKey,

        [Parameter(Mandatory)]
        [ValidateLength(32, 4096)]
        [string] $ReceiverSecret,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $ApiBaseUrl = 'https://www.veritrustlab.in',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $ListenHost = '127.0.0.1',

        [Parameter()]
        [ValidateRange(1, 65535)]
        [int] $ListenPort = 2525,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $UpstreamHost,

        [Parameter()]
        [ValidateRange(1, 65535)]
        [int] $UpstreamPort = 25,

        [Parameter()]
        [ValidateSet('off', 'auto', 'required')]
        [string] $UpstreamStartTls = 'auto',

        [Parameter()]
        [switch] $UpstreamSecure,

        [Parameter()]
        [string] $UpstreamUsername = '',

        [Parameter()]
        [string] $UpstreamPassword = '',

        [Parameter()]
        [string[]] $AllowedClientIps = @(),

        [Parameter()]
        [string] $SmtpUsername = '',

        [Parameter()]
        [string] $SmtpPassword = '',

        [Parameter()]
        [string[]] $AllowedRecipients = @(),

        [Parameter()]
        [string[]] $AllowedRecipientDomains = @(),

        [Parameter()]
        [switch] $AllowAllRecipients,

        [Parameter()]
        [string] $IntegrationId = '',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $ReceiverId = 'veritrust-smtp-gateway',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $AuthservId = 'veritrust-smtp-gateway',

        [Parameter()]
        [ValidateSet('policy', 'defer', 'reject')]
        [string] $DegradedMode = 'defer',

        [Parameter()]
        [ValidateSet('defer', 'reject')]
        [string] $ApiFailureMode = 'defer',

        [Parameter()]
        [ValidateRange(1, 180)]
        [int] $AnalysisTimeoutSec = 90,

        [Parameter()]
        [switch] $NoDecisionHeaders,

        [Parameter()]
        [string] $ProjectRoot = '',

        [Parameter()]
        [switch] $Wait
    )

    $ParsedUrl = $null
    if (-not [Uri]::TryCreate($ApiBaseUrl.TrimEnd('/'), [UriKind]::Absolute, [ref] $ParsedUrl) -or
        $ParsedUrl.Scheme -ne 'https' -or $ParsedUrl.UserInfo -or $ParsedUrl.Query -or $ParsedUrl.Fragment -or $ParsedUrl.AbsolutePath -ne '/') {
        throw 'ApiBaseUrl must be an HTTPS origin without credentials, a path, query, or fragment.'
    }

    $RemoteListener = $ListenHost -notin @('127.0.0.1', '::1', 'localhost')
    if ($RemoteListener) {
        if ($AllowedClientIps.Count -eq 0 -and ([string]::IsNullOrWhiteSpace($SmtpUsername) -or $SmtpPassword.Length -lt 12)) {
            throw 'A LAN/remote listener requires -AllowedClientIps or SMTP credentials with a password of at least 12 characters.'
        }
        if (-not $AllowAllRecipients -and $AllowedRecipients.Count -eq 0 -and $AllowedRecipientDomains.Count -eq 0) {
            throw 'A LAN/remote listener requires -AllowedRecipients, -AllowedRecipientDomains, or explicit -AllowAllRecipients.'
        }
    }

    $ServerPath = Get-VeriTrustMailGatewayServerPath -ProjectRoot $ProjectRoot
    $Environment = @{
        VERITRUST_API_BASE_URL                    = $ApiBaseUrl.TrimEnd('/')
        VERITRUST_API_KEY                         = $ApiKey
        VERITRUST_RECEIVER_SECRET                 = $ReceiverSecret
        VERITRUST_INTEGRATION_ID                  = $IntegrationId
        VERITRUST_SMTP_LISTEN_HOST                = $ListenHost
        VERITRUST_SMTP_LISTEN_PORT                = $ListenPort
        VERITRUST_SMTP_RECEIVER_ID                = $ReceiverId
        VERITRUST_SMTP_AUTHSERV_ID                = $AuthservId
        VERITRUST_SMTP_ALLOWED_CLIENT_IPS         = ($AllowedClientIps -join ',')
        VERITRUST_SMTP_REQUIRE_AUTH               = if (-not [string]::IsNullOrWhiteSpace($SmtpUsername)) { 'true' } else { 'false' }
        VERITRUST_SMTP_AUTH_USERNAME              = $SmtpUsername
        VERITRUST_SMTP_AUTH_PASSWORD              = $SmtpPassword
        VERITRUST_SMTP_ALLOWED_RECIPIENTS         = ($AllowedRecipients -join ',')
        VERITRUST_SMTP_ALLOWED_RECIPIENT_DOMAINS  = ($AllowedRecipientDomains -join ',')
        VERITRUST_SMTP_ALLOW_ALL_RECIPIENTS       = if ($AllowAllRecipients) { 'true' } else { 'false' }
        VERITRUST_SMTP_UPSTREAM_HOST              = $UpstreamHost
        VERITRUST_SMTP_UPSTREAM_PORT              = $UpstreamPort
        VERITRUST_SMTP_UPSTREAM_STARTTLS          = $UpstreamStartTls
        VERITRUST_SMTP_UPSTREAM_SECURE            = if ($UpstreamSecure) { 'true' } else { 'false' }
        VERITRUST_SMTP_UPSTREAM_USERNAME          = $UpstreamUsername
        VERITRUST_SMTP_UPSTREAM_PASSWORD          = $UpstreamPassword
        VERITRUST_SMTP_ANALYSIS_TIMEOUT_MS        = ($AnalysisTimeoutSec * 1000)
        VERITRUST_SMTP_DEGRADED_MODE              = $DegradedMode
        VERITRUST_SMTP_API_FAILURE_MODE           = $ApiFailureMode
        VERITRUST_SMTP_ADD_DECISION_HEADERS       = if ($NoDecisionHeaders) { 'false' } else { 'true' }
    }

    $Started = Start-VeriTrustNodeProcess -ScriptPath $ServerPath -Environment $Environment -Wait:$Wait
    if (-not $Wait) {
        [PSCustomObject] @{
            ProcessId    = $Started.ProcessId
            Listen       = "$ListenHost`:$ListenPort"
            Upstream     = "$UpstreamHost`:$UpstreamPort"
            ReceiverId   = $ReceiverId
            ApiBaseUrl   = $ApiBaseUrl.TrimEnd('/')
            StopCommand  = "Stop-Process -Id $($Started.ProcessId)"
        }
    }
}

function Read-VeriTrustSmtpResponse {
    param(
        [Parameter(Mandatory)]
        [System.IO.StreamReader] $Reader
    )
    $Lines = New-Object System.Collections.Generic.List[string]
    do {
        $Line = $Reader.ReadLine()
        if ($null -eq $Line) { throw 'SMTP connection closed unexpectedly.' }
        $Lines.Add($Line)
        if ($Line -notmatch '^(\d{3})([ -])') { throw "Malformed SMTP response: $Line" }
        $Final = $Matches[2] -eq ' '
    } until ($Final)
    return ,$Lines.ToArray()
}

function Test-VeriTrustMailGateway {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string] $HostName = '127.0.0.1',

        [Parameter()]
        [ValidateRange(1, 65535)]
        [int] $Port = 2525,

        [Parameter()]
        [string] $Username = '',

        [Parameter()]
        [string] $Password = '',

        [Parameter()]
        [ValidateRange(1, 30)]
        [int] $TimeoutSec = 5
    )

    $Client = New-Object System.Net.Sockets.TcpClient
    $Client.ReceiveTimeout = $TimeoutSec * 1000
    $Client.SendTimeout = $TimeoutSec * 1000
    try {
        $Client.Connect($HostName, $Port)
        $Stream = $Client.GetStream()
        $Reader = New-Object System.IO.StreamReader($Stream, [Text.Encoding]::ASCII, $false, 1024, $true)
        $Writer = New-Object System.IO.StreamWriter($Stream, [Text.Encoding]::ASCII, 1024, $true)
        $Writer.NewLine = "`r`n"
        $Writer.AutoFlush = $true

        $Greeting = Read-VeriTrustSmtpResponse -Reader $Reader
        $Writer.WriteLine('EHLO powershell-veritrust-test')
        $Ehlo = Read-VeriTrustSmtpResponse -Reader $Reader

        $Authenticated = $false
        if (-not [string]::IsNullOrWhiteSpace($Username)) {
            $Plain = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("`0$Username`0$Password"))
            $Writer.WriteLine("AUTH PLAIN $Plain")
            $Auth = Read-VeriTrustSmtpResponse -Reader $Reader
            if ($Auth[-1] -notmatch '^235 ') { throw "SMTP authentication failed: $($Auth[-1])" }
            $Authenticated = $true
        }

        $Writer.WriteLine('QUIT')
        $Quit = Read-VeriTrustSmtpResponse -Reader $Reader
        [PSCustomObject] @{
            Reachable      = $true
            Host           = $HostName
            Port           = $Port
            Greeting       = $Greeting[-1]
            Authenticated  = $Authenticated
            QuitResponse   = $Quit[-1]
        }
    }
    finally {
        $Client.Dispose()
    }
}

function Send-VeriTrustGatewayTestMail {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $From,

        [Parameter(Mandatory)]
        [string] $To,

        [Parameter(Mandatory)]
        [string] $Subject,

        [Parameter(Mandatory)]
        [string] $Body,

        [Parameter()]
        [string] $GatewayHost = '127.0.0.1',

        [Parameter()]
        [ValidateRange(1, 65535)]
        [int] $GatewayPort = 2525,

        [Parameter()]
        [string] $Username = '',

        [Parameter()]
        [string] $Password = ''
    )

    $Message = New-Object System.Net.Mail.MailMessage($From, $To, $Subject, $Body)
    $Client = New-Object System.Net.Mail.SmtpClient($GatewayHost, $GatewayPort)
    $Client.EnableSsl = $false
    if (-not [string]::IsNullOrWhiteSpace($Username)) {
        $Client.Credentials = New-Object System.Net.NetworkCredential($Username, $Password)
    }
    try {
        $Client.Send($Message)
        [PSCustomObject] @{
            Submitted = $true
            Gateway   = "$GatewayHost`:$GatewayPort"
            From      = $From
            To        = $To
            Subject   = $Subject
        }
    }
    finally {
        $Message.Dispose()
        $Client.Dispose()
    }
}

function Start-VeriTrustTestReceiver {
    <#
    .SYNOPSIS
    Starts the bundled lab-only SMTP sink on the receiver laptop and saves accepted .eml files to disk.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string] $ListenHost = '127.0.0.1',

        [Parameter()]
        [ValidateRange(1, 65535)]
        [int] $Port = 2526,

        [Parameter()]
        [string] $OutputDirectory = (Join-Path $PWD 'veritrust-test-inbox'),

        [Parameter()]
        [string] $ProjectRoot = '',

        [Parameter()]
        [switch] $Wait
    )

    if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
        $ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    }
    $ScriptPath = Join-Path $ProjectRoot 'mail-gateway\test-receiver.js'
    if (-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) { throw "Test receiver was not found at $ScriptPath" }
    $OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
    [IO.Directory]::CreateDirectory($OutputDirectory) | Out-Null
    $Started = Start-VeriTrustNodeProcess -ScriptPath $ScriptPath -Environment @{
        VERITRUST_TEST_RECEIVER_HOST   = $ListenHost
        VERITRUST_TEST_RECEIVER_PORT   = $Port
        VERITRUST_TEST_RECEIVER_OUTPUT = $OutputDirectory
    } -Wait:$Wait
    if (-not $Wait) {
        [PSCustomObject] @{
            ProcessId   = $Started.ProcessId
            Listen      = "$ListenHost`:$Port"
            InboxFolder = $OutputDirectory
            StopCommand = "Stop-Process -Id $($Started.ProcessId)"
        }
    }
}
