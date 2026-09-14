$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

. (Join-Path $PSScriptRoot '..\assets\powershell\VeriTrust.EmailInvestigation.ps1')

$script:Requests = @()
function Invoke-RestMethod {
    param(
        [string] $Method,
        [string] $Uri,
        [hashtable] $Headers,
        [string] $ContentType,
        [string] $InFile,
        $Body,
        [int] $TimeoutSec,
        [int] $MaximumRedirection,
        [string] $ErrorAction
    )
    $script:Requests += [PSCustomObject]@{ Uri = $Uri; ContentType = $ContentType; InFile = $InFile; Body = $Body; TimeoutSec = $TimeoutSec; MaximumRedirection = $MaximumRedirection; Headers = $Headers }
    [PSCustomObject]@{
        ok = $true
        scan_id = 'scan-smoke-123'
        evidence = [PSCustomObject]@{ state = 'LIKELY_PHISHING'; input_mode = if ($InFile) { 'eml' } else { 'text' }; limitations = @() }
        gateway_decision = [PSCustomObject]@{ risk = 0.91; recommendation = 'quarantine' }
    }
}

$TestApiKey = 'vtg_test_123456789012345678901234'
$TextResult = Invoke-VeriTrustEmailInvestigation -Subject 'Action required' -Body 'Verify your password now.' -ApiKey $TestApiKey -BaseUrl 'https://example.test'
if ($TextResult.Result -ne 'Likely phishing' -or $TextResult.RiskPercent -ne 91) { throw 'Text result mapping failed.' }
if ($TextResult.PSStandardMembers.DefaultDisplayPropertySet.ReferencedPropertyNames -contains 'TechnicalReport') { throw 'Technical evidence leaked into the default report display.' }
if ($null -eq $TextResult.TechnicalReport.evidence) { throw 'Complete evidence was not retained.' }
if ($script:Requests[0].Uri -ne 'https://example.test/api/v1/gateway/email/analyze-text') { throw 'Text endpoint routing failed.' }
if ($script:Requests[0].TimeoutSec -ne 90 -or $script:Requests[0].MaximumRedirection -ne 0) { throw 'Request bounds were not applied.' }
$UnicodeBody = [string][char]0x0939 + [char]0x093F + [char]0x0928
$null = Invoke-VeriTrustEmailInvestigation -Body $UnicodeBody -ApiKey $TestApiKey -BaseUrl 'https://example.test' -IdempotencyKey 'stable-retry-key'
$Decoded = [Text.Encoding]::UTF8.GetString($script:Requests[1].Body) | ConvertFrom-Json
if ($Decoded.body -ne $UnicodeBody -or $script:Requests[1].Headers['Idempotency-Key'] -ne 'stable-retry-key') { throw 'UTF-8 or retry identity was not preserved.' }
$script:Requests = @($script:Requests[0])
foreach ($UnsafeOrigin in @('http://example.test', 'https://user:password@example.test', 'https://example.test/path', 'https://example.test?query=1')) {
    $Rejected = $false
    try { Invoke-VeriTrustEmailInvestigation -Body 'Test' -ApiKey $TestApiKey -BaseUrl $UnsafeOrigin } catch { $Rejected = $true }
    if (-not $Rejected) { throw 'Unsafe API origin was accepted.' }
}

$EmlPath = Join-Path ([IO.Path]::GetTempPath()) ("veritrust-email-{0}.eml" -f [Guid]::NewGuid())
try {
    Set-Content -LiteralPath $EmlPath -Value "From: sender@example.test`r`nSubject: Test`r`n`r`nMessage" -Encoding Ascii
    $EmlResult = Invoke-VeriTrustEmailInvestigation -EmlPath $EmlPath -ApiKey $TestApiKey -BaseUrl 'https://example.test/'
    if ($EmlResult.InputType -ne 'eml') { throw 'EML result mapping failed.' }
    if ($script:Requests[1].Uri -ne 'https://example.test/api/v1/gateway/email/analyze-eml') { throw 'EML endpoint routing failed.' }
    if ($script:Requests[1].ContentType -ne 'message/rfc822') { throw 'EML content type failed.' }
    if ($script:Requests[1].InFile -ne $EmlPath) { throw 'EML file forwarding failed.' }
}
finally {
    Remove-Item -LiteralPath $EmlPath -Force -ErrorAction SilentlyContinue
}

Write-Output 'PowerShell email investigation smoke test passed.'
