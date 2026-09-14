#requires -Version 5.1
$ErrorActionPreference = 'Stop'

$files = @(
    (Join-Path $PSScriptRoot 'VeriTrust-Receiver-CLI.ps1'),
    (Join-Path $PSScriptRoot 'VeriTrust-Sender-CLI.ps1')
)

$failed = $false
foreach ($file in $files) {
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$errors)
    if ($errors.Count -eq 0) {
        Write-Host "[PASS] $([IO.Path]::GetFileName($file))" -ForegroundColor Green
    }
    else {
        $failed = $true
        Write-Host "[FAIL] $([IO.Path]::GetFileName($file))" -ForegroundColor Red
        foreach ($error in $errors) {
            Write-Host ("  Line {0}, Column {1}: {2}" -f $error.Extent.StartLineNumber, $error.Extent.StartColumnNumber, $error.Message) -ForegroundColor Red
        }
    }
}
if ($failed) { exit 1 }
Write-Host ''
Write-Host 'Both VeriTrust CLI scripts passed the local Windows PowerShell parser.' -ForegroundColor Cyan
