# blook-kdu: sign kernel images with the bundled test signer.
#
# Mirrors D:\blook-drv's signing approach: the prebuilt spcsign PKCS#7 builder
# plus the Verisign chain certs and local TSA assets in signer/. The result is a
# legacy-shaped Authenticode signature that test-signing Windows guests accept.
#
#   pwsh scripts/sign.ps1 -Files build/windows/x64/release/kdu_guest_test_driver.sys
#
# Signing an already signed image is fine (it rewrites the signature in place).
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string[]] $Files,
    [string] $Root = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'
$signerExe = Join-Path $Root 'signer/spcsign/spcsign.exe'
if (-not (Test-Path -LiteralPath $signerExe)) {
    throw "signer not found: $signerExe"
}
$chainCerts = @(
    (Join-Path $Root 'signer/certs/verisign-cscs-2010.cer'),
    (Join-Path $Root 'signer/certs/verisign-g5-mcvr.cer')
)
foreach ($file in $Files) {
    if (-not (Test-Path -LiteralPath $file)) {
        throw "image to sign not found: $file"
    }
    $arguments = @('sign', '--sha1', '--cert', 'XINDA',
                   '--tsa-time', '2013-01-01T00:00:00Z')
    foreach ($cert in $chainCerts) { $arguments += @('--chain', $cert) }
    $arguments += $file
    $output = & $signerExe @arguments 2>&1
    foreach ($line in $output) { Write-Host ("  " + [string]$line) }
    if ($LASTEXITCODE -ne 0) {
        throw "spcsign failed for $file ($LASTEXITCODE)"
    }
    Write-Host "signed: $file"
}
