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
    [string] $Root = (Split-Path -Parent $PSScriptRoot),
    # Export the signing (XINDA) leaf certificate from the first signed image,
    # e.g. for `certutil -addstore trustedpublisher` on a test guest/runner.
    [string] $ExportLeafCert = ''
)

$ErrorActionPreference = 'Stop'
$signerExe = Join-Path $Root 'signer/spcsign/spcsign.exe'

# CI path: the SPC signing key ships as a PFX secret, and the local TSA root is
# imported as a trusted root. Locally these stores are already populated, so the
# block is a no-op.
if ($env:SPC_PFX_BASE64) {
    $pfxPath = Join-Path ([System.IO.Path]::GetTempPath()) "kdu-spc-$PID.pfx"
    try {
        [System.IO.File]::WriteAllBytes(
            $pfxPath, [Convert]::FromBase64String($env:SPC_PFX_BASE64))
        $password = ConvertTo-SecureString -String $env:SPC_PFX_PASSWORD `
            -AsPlainText -Force
        Import-PfxCertificate -FilePath $pfxPath -Password $password `
            -CertStoreLocation Cert:\CurrentUser\My | Out-Null
    } finally {
        Remove-Item $pfxPath -Force -ErrorAction SilentlyContinue
    }
    $tsaRoot = Join-Path $Root 'signer/tsa/tsa-root.cer'
    if (Test-Path $tsaRoot) {
        certutil.exe -addstore -f root $tsaRoot | Out-Null
    }
}
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

if ($ExportLeafCert) {
    $leaf = (Get-AuthenticodeSignature $Files[0]).SignerCertificate
    if (-not $leaf) { throw "cannot read the signer certificate from $($Files[0])" }
    $directory = Split-Path -Parent $ExportLeafCert
    if ($directory -and -not (Test-Path $directory)) {
        New-Item -ItemType Directory -Force $directory | Out-Null
    }
    [System.IO.File]::WriteAllBytes($ExportLeafCert, $leaf.Export('Cert'))
    Write-Host "exported signer leaf: $ExportLeafCert"
}


