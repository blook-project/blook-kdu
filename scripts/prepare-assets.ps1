# blook-kdu: build-time driver-asset signing.
#
# The bundled vulnerable drivers carry vendor signatures whose certificates are
# revoked (or expired) on current Windows 11 builds, so the SCM rejects them with
# CERT_E_REVOKED (0x800B010C) even with test signing enabled. For lab VMs that run
# with `testsigning on` we re-sign every embedded .sys with the bundled test
# signer (after stripping any existing Authenticode certificate table, otherwise
# the revoked vendor signature remains primary).
#
# Outputs (git-ignored):
#   build/generated/assets/<exploit>/<file>.bin   signed copies
#   build/generated/assets.rc                     RCDATA table for the CLI
#
# The original blobs stay untouched in src/exploits/*/data.
[CmdletBinding()]
param(
    [string] $Root = (Split-Path -Parent $PSScriptRoot),
    [switch] $Force
)

$ErrorActionPreference = 'Stop'
$signer = Join-Path $Root 'signer/spcsign/spcsign.exe'
$generated = Join-Path $Root 'build/generated'
$assetsDir = Join-Path $generated 'assets'
$rcPath = Join-Path $generated 'assets.rc'
New-Item -ItemType Directory -Force $assetsDir | Out-Null
New-Item -ItemType Directory -Force $generated | Out-Null

function Strip-Authenticode([string] $path) {
    $bytes = [System.IO.File]::ReadAllBytes($path)
    $e_lfanew = [BitConverter]::ToInt32($bytes, 0x3C)
    if ($e_lfanew -le 0 -or $e_lfanew + 0x18 -gt $bytes.Length) { return }
    $optionalHeader = $e_lfanew + 24
    $magic = [BitConverter]::ToUInt16($bytes, $optionalHeader)
    if ($magic -ne 0x20B) { return }  # only PE32+
    # DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY] is entry 4.
    $directoryOffset = $optionalHeader + 112 + (4 * 8)
    if ($directoryOffset + 8 -gt $bytes.Length) { return }
    $certOffset = [BitConverter]::ToUInt32($bytes, $directoryOffset)
    $certSize = [BitConverter]::ToUInt32($bytes, $directoryOffset + 4)
    if ($certOffset -eq 0 -or $certSize -eq 0) { return }
    if ($certOffset + $certSize -gt $bytes.Length) { return }
    # Truncate the certificate table and clear the directory entry.
    [Array]::Clear($bytes, $directoryOffset, 8)
    $trimmed = New-Object byte[] $certOffset
    [Array]::Copy($bytes, $trimmed, $certOffset)
    [System.IO.File]::WriteAllBytes($path, $trimmed)
}

$entries = New-Object System.Collections.Generic.List[string]
$signedCount = 0
$skippedCount = 0
$signerTime = (Get-Item $signer -ErrorAction SilentlyContinue).LastWriteTimeUtc

$sources = @()
foreach ($exploit in Get-ChildItem (Join-Path $Root 'src/exploits') -Directory) {
    if ($exploit.Name -in @('common', 'data')) { continue }
    $dataDir = Join-Path $exploit.FullName 'data'
    if (-not (Test-Path $dataDir)) { continue }
    $resourceHeader = Join-Path $exploit.FullName 'resource.h'
    if (-not (Test-Path $resourceHeader)) { continue }
    $defines = @{}
    foreach ($line in Get-Content $resourceHeader) {
        if ($line -match '^\s*#define\s+(IDR_\w+)\s+(\d+)') {
            $defines[$matches[1]] = [int]$matches[2]
        }
    }
    foreach ($rc in Get-ChildItem $dataDir -Filter '*.rc') {
        $content = Get-Content $rc.FullName -Raw
        foreach ($match in [regex]::Matches($content, '^\s*(IDR_\w+)\s+RCDATA\s+"([^"]+)"', 'Multiline')) {
            $symbol = $match.Groups[1].Value
            $binaryName = $match.Groups[2].Value
            if (-not $defines.ContainsKey($symbol)) { continue }
            $source = Join-Path $dataDir $binaryName
            if (-not (Test-Path $source)) { continue }
            $sources += [pscustomobject]@{
                id = $defines[$symbol]
                exploit = $exploit.Name
                binary = $binaryName
                source = $source
            }
        }
    }
}
# Manual mapper victim driver.
$victimHeader = Join-Path $Root 'src/loader/resource.h'
$victimId = 9101
if (Test-Path $victimHeader) {
    foreach ($line in Get-Content $victimHeader) {
        if ($line -match '^\s*#define\s+IDR_VICTIM_PROCEXP\s+(\d+)') {
            $victimId = [int]$matches[1]
        }
    }
}
$victimDir = Join-Path $Root 'src/loader/data'
$victimBin = Get-ChildItem $victimDir -Filter '*.bin' | Select-Object -First 1
if ($victimBin) {
    $sources += [pscustomobject]@{
        id = $victimId
        exploit = 'loader'
        binary = $victimBin.Name
        source = $victimBin.FullName
    }
}

foreach ($source in $sources) {
    $destinationDir = Join-Path $assetsDir $source.exploit
    New-Item -ItemType Directory -Force $destinationDir | Out-Null
    $destination = Join-Path $destinationDir ($source.binary + '.signed')
    $upToDate = (Test-Path $destination) -and
                  ((Get-Item $destination).LastWriteTimeUtc -ge
                   (Get-Item $source.source).LastWriteTimeUtc) -and
                  ($null -eq $signerTime -or
                   (Get-Item $destination).LastWriteTimeUtc -ge $signerTime)
    if ($upToDate -and -not $Force) {
        $skippedCount++
    } else {
        Copy-Item $source.source $destination -Force
        Strip-Authenticode $destination
        if ($signer -and (Test-Path $signer)) {
            & pwsh -NoProfile -ExecutionPolicy Bypass -File `
                (Join-Path $Root 'scripts/sign.ps1') -Files $destination | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "signing failed: $destination" }
        } else {
            Write-Warning "signer missing; embedding unsigned $($source.binary)"
        }
        $signedCount++
    }
    $entries.Add(('{0} RCDATA "{1}"' -f $source.id,
                    ($destination -replace '\\', '/')))
}

$rc = @('#include <winres.h>', '// Generated by scripts/prepare-assets.ps1 - do not edit.')
foreach ($entry in $entries) { $rc += $entry }
Set-Content -Path $rcPath -Value $rc -Encoding ascii
Write-Host ("prepared {0} embedded driver asset(s): {1} signed, {2} cached" -f `
            $entries.Count, $signedCount, $skippedCount)

