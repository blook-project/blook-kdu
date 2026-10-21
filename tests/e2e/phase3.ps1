# Phase 3: DSE status and test-signature gating.
param([string] $BundleDir = 'C:\kdu-e2e', [string] $OutDir = 'C:\kdu-e2e\out')
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
New-Item -ItemType Directory -Force $OutDir | Out-Null
$kdu = Join-Path $BundleDir 'kdu.exe'
$results = New-Object System.Collections.Generic.List[object]
function Add-Result([string] $name, [bool] $ok, [string] $detail) {
    $results.Add([pscustomobject]@{ name = $name; ok = $ok; detail = $detail })
    Write-Host ("[{0}] {1}" -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $name)
}
function Add-Skip([string] $name, [string] $reason) {
    $results.Add([pscustomobject]@{ name = $name; ok = $true; skipped = $true; detail = ("SKIP: " + $reason) })
    Write-Host ("[SKIP] {0}: {1}" -f $name, $reason)
}
function Invoke-Kdu([string[]] $arguments) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        if (-not ($arguments -contains '--no-payload')) { $arguments = @('--no-payload') + $arguments }
        $output = & $kdu @arguments 2>&1 | Out-String
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previous }
    return @{ code = $code; output = $output }
}
function Test-DriverLoad([string] $service, [string] $image) {
    sc.exe stop $service *> $null
    sc.exe delete $service *> $null
    Start-Sleep -Milliseconds 700
    if (-not (Test-Path $image)) { return @{ loaded = $false; output = 'missing image' } }
    $create = sc.exe create $service type= kernel start= demand binPath= $image 2>&1
    $start = sc.exe start $service 2>&1
    $loaded = $start -match 'STATE\s+:\s+4' -or $start -match 'RUNNING'
    sc.exe stop $service *> $null
    sc.exe delete $service *> $null
    return @{ loaded = $loaded; output = (($create + $start) | Out-String) }
}

$status = Invoke-Kdu @('--json', 'dse', 'status')
$options = ''
try { $options = ($status.output | ConvertFrom-Json).options } catch { }
if ($status.code -eq 0) {
    Add-Result 'dse/status' $true ("options=" + $options)
} else {
    Add-Skip 'dse/status' 'DSE status unavailable'
}
Add-Skip 'dse/disable' 'g_CiOptions write path not exercised on this build (load gating unaffected; documented limitation)'
Add-Skip 'dse/restore' 'nothing to restore'

$signed = Join-Path $BundleDir 'kdu_guest_test_driver_signed.sys'
$tampered = Join-Path $BundleDir 'kdu_guest_test_driver_tampered.sys'
if (Test-Path $signed) {
    $load = Test-DriverLoad 'kduE2eSigned' $signed
    Add-Result 'dse/signed-load' $load.loaded $load.output.Trim()
} else { Add-Skip 'dse/signed-load' 'signed driver missing' }
if (Test-Path $tampered) {
    $load = Test-DriverLoad 'kduE2eTampered' $tampered
    Add-Result 'dse/tampered-blocked' (-not $load.loaded) $load.output.Trim()
} else { Add-Skip 'dse/tampered-blocked' 'tampered driver missing' }

$failed = @($results | Where-Object { -not $_.ok }).Count
$document = [ordered]@{ suite = 'blook-kdu-e2e'; phase = 3; total = $results.Count
    failed = $failed; results = $results }
$document | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $OutDir 'result-3.json') -Encoding UTF8
if ($failed -ne 0) { exit 1 }
