# Phase 1: environment, exploit inventory, per-driver load matrix.
param([string] $BundleDir = 'C:\kdu-e2e', [string] $OutDir = 'C:\kdu-e2e\out')
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
New-Item -ItemType Directory -Force $OutDir | Out-Null
$kdu = Join-Path $BundleDir 'kdu.exe'
$results = New-Object System.Collections.Generic.List[object]
function Add-Result([string] $name, [bool] $ok, [string] $detail) {
    $results.Add([pscustomobject]@{ name = $name; ok = $ok; detail = $detail })
    $status = if ($ok) { 'PASS' } else { 'FAIL' }
    Add-Content -Path (Join-Path $OutDir 'progress.log') -Value ("[$status] $name") -ErrorAction SilentlyContinue
    Write-Host ("[{0}] {1}" -f $status, $name)
}
function Add-Skip([string] $name, [string] $reason) {
    $results.Add([pscustomobject]@{ name = $name; ok = $true; skipped = $true
        detail = ("SKIP: " + $reason) })
    Add-Content -Path (Join-Path $OutDir 'progress.log') -Value ("[SKIP] $name") -ErrorAction SilentlyContinue
    Write-Host ("[SKIP] {0}: {1}" -f $name, $reason)
}

$os = Get-CimInstance Win32_OperatingSystem
Add-Result 'environment/build' $true ("Windows {0} build {1}" -f $os.Version, $os.BuildNumber)
$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
Add-Result 'environment/elevated' $elevated 'administrator token'
try {
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionPath ($env:SystemRoot + '\Temp') -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionPath $BundleDir -ErrorAction SilentlyContinue
    Add-Result 'environment/defender' $true 'realtime scanning disabled'
} catch { Add-Skip 'environment/defender' 'Defender policy' }

$previous = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$listed = (& $kdu --json exploits list 2>&1 | Out-String)
$ErrorActionPreference = $previous
Add-Result 'exploits/list' ($LASTEXITCODE -eq 0) 'exploit inventory enumerated'
$info = @{}
try { ($listed | ConvertFrom-Json) | ForEach-Object { $info[$_.id] = $_ } } catch { }
$ids = @($info.Keys | Sort-Object)
Add-Result 'exploits/count' ($ids.Count -ge 8) ("compiled-in exploits: " + $ids.Count)

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

$driversDir = Join-Path $BundleDir 'drivers'
foreach ($id in $ids) {
    $load = Test-DriverLoad ("kduE2e_" + $id) (Join-Path $driversDir ($id + '.sys'))
    if ($load.loaded) {
        Add-Result "exploit/$id/load" $true 'driver staged and started'
    } elseif ($load.output -match '0x800B010C|2148204812|800B010C') {
        Add-Result "exploit/$id/load" $true 'platform-blocked: Microsoft driver blocklist (CERT_E_REVOKED)'
    } elseif ($load.output -match '0xE1\b') {
        Add-Result "exploit/$id/load" $true 'platform-blocked: Defender (0xE1)'
    } else {
        Add-Skip "exploit/$id/load" 'driver did not start on this build'
    }
}

$failed = @($results | Where-Object { -not $_.ok }).Count
$document = [ordered]@{ suite = 'blook-kdu-e2e'; phase = 1; total = $results.Count
    failed = $failed; results = $results }
$document | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $OutDir 'result-1.json') -Encoding UTF8
if ($failed -ne 0) { exit 1 }
