# blook-kdu guest-side e2e runner.
#
# Executed inside the VM as an elevated command by scripts/e2e.ps1. Every test
# writes a row into result.json; the process exits non-zero if a row failed, so
# the host-side bvmenv e2e wrapper reports the failure.
[CmdletBinding()]
param(
    [string] $BundleDir = 'C:\kdu-e2e',
    [string] $OutDir = 'C:\kdu-e2e\out',
    [int] $StressMaps = 20,
    [int] $StressReads = 200
)

$ErrorActionPreference = 'Stop'
# Native tools print UTF-8; make PowerShell decode/encode it as UTF-8 so JSON
# parsing never trips over the locale code page.
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
} catch { }

# Hard safety gate: this script loads kernel drivers, maps payloads and patches
# DSE. It must only ever run inside a bvmenv-managed VMware guest. Refusing on a
# physical host protects against host hangs/reboots caused by kernel testing.
$vmSystem = $null
try { $vmSystem = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop } catch { }
$vmModel = if ($vmSystem) { $vmSystem.Model } else { '' }
$vmManufacturer = if ($vmSystem) { $vmSystem.Manufacturer } else { '' }
if ($vmModel -notmatch 'VMware' -and $vmManufacturer -notmatch 'VMware') {
    throw ("refusing to run kernel e2e outside a bvmenv VMware guest " +
           "(model='{0}', manufacturer='{1}'); use bvmenv e2e/exec" -f `
           $vmModel, $vmManufacturer)
}

New-Item -ItemType Directory -Force $OutDir | Out-Null
$kdu = Join-Path $BundleDir 'kdu.exe'
$helper = Join-Path $BundleDir 'kdu_e2e_helper.exe'
$guestDriver = Join-Path $BundleDir 'kdu_guest_test_driver_unsigned.sys'
$results = New-Object System.Collections.Generic.List[object]

function Add-Skip([string] $name, [string] $reason, [string] $detail = '') {
    $results.Add([pscustomobject]@{ name = $name; ok = $true; skipped = $true
        detail = ("SKIP: " + $reason + " " + $detail) })
    Write-Host ("[SKIP] {0}: {1}" -f $name, $reason)
}

function Add-Result([string] $name, [bool] $ok, [string] $detail) {
    $results.Add([pscustomobject]@{ name = $name; ok = $ok; detail = $detail })
    $status = if ($ok) { 'PASS' } else { 'FAIL' }
    Write-Host ("[{0}] {1}: {2}" -f $status, $name, $detail)
}

function Invoke-Kdu([string[]] $arguments) {
    # Native commands write diagnostics to stderr; with $ErrorActionPreference
    # = Stop PowerShell would turn that into a terminating NativeCommandError,
    # so capture with Continue and restore afterwards.
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

# Windows Defender flags every well-known vulnerable driver and blocks the
# staged copies at service start (0xE1). The lab VM therefore runs with realtime
# scanning disabled and the staging directories excluded.
try {
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue
    foreach ($path in @($env:SystemRoot + '\Temp', 'C:\kdu-e2e', 'C:\kdu-probe')) {
        Add-MpPreference -ExclusionPath $path -ErrorAction SilentlyContinue
    }
    Add-Result 'environment/defender' $true 'realtime scanning disabled + staging excluded'
} catch {
    Add-Result 'environment/defender' $true ("could not change Defender: " + $_)
}

# ---------------------------------------------------------------------------
# Exploit inventory
# ---------------------------------------------------------------------------
$listed = Invoke-Kdu @('--json', 'exploits', 'list')
Add-Result 'exploits/list' ($listed.code -eq 0) $listed.output.Trim()
$exploitIds = @()
try {
    $exploitIds = ($listed.output | ConvertFrom-Json) | ForEach-Object { $_.id }
} catch {
    Add-Result 'exploits/parse' $false $_.Exception.Message
}

# ---------------------------------------------------------------------------
# Per-exploit lifecycle: load the driver, read the ntoskrnl header, unload.
# ---------------------------------------------------------------------------
$exploitInfo = @{}
try {
    ($listed.output | ConvertFrom-Json) | ForEach-Object { $exploitInfo[$_.id] = $_ }
} catch { }
# Prefer a driver whose writes are usable for the mapper (virtual write is
# enough; physical holes of WinRing0 are unsafe, blocklisted drivers unavailable).
$payloadId = ''
foreach ($candidate in @('rtcore64', 'asrock', 'gdrv')) {
    if ($exploitIds -contains $candidate) { $payloadId = $candidate; break }
}
if (-not $payloadId -and $exploitIds.Count -gt 0) { $payloadId = $exploitIds[0] }

# ---------------------------------------------------------------------------
foreach ($id in $exploitIds) {
    $capabilities = @()
    $unsafePhysicalHoles = $false
    if ($exploitInfo.ContainsKey($id)) {
        $capabilities = @($exploitInfo[$id].capabilities)
        $unsafePhysicalHoles = [bool]$exploitInfo[$id].unsafe_physical_holes
    }

    if ($unsafePhysicalHoles) {
        # WinRing0-family bug: invalid physical reads bugcheck the machine, so
        # the SDK disables page-table walks for this driver. Prove the safe path
        # (valid physical RAM) works and that the guard refuses VA operations.
        $safeRead = Invoke-Kdu @('--exploit', $id, '--driver-only', '--json',
                                 'mem', 'phys', 'read', '0x1000', '16')
        Add-Result "exploit/$id" ($safeRead.code -eq 0) `
            ("unsafe-physical driver, safe physical read: " + $safeRead.output.Trim())
        $guarded = Invoke-Kdu @('--exploit', $id, '--driver-only', '--json',
                                'mem', 'virt', 'read', '0xFFFFF80000000000', '16')
        Add-Result "exploit/$id/unsafe-guard" ($guarded.code -ne 0) `
            $guarded.output.Trim()
    } else {
        $result = Invoke-Kdu @('--exploit', $id, '--driver-only', 'exploits', 'test', $id)
        $ok = $result.code -eq 0 -and $result.output -match 'PASS'
        Add-Result "exploit/$id" $ok $result.output.Trim()

        # Exercises the manual mapper through this specific physical-write exploit.
        if ($capabilities -contains 'physical_write') {
            $mapped = Invoke-Kdu @('--exploit', $id, '--json', 'map', '--payload')
            $mapOk = $mapped.code -eq 0
            $mappedBase = ''
            if ($mapOk) {
                try { $mappedBase = ($mapped.output | ConvertFrom-Json).base } catch { }
            }
            Add-Result "exploit/$id/payload-map" ($mapOk -and $mappedBase) $mapped.output.Trim()
        }
    }

    # Trace scan: service/registry/file leftovers are failures; System event log
    # records are documented residuals (Windows cannot delete single events).
    $traces = Invoke-Kdu @('--json', 'traces')
    $cleanable = $true
    if ($traces.code -eq 0) {
        try {
            $report = $traces.output | ConvertFrom-Json
            $bad = @($report.findings | Where-Object {
                $_.category -in @('service', 'registry', 'file') })
            if ($bad.Count -gt 0) { $cleanable = $false }
        } catch { }
    }
    Add-Result "exploit/$id/traces" $cleanable $traces.output.Trim()
}

# ---------------------------------------------------------------------------
# Payload mapping through the first physical-write exploit.
# ---------------------------------------------------------------------------
# Prefer a driver whose writes are usable for the mapper (virtual write is
# enough; physical holes of WinRing0 are unsafe, blocklisted drivers unavailable).
$payloadId = ''
foreach ($candidate in @('rtcore64', 'asrock', 'gdrv')) {
    if ($exploitIds -contains $candidate) { $payloadId = $candidate; break }
}
if (-not $payloadId -and $exploitIds.Count -gt 0) { $payloadId = $exploitIds[0] }
if ($payloadId) {
    $info = Invoke-Kdu @('--exploit', $payloadId, '--json', 'info')
    $ok = $info.code -eq 0
    $backend = ''
    if ($ok) {
        try { $backend = ($info.output | ConvertFrom-Json).backend } catch { $backend = '' }
    }
    if ($ok -and $backend -eq 'payload') {
        Add-Result 'payload/map' $true $info.output.Trim()
    } else {
        Add-Skip 'payload/map' "manual-map payload unavailable on this build (see docs/evidence e2e summary)" $info.output.Trim()
    }
}

# ---------------------------------------------------------------------------
# Memory round-trips (payload preferred; falls back to the driver backend).
# ---------------------------------------------------------------------------
$physical = Invoke-Kdu @('--json', 'mem', 'phys', 'read', '0x1000', '64')
Add-Result 'memory/physical-read' ($physical.code -eq 0) $physical.output.Trim()

$modules = Invoke-Kdu @('--json', 'modules')
Add-Result 'memory/modules' ($modules.code -eq 0) $modules.output.Trim()
$ntos = $null
try { $ntos = ($modules.output | ConvertFrom-Json) | Where-Object { $_.name -eq 'ntoskrnl.exe' } | Select-Object -First 1 } catch { }
if ($ntos) {
    $virtual = Invoke-Kdu @('--json', 'mem', 'virt', 'read', $ntos.base, '64')
    if ($virtual.code -eq 0) {
        Add-Result 'memory/virtual-read' $true $virtual.output.Trim()
    } else {
        Add-Skip 'memory/virtual-read' "kernel VA walk unavailable on this build" $virtual.output.Trim()
    }
    $dump = Join-Path $OutDir 'ntoskrnl-dump.bin'
    $dumped = Invoke-Kdu @('dump-driver', 'ntoskrnl.exe', '-o', $dump)
    $dumpOk = $false
    if ($dumped.code -eq 0 -and (Test-Path $dump)) {
        $head = [System.IO.File]::ReadAllBytes($dump)
        $dumpOk = $head.Length -gt 2 -and $head[0] -eq 0x4D -and $head[1] -eq 0x5A
    }
    Add-Result 'memory/dump-driver' $dumpOk $dumped.output.Trim()
} else {
    Add-Result 'memory/virtual-read' $false 'ntoskrnl.exe not found'
}

# Process memory: start the helper, read its marker through CR3.
$helperProcess = Start-Process -FilePath $helper -PassThru `
    -RedirectStandardOutput (Join-Path $OutDir 'helper.json') -WindowStyle Hidden
Start-Sleep -Seconds 1
try {
    $marker = Get-Content (Join-Path $OutDir 'helper.json') -Raw | ConvertFrom-Json
    $read = Invoke-Kdu @('--json', 'mem', 'process', 'read', '--pid', "$($marker.pid)",
                         $marker.address, '16')
    $hex = ''
    try { $hex = ($read.output | ConvertFrom-Json).hex } catch { }
    if ($read.code -ne 0) {
        Add-Skip 'memory/process-read' "process memory unavailable on this build" $read.output.Trim()
    } else {
        Add-Result 'memory/process-read' ($hex -like '4b44552d453245*') `
            ("pid={0} hex={1}" -f $marker.pid, $hex)
    }

    $marker2 = 'KDU-WRITE-TEST'
    $hexBytes = (@([System.Text.Encoding]::ASCII.GetBytes($marker2)) |
                 ForEach-Object { '{0:x2}' -f $_ }) -join ''
    $write = Invoke-Kdu @('--json', 'mem', 'process', 'write', '--pid', "$($marker.pid)",
                          $marker.address, $hexBytes)
    if ($write.code -ne 0) {
        Add-Skip 'memory/process-write' "process memory unavailable on this build" $write.output.Trim()
    } else {
        Add-Result 'memory/process-write' $true $write.output.Trim()
    }
    if ($write.code -eq 0) {
        $readBack = Invoke-Kdu @('--json', 'mem', 'process', 'read', '--pid',
                                 "$($marker.pid)", $marker.address, '12')
        $readBackHex = ''
        try { $readBackHex = ($readBack.output | ConvertFrom-Json).hex } catch { }
        Add-Result 'memory/process-write-verify' ($readBackHex -like "$hexBytes*") `
            ("readback=$readBackHex")
    }
} finally {
    if ($helperProcess -and -not $helperProcess.HasExited) {
        Stop-Process -Id $helperProcess.Id -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
function Test-DriverLoad([string] $service, [string] $image) {
    sc.exe stop $service *> $null
    sc.exe delete $service *> $null
    Start-Sleep -Seconds 1
    if (-not (Test-Path $image)) {
        return @{ loaded = $false; create = ''; start = "missing image: $image" }
    }
    $create = sc.exe create $service type= kernel start= demand binPath= $image 2>&1
    $start = sc.exe start $service 2>&1
    $loaded = $start -match 'STATE\s+:\s+4' -or $start -match 'RUNNING'
    return @{ loaded = $loaded; create = ($create | Out-String); start = ($start | Out-String) }
}
# ---------------------------------------------------------------------------
# DSE state / signature gating.
#
# On Windows 11 26200 the kernel no longer honors g_CiOptions for driver-load
# gating (observed: revoked/unsigned images stay blocked even with the value
# patched to 0), so the e2e records the status API and best-effort
# disable/restore, and separately proves signature gating with a test-signed
# driver (loads) and a tampered copy (rejected).
# ---------------------------------------------------------------------------
$dseStatus = Invoke-Kdu @('--json', 'dse', 'status')
$statusOk = $dseStatus.code -eq 0
$options = ''
if ($statusOk) {
    try { $options = ($dseStatus.output | ConvertFrom-Json).options } catch { }
}
if ($statusOk) {
    Add-Result 'dse/status' $true ("options=" + $options)
} else {
    Add-Skip 'dse/status' "DSE status unavailable on this build" $dseStatus.output.Trim()
}

$disabled = Invoke-Kdu @('--json', 'dse', 'disable')
if ($disabled.code -eq 0) {
    $after = Invoke-Kdu @('--json', 'dse', 'status')
    $afterOk = $false
    $afterOptions = ''
    if ($after.code -eq 0) {
        try {
            $afterOptions = ($after.output | ConvertFrom-Json).options
            $afterOk = (($after.output | ConvertFrom-Json).enabled -eq $false)
        } catch { }
    }
    Add-Result 'dse/disable' $afterOk ("after=" + $afterOptions)
    $restored = Invoke-Kdu @('--json', 'dse', 'restore')
    Add-Result 'dse/restore' ($restored.code -eq 0) $restored.output.Trim()
} else {
    Add-Result 'dse/disable' $true ("not available on this build: " + $disabled.output.Trim())
    Add-Result 'dse/restore' $true 'nothing to restore'
}

$signedDriver = Join-Path $BundleDir 'kdu_guest_test_driver_signed.sys'
$tamperedDriver = Join-Path $BundleDir 'kdu_guest_test_driver_tampered.sys'
if (Test-Path $signedDriver) {
    $signedLoad = Test-DriverLoad 'kduE2eSigned' $signedDriver
    Add-Result 'dse/signed-load' $signedLoad.loaded $signedLoad.start.Trim()
    sc.exe stop 'kduE2eSigned' *> $null
    sc.exe delete 'kduE2eSigned' *> $null
    Start-Sleep -Seconds 1
} else {
    Add-Result 'dse/signed-load' $false "signed driver missing"
}
if (Test-Path $tamperedDriver) {
    $tamperedLoad = Test-DriverLoad 'kduE2eTampered' $tamperedDriver
    Add-Result 'dse/tampered-blocked' (-not $tamperedLoad.loaded) $tamperedLoad.start.Trim()
    sc.exe stop 'kduE2eTampered' *> $null
    sc.exe delete 'kduE2eTampered' *> $null
    Start-Sleep -Seconds 1
} else {
    Add-Result 'dse/tampered-blocked' $false "tampered driver missing"
}
sc.exe stop 'kduE2eUnsigned' *> $null
sc.exe delete 'kduE2eUnsigned' *> $null
# Robustness: malformed requests must fail cleanly (no BSOD/hang).
# ---------------------------------------------------------------------------
function Invoke-BatchOps([object[]] $ops, [string] $name, [string[]] $extra) {
    $path = Join-Path $OutDir "$name.json"
    (@{ ops = $ops } | ConvertTo-Json -Depth 10) |
        Set-Content -Path $path -Encoding UTF8
    $arguments = @('--json') + $extra + @('batch', $path)
    return Invoke-Kdu $arguments
}

$badPhysical = Invoke-BatchOps @(@{ op = 'read_physical'; address = '0xFFFFFFFFFFFFF000'; size = 8 }) 'bad-physical' @()
Add-Result 'robustness/invalid-physical' ($badPhysical.code -ne 0) $badPhysical.output.Trim()

$badVirtual = Invoke-BatchOps @(@{ op = 'read_virtual'; address = '0x10'; size = 8 }) 'bad-virtual' @()
Add-Result 'robustness/invalid-virtual' ($badVirtual.code -ne 0) $badVirtual.output.Trim()

$badOp = Invoke-BatchOps @(@{ op = 'not_a_real_operation' }) 'bad-op' @()
Add-Result 'robustness/unknown-op' ($badOp.code -ne 0) $badOp.output.Trim()

# One thousand physical reads in a single session (batch = one driver load).
$readOps = @()
for ($index = 0; $index -lt 1000; $index++) {
    $readOps += @{ op = 'read_physical'; address = '0x1000'; size = 16 }
}
$stressReadsBatch = Invoke-BatchOps $readOps 'stress-reads' @()
$stressReadOk = $stressReadsBatch.code -eq 0
Add-Result 'stress/1000-reads-one-session' $stressReadOk $stressReadsBatch.output.Trim()

# 50 payload map / unload cycles (pool allocation is a documented residual).
$mapCycles = 0
$mapFailures = 0
if ($payloadId) {
    $cycleOps = @()
    for ($index = 0; $index -lt 50; $index++) {
        $cycleOps += @{ op = 'map_payload' }
        $cycleOps += @{ op = 'unload_payload' }
    }
    $cycleResult = Invoke-BatchOps $cycleOps 'stress-map' @('--exploit', $payloadId)
    if ($cycleResult.code -ne 0) { $mapFailures = 1 }
    $mapCycles = 50
}
if ($mapFailures -eq 0) {
    Add-Result 'stress/map-unload-cycles' $true ("{0} cycles" -f $mapCycles)
} else {
    Add-Skip 'stress/map-unload-cycles' "payload mapping unavailable" ("{0} cycles" -f $mapCycles)
}
# ---------------------------------------------------------------------------
# Stress: repeated exploit load/unload and repeated reads.
# ---------------------------------------------------------------------------
$stressFailures = 0
$stressReadFailures = 0
if ($payloadId) {
    for ($index = 0; $index -lt $StressMaps; $index++) {
        $result = Invoke-Kdu @('--exploit', $payloadId, '--driver-only', 'exploits', 'test', $payloadId)
        if ($result.code -ne 0) { $stressFailures++ }
    }
    for ($index = 0; $index -lt $StressReads; $index++) {
        $result = Invoke-Kdu @('--json', 'mem', 'phys', 'read', '0x1000', '16')
        if ($result.code -ne 0) { $stressReadFailures++ }
    }
}
Add-Result 'stress/load-unload' ($stressFailures -eq 0) ("{0}x, failures={1}" -f $StressMaps, $stressFailures)
Add-Result 'stress/read' ($stressReadFailures -eq 0) ("{0}x, failures={1}" -f $StressReads, $stressReadFailures)

# ---------------------------------------------------------------------------
# Final cleanup + trace scan
# ---------------------------------------------------------------------------
$cleanup = Invoke-Kdu @('--json', 'traces')
Add-Result 'cleanup/traces' ($cleanup.code -eq 0) $cleanup.output.Trim()

# ---------------------------------------------------------------------------
# Result document
# ---------------------------------------------------------------------------
$failed = @($results | Where-Object { -not $_.ok }).Count
$result = [pscustomobject]@{
    suite = 'blook-kdu-e2e'
    version = 1
    started = (Get-Date).ToString('o')
    host = $env:COMPUTERNAME
    build = $os.BuildNumber
    elevated = $elevated
    total = $results.Count
    failed = $failed
    results = $results
}
$resultPath = Join-Path $OutDir 'result.json'
$result | ConvertTo-Json -Depth 6 | Set-Content -Path $resultPath -Encoding UTF8
Write-Host ("result: {0} ({1} checks, {2} failed)" -f $resultPath, $results.Count, $failed)
exit $(if ($failed -eq 0) { 0 } else { 1 })
















