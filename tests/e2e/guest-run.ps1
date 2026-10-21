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
$guestDriver = Join-Path $BundleDir 'kdu_guest_test_driver.sys'
$results = New-Object System.Collections.Generic.List[object]

function Add-Result([string] $name, [bool] $ok, [string] $detail) {
    $results.Add([pscustomobject]@{ name = $name; ok = $ok; detail = $detail })
    $status = if ($ok) { 'PASS' } else { 'FAIL' }
    Write-Host ("[{0}] {1}: {2}" -f $status, $name, $detail)
}

function Invoke-Kdu([string[]] $arguments) {
    $output = & $kdu @arguments 2>&1 | Out-String
    return @{ code = $LASTEXITCODE; output = $output }
}

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------
$os = Get-CimInstance Win32_OperatingSystem
Add-Result 'environment/build' $true ("Windows {0} build {1}" -f $os.Version, $os.BuildNumber)
$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
Add-Result 'environment/elevated' $elevated 'administrator token'

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
foreach ($id in $exploitIds) {
    $result = Invoke-Kdu @('--exploit', $id, '--driver-only', 'exploits', 'test', $id)
    $ok = $result.code -eq 0 -and $result.output -match 'PASS'
    Add-Result "exploit/$id" $ok $result.output.Trim()
    $cleanup = Invoke-Kdu @('--json', 'doctor', '--traces')
    Add-Result "exploit/$id/traces" ($cleanup.code -eq 0) $cleanup.output.Trim()
}

# ---------------------------------------------------------------------------
# Payload mapping through the first physical-write exploit.
# ---------------------------------------------------------------------------
$payloadId = ''
if ($exploitIds -contains 'gdrv') { $payloadId = 'gdrv' } elseif ($exploitIds.Count -gt 0) { $payloadId = $exploitIds[0] }
if ($payloadId) {
    $info = Invoke-Kdu @('--exploit', $payloadId, '--json', 'info')
    $ok = $info.code -eq 0
    $backend = ''
    if ($ok) {
        try { $backend = ($info.output | ConvertFrom-Json).backend } catch { $backend = '' }
    }
    Add-Result 'payload/map' ($ok -and $backend -eq 'payload') $info.output.Trim()
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
    Add-Result 'memory/virtual-read' ($virtual.code -eq 0) $virtual.output.Trim()
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
    Add-Result 'memory/process-read' ($read.code -eq 0 -and $hex -like '4b44552d453245*') `
        ("pid={0} hex={1}" -f $marker.pid, $hex)
    $marker2 = 'KDU-WRITE-TEST'
    $write = Invoke-Kdu @('--json', 'mem', 'process', 'write', '--pid', "$($marker.pid)",
                          $marker.address, ($marker2 -split '' | Where-Object { $_ } |
                          ForEach-Object { '{0:x2}' -f [int][char]$_ }) -join '')
    Add-Result 'memory/process-write' ($write.code -eq 0) $write.output.Trim()
} finally {
    if ($helperProcess -and -not $helperProcess.HasExited) {
        Stop-Process -Id $helperProcess.Id -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# DSE: disable -> unsigned driver loads -> restore -> it cannot load again.
# ---------------------------------------------------------------------------
function Test-DriverLoad([string] $service) {
    sc.exe stop $service *> $null
    sc.exe delete $service *> $null
    $create = sc.exe create $service type= kernel start= demand binPath= $guestDriver 2>&1
    $start = sc.exe start $service 2>&1
    $loaded = $start -match 'STATE\s+:\s+4' -or $start -match 'RUNNING'
    return @{ loaded = $loaded; create = ($create | Out-String); start = ($start | Out-String) }
}

if (Test-Path $guestDriver) {
    $disabled = Invoke-Kdu @('dse', 'disable')
    Add-Result 'dse/disable' ($disabled.code -eq 0) $disabled.output.Trim()
    $first = Test-DriverLoad 'kduE2eDriver'
    Add-Result 'dse/unsigned-load' $first.loaded $first.start.Trim()
    $restored = Invoke-Kdu @('dse', 'restore')
    Add-Result 'dse/restore' ($restored.code -eq 0) $restored.output.Trim()
    $second = Test-DriverLoad 'kduE2eDriver'
    Add-Result 'dse/unsigned-blocked' (-not $second.loaded) $second.start.Trim()
    sc.exe stop 'kduE2eDriver' *> $null
    sc.exe delete 'kduE2eDriver' *> $null
} else {
    Add-Result 'dse/unsigned-load' $false "guest test driver missing: $guestDriver"
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


