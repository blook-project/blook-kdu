# blook-kdu host-side VM e2e driver.
#
# Builds an e2e bundle from the current build outputs, pushes it into a bvmenv
# VM, runs the elevated guest suite and pulls the artifacts back. Every bvmenv
# call is wrapped in a hard timeout: bvmenv has been observed to hang, and the
# e2e pipeline must never wedge the host. Kernel code only ever runs inside the
# guest; this script only orchestrates bvmenv.
[CmdletBinding()]
param(
    [string] $Root = (Split-Path -Parent $PSScriptRoot),
    [string] $Vm = '',
    [string] $Out = '',
    [string] $Bvmenv = 'D:\blook-kernel-project\blook-vmware-environment\dist\bvmenv-latest.exe',
    [int] $ExecTimeoutSeconds = 1500,
    [int] $StepTimeoutSeconds = 300,
    [switch] $NoReset,
    [switch] $Reuse
)

$ErrorActionPreference = 'Stop'
Set-Location $Root
if (-not $Vm) {
    throw "refusing to run kernel e2e on the host: pass -Vm <bvmenv guest name> (e.g. -Vm vm-kdu)"
}
if (-not (Test-Path $Bvmenv)) {
    throw "bvmenv not found: $Bvmenv"
}
$version = (Get-Content (Join-Path $Root 'version.txt') -Raw).Trim()
if (-not $Out) {
    $Out = Join-Path $Root ("docs/evidence/{0}-e2e" -f (Get-Date -Format 'yyyyMMdd'))
}
New-Item -ItemType Directory -Force $Out | Out-Null
$build = Join-Path $Root 'build/windows/x64/release'
if (-not (Test-Path $build)) {
    throw "build outputs missing: $build (run xmake -y first)"
}

function Invoke-Bvmenv {
    param([string] $Arguments, [int] $TimeoutSeconds = $StepTimeoutSeconds)
    Write-Host ("> bvmenv {0}" -f $Arguments)
    $stdoutPath = Join-Path $Out 'bvmenv.out.log'
    $stderrPath = Join-Path $Out 'bvmenv.err.log'
    $process = Start-Process -FilePath $Bvmenv -ArgumentList $Arguments `
        -NoNewWindow -PassThru `
        -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        try { $process.Kill($true) } catch { }
        throw ("bvmenv {0} timed out after {1}s" -f $Arguments, $TimeoutSeconds)
    }
    $stdout = Get-Content $stdoutPath -Raw -ErrorAction SilentlyContinue
    $stderr = Get-Content $stderrPath -Raw -ErrorAction SilentlyContinue
    return @{ code = $process.ExitCode; stdout = $stdout; stderr = $stderr }
}

# ---------------------------------------------------------------------------
# 0. Verify the VM exists (create it only when missing).
# ---------------------------------------------------------------------------
$list = Invoke-Bvmenv 'list --json' $StepTimeoutSeconds
if ($list.code -ne 0) {
    throw ("bvmenv list failed ({0}): {1}{2}" -f $list.code, $list.stdout,
           $list.stderr)
}
if ($list.stdout -notmatch [regex]::Escape($Vm)) {
    if ($Reuse) {
        throw "VM $Vm does not exist (remove -Reuse or create it first)"
    }
    Write-Host "VM $Vm does not exist; creating from the base snapshot"
    $created = Invoke-Bvmenv "create $Vm --cpus 4 --memory 6144" 600
    if ($created.code -ne 0) {
        throw ("bvmenv create failed: " + $created.stdout + $created.stderr)
    }
    $ready = Invoke-Bvmenv "wait-ready $Vm --timeout 600" 660
    if ($ready.code -ne 0) {
        Write-Warning ("wait-ready reported not ready: " + $ready.stdout +
                       $ready.stderr)
    }
}

# Make sure the VM is powered on (the last run leaves it reset/powered off).
$probe = Invoke-Bvmenv "state $Vm --json --no-ocr" $StepTimeoutSeconds
$power = ''
try { $power = ($probe.stdout | ConvertFrom-Json).power } catch { }
if ($power -ne 'on') {
    $started = Invoke-Bvmenv "start $Vm" 240
    if ($started.code -ne 0) {
        throw ("bvmenv start failed: " + $started.stdout + $started.stderr)
    }
    $ready = Invoke-Bvmenv "wait-ready $Vm --timeout 600" 660
    if ($ready.code -ne 0) {
        Write-Warning ("wait-ready reported not ready: " + $ready.stdout + $ready.stderr)
    }
}
# Lab preparation: kernel pool must be executable for the manual mapper
# (nx AlwaysOff) and Defender would block the staged vulnerable drivers.
$prepCommand = 'cmd /c bcdedit /set nx AlwaysOff >nul 2>&1 && powershell -NoProfile -Command "Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue; Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue; Add-MpPreference -ExclusionPath C:\Windows\Temp -ErrorAction SilentlyContinue; Add-MpPreference -ExclusionPath C:\kdu-e2e -ErrorAction SilentlyContinue" && shutdown /r /t 0 /f'
$prep = Invoke-Bvmenv ("exec {0} --elevated --timeout 120 -- {1}" -f $Vm, $prepCommand) 180
Write-Host "lab preparation exit: $($prep.code)"
Start-Sleep -Seconds 15
$readyAfterPrep = Invoke-Bvmenv ("wait-ready {0} --timeout 600" -f $Vm) 660
if ($readyAfterPrep.code -ne 0) {
    Write-Warning ("guest not ready after lab preparation: " + $readyAfterPrep.stdout)
}
# ---------------------------------------------------------------------------
# 1. Build the bundle.
# ---------------------------------------------------------------------------
$bundle = Join-Path $Out 'bundle'
if (Test-Path $bundle) { Remove-Item $bundle -Recurse -Force }
New-Item -ItemType Directory -Force $bundle | Out-Null
$required = @('kdu.exe', 'kdu_payload.sys', 'kdu_e2e_helper.exe',
              'kdu_guest_test_driver.sys')
foreach ($file in $required) {
    $source = Join-Path $build $file
    if (Test-Path $source) {
        Copy-Item $source (Join-Path $bundle $file) -Force
    } elseif ($file -in @('kdu.exe', 'kdu_payload.sys')) {
        throw "required build output missing: $source"
    } else {
        Write-Warning "optional e2e asset missing: $source"
    }
}

# The DSE check needs a test-signed driver (loads while DSE is on) and a plain
# unsigned driver (must be blocked until DSE is disabled).
$guestDriverSource = Join-Path $build 'kdu_guest_test_driver.sys'
if (Test-Path $guestDriverSource) {
    $unsigned = Join-Path $bundle 'kdu_guest_test_driver_unsigned.sys'
    $signed = Join-Path $bundle 'kdu_guest_test_driver_signed.sys'
    Copy-Item $guestDriverSource $unsigned -Force
    Copy-Item $guestDriverSource $signed -Force
    try {
        & pwsh -NoProfile -ExecutionPolicy Bypass -File `
            (Join-Path $Root 'scripts/sign.ps1') -Files $signed | Out-Null
        Write-Host "test-signed guest driver: $signed"
        # Tampered copy: flip one byte inside the signed image so the signature
        # no longer matches. It must be rejected while code integrity is on.
        $tampered = Join-Path $bundle 'kdu_guest_test_driver_tampered.sys'
        $bytes = [System.IO.File]::ReadAllBytes($signed)
        $bytes[0x400] = $bytes[0x400] -bxor 0xFF
        [System.IO.File]::WriteAllBytes($tampered, $bytes)
    } catch {
        Write-Warning ("could not test-sign the guest driver: " + $_)
        Remove-Item $signed -Force -ErrorAction SilentlyContinue
    }
}

# Per-exploit signed driver images for the guest load matrix.
$assetMap = @{
    asrock = 'asrock/AsrDrv107n.sys.bin.signed'
    atszio64 = 'atszio64/ATSZIO64.bin.signed'
    dbk64 = 'dbk64/dbk64.bin.signed'
    echodrv = 'echodrv/echo_driver.bin.signed'
    gdrv = 'gdrv/gdrv.bin.signed'
    physmem64 = 'physmem64/Phymemx64.bin.signed'
    rtcore64 = 'rtcore64/RTCore64.sys.bin.signed'
    winring0 = 'winring0/WinRing0x64.bin.signed'
}
$driversDir = Join-Path $bundle 'drivers'
New-Item -ItemType Directory -Force $driversDir | Out-Null
foreach ($id in $assetMap.Keys) {
    $asset = Join-Path $Root ('build/generated/assets/' + $assetMap[$id])
    if (Test-Path $asset) {
        Copy-Item $asset (Join-Path $driversDir ($id + '.sys')) -Force
    } else {
        Write-Warning "signed driver asset missing: $asset"
    }
}

foreach ($phaseScript in Get-ChildItem (Join-Path $Root 'tests/e2e') -Filter 'phase*.ps1') {
    Copy-Item $phaseScript.FullName (Join-Path $bundle $phaseScript.Name) -Force
}
Copy-Item (Join-Path $Root 'tests/e2e/guest-run.ps1') `
          (Join-Path $bundle 'guest-run.ps1') -Force
Copy-Item (Join-Path $Root 'README.md') (Join-Path $bundle 'README.md') -Force
$version | Set-Content (Join-Path $bundle 'version.txt')

# ---------------------------------------------------------------------------
# 2. Push + run inside the guest (elevated; bvmenv falls back to SYSTEM).
# The suite runs in small phases so a hang/crash in one step is isolated and the
# results of the previous phases are already on the host.
# ---------------------------------------------------------------------------
$guestDir = 'C:\kdu-e2e'
$guestOutDir = "$guestDir\out"
$pushed = Invoke-Bvmenv ("push {0} `"{1}`" {2}" -f $Vm, $bundle, $guestDir) $StepTimeoutSeconds
if ($pushed.code -ne 0) {
    throw ("bvmenv push failed: " + $pushed.stdout + $pushed.stderr)
}

$guestOut = Join-Path $Out 'guest-out'
if (Test-Path $guestOut) { Remove-Item $guestOut -Recurse -Force }
New-Item -ItemType Directory -Force $guestOut | Out-Null

$phaseSummaries = @()
$ok = $true
foreach ($phase in 1..4) {
    $script = "$guestDir\phase$phase.ps1"
    if (-not (Test-Path (Join-Path $bundle "phase$phase.ps1"))) {
        $phaseSummaries += [ordered]@{ phase = $phase; code = -1; note = 'script missing' }
        $ok = $false
        break
    }
    $command = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -BundleDir $guestDir -OutDir $guestOutDir"
    try {
        $exec = Invoke-Bvmenv ("exec {0} --elevated --timeout {1} -- {2}" -f $Vm, $ExecTimeoutSeconds, $command) ($ExecTimeoutSeconds + 120)
    } catch {
        $phaseSummaries += [ordered]@{ phase = $phase; code = -1; note = [string]$_ }
        $ok = $false
        break
    }
    ($exec.stdout | Out-String) | Set-Content (Join-Path $Out "phase$phase.log")
    ($exec.stderr | Out-String) | Set-Content (Join-Path $Out "phase$phase.err.log")
    # Best-effort pull after every phase so completed results survive a later hang.
    try {
        (Invoke-Bvmenv ("pull {0} {1} `"{2}`"" -f $Vm, $guestOutDir, $guestOut) 300) | Out-Null
    } catch {
        Write-Warning ("pull after phase $phase failed: " + $_)
    }
    $phaseSummaries += [ordered]@{
        phase = $phase
        code = $exec.code
        stdout_tail = (($exec.stdout | Out-String) -split "`n" | Select-Object -Last 8) -join "`n"
    }
    if ($exec.code -ne 0) {
        $ok = $false
        break
    }
}

# Merge the per-phase result documents that made it to the host.
$mergedResults = @()
$mergedFailed = 0
$mergedSkipped = 0
foreach ($phase in 1..4) {
    $path = Join-Path $guestOut "result-$phase.json"
    if (-not (Test-Path $path)) { continue }
    try {
        $document = Get-Content $path -Raw | ConvertFrom-Json
        $mergedResults += $document.results
        $mergedFailed += [int]$document.failed
        $mergedSkipped += @($document.results | Where-Object { $_.skipped }).Count
    } catch {
        Write-Warning ("cannot parse $path : " + $_)
    }
}
$guestResult = [ordered]@{
    suite = 'blook-kdu-e2e'
    total = @($mergedResults).Count
    failed = $mergedFailed
    skipped = $mergedSkipped
    results = $mergedResults
}
if (@($mergedResults).Count -eq 0) {
    $ok = $false
}

# ---------------------------------------------------------------------------
# 3. Host-side state observation + evidence.
# ---------------------------------------------------------------------------
$state = Invoke-Bvmenv ("state {0} --json --screenshot `"{1}`"" -f $Vm, (Join-Path $Out 'state.png')) $StepTimeoutSeconds
$state.stdout | Set-Content (Join-Path $Out 'state.json')

$ok = $ok -and $mergedFailed -eq 0
$summary = [ordered]@{
    suite = 'blook-kdu-e2e'
    schema = 'kdu.e2e.v1'
    version = $version
    vm = $Vm
    finished = (Get-Date).ToString('o')
    ok = $ok
    phases = $phaseSummaries
    guest_result = $guestResult
    state = ($state.stdout | ConvertFrom-Json -ErrorAction SilentlyContinue)
}
$summary | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $Out 'summary.json') -Encoding UTF8
Write-Host ("e2e {0}: {1}" -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $Out)

# ---------------------------------------------------------------------------
# 4. Try to reset the VM so the next run starts clean.
# ---------------------------------------------------------------------------
if (-not $NoReset) {
    try { (Invoke-Bvmenv "reset $Vm" 300) | Out-Null } catch { Write-Warning $_ }
}

if (-not $ok) { exit 1 }






