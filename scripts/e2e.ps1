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
    [string] $Bvmenv = 'D:\blook-kernel-project\blook-vmware-environment\build\windows\x64\releasedbg\bvmenv.exe',
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
    } catch {
        Write-Warning ("could not test-sign the guest driver: " + $_)
        Remove-Item $signed -Force -ErrorAction SilentlyContinue
    }
}

Copy-Item (Join-Path $Root 'tests/e2e/guest-run.ps1') `
          (Join-Path $bundle 'guest-run.ps1') -Force
Copy-Item (Join-Path $Root 'README.md') (Join-Path $bundle 'README.md') -Force
$version | Set-Content (Join-Path $bundle 'version.txt')

# ---------------------------------------------------------------------------
# 2. Push + run inside the guest (elevated; bvmenv falls back to SYSTEM).
# ---------------------------------------------------------------------------
$guestDir = 'C:\kdu-e2e'
$guestOutDir = "$guestDir\out"
$pushed = Invoke-Bvmenv ("push {0} `"{1}`" {2}" -f $Vm, $bundle, $guestDir) $StepTimeoutSeconds
if ($pushed.code -ne 0) {
    throw ("bvmenv push failed: " + $pushed.stdout + $pushed.stderr)
}

$command = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File $guestDir\guest-run.ps1 -BundleDir $guestDir -OutDir $guestOutDir"
$exec = Invoke-Bvmenv ("exec {0} --elevated --timeout {1} -- {2}" -f $Vm, $ExecTimeoutSeconds, $command) ($ExecTimeoutSeconds + 120)
$exec.stdout | Set-Content (Join-Path $Out 'guest-exec.log')
$exec.stderr | Set-Content (Join-Path $Out 'guest-exec.err.log')

$guestOut = Join-Path $Out 'guest-out'
if (Test-Path $guestOut) { Remove-Item $guestOut -Recurse -Force }
$pulled = Invoke-Bvmenv ("pull {0} {1} `"{2}`"" -f $Vm, $guestOutDir, $guestOut) $StepTimeoutSeconds
if ($pulled.code -ne 0) {
    Write-Warning ("bvmenv pull failed: " + $pulled.stdout + $pulled.stderr)
}

# ---------------------------------------------------------------------------
# 3. Host-side state observation + evidence.
# ---------------------------------------------------------------------------
$state = Invoke-Bvmenv ("state {0} --json --screenshot `"{1}`"" -f $Vm, (Join-Path $Out 'state.png')) $StepTimeoutSeconds
$state.stdout | Set-Content (Join-Path $Out 'state.json')

$resultPath = Join-Path $guestOut 'result.json'
$guestResult = $null
if (Test-Path $resultPath) {
    $guestResult = Get-Content $resultPath -Raw | ConvertFrom-Json
}
$ok = $exec.code -eq 0 -and $null -ne $guestResult -and
      $guestResult.failed -eq 0
$summary = [ordered]@{
    suite = 'blook-kdu-e2e'
    schema = 'kdu.e2e.v1'
    version = $version
    vm = $Vm
    finished = (Get-Date).ToString('o')
    exec_exit_code = $exec.code
    ok = $ok
    guest_result = $guestResult
    exec_stdout_tail = ($exec.stdout -split "`n" | Select-Object -Last 60) -join "`n"
    exec_stderr_tail = ($exec.stderr -split "`n" | Select-Object -Last 20) -join "`n"
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

