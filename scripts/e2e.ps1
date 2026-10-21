# blook-kdu host-side VM e2e driver.
#
# Builds an e2e bundle from the current build outputs, pushes it into a bvmenv
# VM, runs the elevated guest suite and pulls the artifacts back. Every bvmenv
# call is wrapped in a hard timeout: bvmenv has been observed to hang, and the
# e2e pipeline must never wedge the host.
[CmdletBinding()]
param(
    [string] $Root = (Split-Path -Parent $PSScriptRoot),
    [string] $Vm = '',
    [string] $Out = '',
    [string] $Bvmenv = 'D:\blook-kernel-project\blook-vmware-environment\build\windows\x64\releasedbg\bvmenv.exe',
    [int] $ExecTimeoutSeconds = 1200,
    [int] $StepTimeoutSeconds = 300,
    [switch] $NoReset,
    [switch] $Reuse
)

$ErrorActionPreference = 'Stop'
Set-Location $Root
if (-not $Vm) {
    throw "refusing to run kernel e2e on the host: pass -Vm <bvmenv guest name> (e.g. -Vm vm-kdu)"
}
$version = (Get-Content (Join-Path $Root 'version.txt') -Raw).Trim()
if (-not $Out) {
    $Out = Join-Path $Root ("docs/evidence/{0}-e2e" -f (Get-Date -Format 'yyyyMMdd'))
}
New-Item -ItemType Directory -Force $Out | Out-Null
$build = Join-Path $Root 'build/windows/x64/release'
if (-not (Test-Path $build)) { throw "build outputs missing: $build (run xmake -y first)" }

function Invoke-Bvmenv {
    param([string[]] $Arguments, [int] $TimeoutSeconds = $StepTimeoutSeconds)
    Write-Host ("> bvmenv {0}" -f ($Arguments -join ' '))
    $process = Start-Process -FilePath $Bvmenv -ArgumentList $Arguments `
        -NoNewWindow -PassThru -RedirectStandardOutput (Join-Path $Out 'bvmenv.out.log') `
        -RedirectStandardError (Join-Path $Out 'bvmenv.err.log')
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        try { $process.Kill($true) } catch { }
        throw ("bvmenv {0} timed out after {1}s" -f ($Arguments -join ' '), $TimeoutSeconds)
    }
    $stdout = Get-Content (Join-Path $Out 'bvmenv.out.log') -Raw -ErrorAction SilentlyContinue
    $stderr = Get-Content (Join-Path $Out 'bvmenv.err.log') -Raw -ErrorAction SilentlyContinue
    return @{ code = $process.ExitCode; stdout = $stdout; stderr = $stderr }
}

# ---------------------------------------------------------------------------
# 0. Make sure the VM exists (never block on create/wait-ready).
# ---------------------------------------------------------------------------
$list = Invoke-Bvmenv @('list', '--json') $StepTimeoutSeconds
if ($list.code -ne 0) {
    throw ("bvmenv list failed ({0}): {1}" -f $list.code, $list.stdout + $list.stderr)
}
if ($list.stdout -notmatch [regex]::Escape($Vm)) {
    if ($Reuse) { throw "VM $Vm does not exist (remove -Reuse or create it first)" }
    Write-Host "VM $Vm does not exist; creating"
    $created = Invoke-Bvmenv @('create', $Vm, '--cpus', '4', '--memory', '6144') 600
    if ($created.code -ne 0) {
        throw ("bvmenv create failed: " + $created.stdout + $created.stderr)
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
Copy-Item (Join-Path $Root 'tests/e2e/guest-run.ps1') (Join-Path $bundle 'guest-run.ps1') -Force
Copy-Item (Join-Path $Root 'README.md') (Join-Path $bundle 'README.md') -Force
$version | Set-Content (Join-Path $bundle 'version.txt')

# ---------------------------------------------------------------------------
# 2. Push + run inside the guest.
# ---------------------------------------------------------------------------
$guestDir = 'C:\kdu-e2e'
$pushed = Invoke-Bvmenv @('push', $Vm, $bundle, $guestDir) $StepTimeoutSeconds
if ($pushed.code -ne 0) {
    throw ("bvmenv push failed: " + $pushed.stdout + $pushed.stderr)
}

$exec = Invoke-Bvmenv @('exec', $Vm, '--elevated', '--timeout', "$ExecTimeoutSeconds",
                        '--', "powershell.exe -NoProfile -ExecutionPolicy Bypass -File $guestDir\guest-run.ps1 -BundleDir $guestDir -OutDir $guestDir\out") `
                     ($ExecTimeoutSeconds + 120)
$exec.stdout | Set-Content (Join-Path $Out 'guest-exec.log')
$exec.stderr | Set-Content (Join-Path $Out 'guest-exec.err.log')

$guestOut = Join-Path $Out 'guest-out'
$pulled = Invoke-Bvmenv @('pull', $Vm, "$guestDir\\out", $guestOut) $StepTimeoutSeconds
if ($pulled.code -ne 0) {
    Write-Warning ("bvmenv pull failed: " + $pulled.stdout + $pulled.stderr)
}

# ---------------------------------------------------------------------------
# 3. Host-side state observation + evidence.
# ---------------------------------------------------------------------------
$state = Invoke-Bvmenv @('state', $Vm, '--json', '--screenshot',
                         (Join-Path $Out 'state.png')) $StepTimeoutSeconds
$state.stdout | Set-Content (Join-Path $Out 'state.json')

$resultPath = Join-Path $guestOut 'result.json'
$summary = [ordered]@{
    suite = 'blook-kdu-e2e'
    version = $version
    vm = $Vm
    started = (Get-Date).ToString('o')
    exec_exit_code = $exec.code
    exec_stdout_tail = ($exec.stdout -split "`n" | Select-Object -Last 40) -join "`n"
    exec_stderr_tail = ($exec.stderr -split "`n" | Select-Object -Last 40) -join "`n"
    state = ($state.stdout | ConvertFrom-Json -ErrorAction SilentlyContinue)
    guest_result = if (Test-Path $resultPath) {
        Get-Content $resultPath -Raw | ConvertFrom-Json
    } else { $null }
}
$ok = $exec.code -eq 0 -and $null -ne $summary.guest_result -and
      $summary.guest_result.failed -eq 0
$summary.ok = $ok
$summary | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $Out 'summary.json') -Encoding UTF8
Write-Host ("e2e {0}: {1}" -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $Out)

# ---------------------------------------------------------------------------
# 4. Always try to reset the VM so the next run starts clean.
# ---------------------------------------------------------------------------
if (-not $NoReset) {
    try { (Invoke-Bvmenv @('reset', $Vm) 300) | Out-Null } catch { Write-Warning $_ }
}

if (-not $ok) { exit 1 }

