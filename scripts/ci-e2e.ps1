# blook-kdu: full CI e2e matrix on a stock Windows runner.
#
# The hosted runner cannot load the blocklisted victim drivers, and mapped
# images cannot execute there, so the runner matrix covers everything that does
# not need those: a real SPC-signed kernel driver load + two IOCTL round-trips
# (magic + kernel pointer), repeated load/unload, trace scan, error paths and
# documented platform skips. The payload service path, CR3 process memory and
# DSE gating are exercised by the VM suite (`scripts/e2e.ps1`).
#
# Prereqs: elevated shell, signed test driver + SPC trust imported (the CI job
# does that), and kdu.exe / kdu_ci_smoke_driver.sys / kdu_ci_smoke_client.exe in
# the build dir. Optional artifacts/ci-signing.json supplies the runner's
# testsigning state and signtool /kp verdict.
[CmdletBinding()]
param(
    [string] $Root = (Split-Path -Parent $PSScriptRoot),
    [string] $BuildDir = 'build/windows/x64/release'
)

$ErrorActionPreference = 'Stop'
Set-Location $Root
$kdu = Join-Path $BuildDir 'kdu.exe'
if (-not (Test-Path $kdu)) { throw "kdu.exe not found: $kdu" }
$results = New-Object System.Collections.Generic.List[object]
New-Item -ItemType Directory -Force artifacts | Out-Null
"" | Set-Content artifacts/ci-e2e-progress.log -Encoding UTF8

function Add-Result([string] $name, [bool] $ok, [string] $detail) {
    $status = if ($ok) { 'pass' } else { 'fail' }
    $results.Add([pscustomobject]@{ name = $name; status = $status
        detail = $detail })
    Write-Host ("[{0}] {1}: {2}" -f $status.ToUpper(), $name, $detail)
    Add-Content -Path artifacts/ci-e2e-progress.log -ErrorAction SilentlyContinue `
        -Value ("[{0}] {1}: {2}" -f $status.ToUpper(), $name, $detail)
}
# Skip reasons use the shared CI vocabulary so the matrix gate can classify
# every skip.
function Add-Skip([string] $name, [string] $reason) {
    $allowed = @('requires VT-x', 'requires VM reboot/BSOD',
                 'blocklisted victim driver', 'KVA-shadow platform',
                 'manual-map NX on 26200')
    if ($allowed -notcontains $reason) {
        throw "skip reason not in the allowed vocabulary: $reason"
    }
    $results.Add([pscustomobject]@{ name = $name; status = 'skip'
        detail = $reason })
    Write-Host ("[SKIP] {0}: {1}" -f $name, $reason)
    Add-Content -Path artifacts/ci-e2e-progress.log -ErrorAction SilentlyContinue `
        -Value ("[SKIP] {0}: {1}" -f $name, $reason)
}
function Invoke-Kdu([string[]] $arguments, [int] $timeoutSeconds = 120) {
    $stdout = Join-Path $env:TEMP ("kdu-ci-" + [guid]::NewGuid() + ".out")
    $stderr = Join-Path $env:TEMP ("kdu-ci-" + [guid]::NewGuid() + ".err")
    $process = Start-Process -FilePath $kdu -ArgumentList $arguments `
        -NoNewWindow -PassThru -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr
    if (-not $process.WaitForExit($timeoutSeconds * 1000)) {
        try { $process.Kill($true) } catch { }
        return @{ code = -1; output = "TIMEOUT after $timeoutSeconds s" }
    }
    $out = Get-Content $stdout -Raw -ErrorAction SilentlyContinue
    $err = Get-Content $stderr -Raw -ErrorAction SilentlyContinue
    Remove-Item $stdout, $stderr -Force -ErrorAction SilentlyContinue
    return @{ code = $process.ExitCode; output = (($out + $err) | Out-String) }
}
function Test-DriverLoad([string] $service, [string] $image) {
    sc.exe stop $service *> $null
    sc.exe delete $service *> $null
    Start-Sleep -Milliseconds 500
    if (-not (Test-Path $image)) { return @{ loaded = $false; output = 'missing image' } }
    $create = sc.exe create $service type= kernel start= demand binPath= $image 2>&1
    # Guarded start: a buggy image must not wedge the runner.
    $startProcess = Start-Process sc.exe -ArgumentList "start $service" `
        -NoNewWindow -PassThru -RedirectStandardOutput "$env:TEMP\sc-$service.log" `
        -RedirectStandardError "$env:TEMP\sc-$service.err"
    if (-not $startProcess.WaitForExit(30000)) {
        try { $startProcess.Kill($true) } catch { }
        sc.exe stop $service *> $null
        sc.exe delete $service *> $null
        return @{ loaded = $false; output = 'sc start hung for 30s' }
    }
    $start = Get-Content "$env:TEMP\sc-$service.log" -Raw -ErrorAction SilentlyContinue
    $loaded = $start -match 'STATE\s+:\s+4' -or $start -match 'RUNNING'
    sc.exe stop $service *> $null
    sc.exe delete $service *> $null
    return @{ loaded = $loaded; output = (($create + $start) | Out-String) }
}

# ---------------------------------------------------------------------------
# 1. Real kernel driver: load, two IOCTL round-trips, unload.
# ---------------------------------------------------------------------------
$smokeDriver = Join-Path $BuildDir 'kdu_ci_smoke_driver.sys'
$smokeClient = Join-Path $BuildDir 'kdu_ci_smoke_client.exe'
if ((Test-Path $smokeDriver) -and (Test-Path $smokeClient)) {
    $load = Test-DriverLoad 'kduCiSmoke' $smokeDriver
    if ($load.loaded) {
        Add-Result 'driver/signed-load' $true 'SPC-signed test driver STATE 4 RUNNING'
        $client = & $smokeClient | Out-String
        $clientDocument = $null
        try { $clientDocument = $client | ConvertFrom-Json } catch { }
        $functional = $null -ne $clientDocument -and $clientDocument.ok -and
                      $clientDocument.canonical
        Add-Result 'driver/ioctl-roundtrip' $functional $client.Trim()
    } else {
        Add-Result 'driver/signed-load' $false $load.output.Trim()
        Add-Result 'driver/ioctl-roundtrip' $false 'driver did not load'
    }
} else {
    Add-Result 'driver/signed-load' $false 'smoke driver/client not built'
    Add-Result 'driver/ioctl-roundtrip' $false 'smoke driver/client not built'
}

# ---------------------------------------------------------------------------
# 2. Repeated load/unload of the real driver.
# ---------------------------------------------------------------------------
$cycles = 5
$failures = 0
for ($index = 0; $index -lt $cycles; $index++) {
    $load = Test-DriverLoad 'kduCiSmoke' $smokeDriver
    if (-not $load.loaded) { $failures++ }
}
Add-Result 'stress/load-unload' ($failures -eq 0) ("{0}x, failures={1}" -f $cycles, $failures)

# ---------------------------------------------------------------------------
# 3. Trace scan (no kdu-owned service/registry/file leftovers).
# ---------------------------------------------------------------------------
$traces = Invoke-Kdu @('--json', 'traces')
$cleanable = $false
try {
    $report = $traces.output | ConvertFrom-Json
    $bad = @($report.findings | Where-Object {
        $_.category -in @('service', 'registry', 'file') })
    $cleanable = $traces.code -eq 0 -and $bad.Count -eq 0
} catch { }
Add-Result 'cleanup/traces' $cleanable 'no service/registry/file leftovers'

# ---------------------------------------------------------------------------
# 4. Negative input fuzz.
# ---------------------------------------------------------------------------
$badMode = Invoke-Kdu @('payload', 'load', '--json', '--mode', 'nonsense')
Add-Result 'fuzz/bad-mode' ($badMode.code -ne 0) 'unknown payload mode rejected'
$badOp = Invoke-Kdu @('--json', 'batch', (Join-Path $Root 'tests/ci/bad-op.json'))
Add-Result 'fuzz/unknown-op' ($badOp.code -ne 0) 'unknown batch op rejected'
$badLoad = Invoke-Kdu @('--json', 'batch', (Join-Path $Root 'tests/ci/bad-physical.json'))
Add-Result 'fuzz/invalid-physical' ($badLoad.code -ne 0) 'invalid physical read rejected'

# ---------------------------------------------------------------------------
# 5. Documented platform skips (VM-only cases).
# ---------------------------------------------------------------------------
Add-Skip 'exploit/victim-driver-load' 'blocklisted victim driver'
Add-Skip 'payload/manual-map' 'manual-map NX on 26200'
Add-Skip 'dse/unsigned-load' 'requires VM reboot/BSOD'

# ---------------------------------------------------------------------------
# Persist the result document (runner signing facts included).
# ---------------------------------------------------------------------------
$signing = [ordered]@{ testsigning = 'unknown'; signtool_kp = 'unknown' }
$signingPath = Join-Path $Root 'artifacts/ci-signing.json'
if (Test-Path $signingPath) {
    try {
        $signingDocument = Get-Content $signingPath -Raw | ConvertFrom-Json
        if ($signingDocument.testsigning) { $signing.testsigning = $signingDocument.testsigning }
        if ($signingDocument.signtool_kp) { $signing.signtool_kp = $signingDocument.signtool_kp }
    } catch { }
}
$failed = @($results | Where-Object { $_.status -eq 'fail' }).Count
$skipped = @($results | Where-Object { $_.status -eq 'skip' }).Count
$passed = @($results | Where-Object { $_.status -eq 'pass' }).Count
$documentOut = [ordered]@{
    suite = 'blook-kdu-ci-e2e'
    schema = 'kdu.e2e.v1'
    runner = $env:COMPUTERNAME
    build = [System.Environment]::OSVersion.VersionString
    testsigning = $signing.testsigning
    signtool_kp = $signing.signtool_kp
    elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    total = $results.Count
    passed = $passed
    failed = $failed
    skipped = $skipped
    cases = $results
}
$documentOut | ConvertTo-Json -Depth 6 |
    Set-Content artifacts/ci-e2e-result.json -Encoding UTF8
Write-Host ("result: artifacts/ci-e2e-result.json ({0} checks, {1} passed, {2} failed, {3} skipped)" -f `
            $results.Count, $passed, $failed, $skipped)
if ($failed -ne 0) { exit 1 }
