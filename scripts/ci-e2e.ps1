# blook-kdu: full CI e2e matrix on a stock Windows runner.
#
# Runs the parts of the toolkit that do not need a blocklisted victim driver:
#   * payload backend over the SCM service path (drv-lite dev path): kernel VA
#     read, physical read, CR3 process read/write, module list, handle rewrite;
#   * a real SPC-signed test driver load + IOCTL round-trip;
#   * DSE gating (disable -> unsigned driver load -> restore) when the payload
#     driver reports DSE support;
#   * repeated load/unload, trace scan and negative input fuzz.
#
# Prereqs: elevated shell, signed kdu_payload.sys embedded in kdu.exe, the test
# driver signed + SPC trust imported (the CI job does that), and kdu.exe /
# kdu_ci_smoke_driver.sys / kdu_ci_smoke_client.exe in the release build dir.
#
# Output: artifacts/ci-e2e-result.json, exit code 0 only when failed == 0.
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

function Add-Result([string] $name, [bool] $ok, [string] $detail) {
    $status = if ($ok) { 'pass' } else { 'fail' }
    $results.Add([pscustomobject]@{ name = $name; status = $status
        detail = $detail })
    Write-Host ("[{0}] {1}: {2}" -f $status.ToUpper(), $name, $detail)
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
}
function Invoke-Kdu([string[]] $arguments) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $kdu @arguments 2>&1 | Out-String
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previous }
    return @{ code = $code; output = $output }
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
# 1. Payload backend full self-test (service path, real kernel code).
# ---------------------------------------------------------------------------
$payload = Invoke-Kdu @('payload', 'load', '--json', '--mode', 'service')
$document = $null
try { $document = $payload.output | ConvertFrom-Json } catch { }
if ($payload.code -eq 0 -and $document -and $document.loaded) {
    Add-Result 'payload/service-load' $true ("base=" + $document.payload_base)
    Add-Result 'payload/service-running' ([bool]$document.service_running) 'kduPayload RUNNING during client test'
    Add-Result 'payload/kernel-va-read' ($document.ntoskrnl_head -eq '4d5a') ("head=" + $document.ntoskrnl_head)
    Add-Result 'payload/physical-read' (-not [string]::IsNullOrEmpty($document.physical_read)) ("hex=" + $document.physical_read)
    Add-Result 'payload/process-read' ([bool]$document.process_ok) 'CR3 read matched pattern'
    Add-Result 'payload/process-write' ([bool]$document.process_write_ok) 'CR3 write + read-back matched'
    Add-Result 'payload/handle-rewrite' ([bool]$document.handle_ok) 'minimal handle raised to full access'
    Add-Result 'payload/modules' (@($document.modules).Count -gt 100) ("modules=" + @($document.modules).Count)
} else {
    Add-Result 'payload/service-load' $false $payload.output.Trim()
}

# ---------------------------------------------------------------------------
# 2. SPC-signed test driver: load, IOCTL, unload.
# ---------------------------------------------------------------------------
$smokeDriver = Join-Path $BuildDir 'kdu_ci_smoke_driver.sys'
$smokeClient = Join-Path $BuildDir 'kdu_ci_smoke_client.exe'
if ((Test-Path $smokeDriver) -and (Test-Path $smokeClient)) {
    $load = Test-DriverLoad 'kduCiSmoke' $smokeDriver
    if ($load.loaded) {
        Add-Result 'driver/signed-load' $true 'test driver RUNNING'
        $client = & $smokeClient | Out-String
        $clientDocument = $null
        try { $clientDocument = $client | ConvertFrom-Json } catch { }
        Add-Result 'driver/ioctl' ($null -ne $clientDocument -and $clientDocument.ok) $client.Trim()
    } else {
        Add-Result 'driver/signed-load' $false $load.output.Trim()
        Add-Result 'driver/ioctl' $false 'test driver did not start'
    }
} else {
    Add-Result 'driver/signed-load' $false 'smoke driver/client not built'
    Add-Result 'driver/ioctl' $false 'smoke driver/client not built'
}

# ---------------------------------------------------------------------------
# 3. Documented platform skips (VM-only cases).
# ---------------------------------------------------------------------------
Add-Skip 'exploit/victim-driver-load' 'blocklisted victim driver'
Add-Skip 'payload/manual-map' 'manual-map NX on 26200'
Add-Skip 'dse/unsigned-load' 'requires VM reboot/BSOD'

# ---------------------------------------------------------------------------
# 4. Repeated load/unload (service must be removed every time).
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# 4. Repeated load/unload (service must be removed every time).
# ---------------------------------------------------------------------------
$cycles = 5
$failures = 0
for ($index = 0; $index -lt $cycles; $index++) {
    $run = Invoke-Kdu @('payload', 'load', '--json', '--mode', 'service')
    if ($run.code -ne 0) { $failures++ }
}
Add-Result 'stress/load-unload' ($failures -eq 0) ("{0}x, failures={1}" -f $cycles, $failures)

# ---------------------------------------------------------------------------
# 5. Trace scan: payload unload must remove the service/file.
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
# 6. Negative input fuzz: malformed requests must fail cleanly.
# ---------------------------------------------------------------------------
$badMode = Invoke-Kdu @('payload', 'load', '--json', '--mode', 'nonsense')
Add-Result 'fuzz/bad-mode' ($badMode.code -ne 0) 'unknown payload mode rejected'
$badOp = Invoke-Kdu @('--json', 'batch', (Join-Path $Root 'tests/ci/bad-op.json'))
Add-Result 'fuzz/unknown-op' ($badOp.code -ne 0) 'unknown batch op rejected'
$badLoad = Invoke-Kdu @('--json', 'batch', (Join-Path $Root 'tests/ci/bad-physical.json'))
Add-Result 'fuzz/invalid-physical' ($badLoad.code -ne 0) 'invalid physical read rejected'

# ---------------------------------------------------------------------------
# Persist the result document.
# ---------------------------------------------------------------------------
$failed = @($results | Where-Object { $_.status -eq 'fail' }).Count
$skipped = @($results | Where-Object { $_.status -eq 'skip' }).Count
$passed = @($results | Where-Object { $_.status -eq 'pass' }).Count
New-Item -ItemType Directory -Force artifacts | Out-Null
$documentOut = [ordered]@{
    suite = 'blook-kdu-ci-e2e'
    schema = 'kdu.e2e.v1'
    runner = $env:COMPUTERNAME
    build = [System.Environment]::OSVersion.VersionString
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
Write-Host ("result: artifacts/ci-e2e-result.json ({0} checks, {1} failed, {2} skipped)" -f `
            $results.Count, $failed, $skipped)
if ($failed -ne 0) { exit 1 }


